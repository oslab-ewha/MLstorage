/*******************************************************************************
 ** Copyright © 2011 - 2021 Petros Koutoupis
 ** All rights reserved.
 **
 ** This program is free software: you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation; under version 2 of the License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **
 ** SPDX-License-Identifier: GPL-2.0-only
 **
 ** filename: stolearn-cache.c
 ** description: Device mapper target for block-level disk write-through and
 **	 write-around caching. This module is based on Flashcache-wt:
 **	  Copyright 2010 Facebook, Inc.
 **	  Author: Mohan Srinivasan (mohan@facebook.com)
 **
 **	 Which in turn was based on DM-Cache:
 **	  Copyright (C) International Business Machines Corp., 2006
 **	  Author: Ming Zhao (mingzhao@ufl.edu)
 **
 ** created: 3Dec11, petros@petroskoutoupis.com
 **
 ******************************************************************************/

#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/hardirq.h>
#include <linux/dm-io.h>
#include <linux/device-mapper.h>
#include <linux/mm.h>

#include "pcache.h"

#define ASSERT(x) do { \
	if (unlikely(!(x))) { \
		dump_stack(); \
		panic("ASSERT: assertion (%s) failed at %s (%d)\n", \
		#x,  __FILE__, __LINE__); \
	} \
} while (0)

#define VERSION_STR	"1.0.0"
#define DM_MSG_PREFIX	"stolearn-cache"

#define READSOURCE	3
#define WRITESOURCE	4

#define BYTES_PER_BLOCK		512
/* Default cache parameters */
#define DEFAULT_CACHE_ASSOC	512
#define CACHE_BLOCK_SIZE	(PAGE_SIZE / BYTES_PER_BLOCK)
#define CONSECUTIVE_BLOCKS	512

/* States of a cache block */
#define INVALID		0
#define VALID		1
#define INPROG		2	/* IO (cache fill) is in progress */

#define IS_VALID_CACHE_STATE(s)	((s) == VALID)
#define IS_VALID_OR_PROG_CACHE_STATE(s)	(IS_VALID_CACHE_STATE(s) || (s) == INPROG)

#define DEV_PATHLEN	128

#ifndef DM_MAPIO_SUBMITTED
#define DM_MAPIO_SUBMITTED	0
#endif

#define WT_MIN_JOBS	1024
/* Number of pages for I/O */

/* Cache block metadata structure */
#pragma pack(push, 1)
typedef struct _cacheinfo {
	sector_t dbn;		/* Sector number of the cached block */
	u16	n_readers;
	int	state:16;
} cacheinfo_t;
#pragma pack(pop)

/* Cache context */
struct cache_context {
	struct dm_target *tgt;
	struct dm_dev *disk_dev;	/* Source device */
	struct dm_dev *cache_dev;	/* Cache device */
	pcache_t	*pcache;

	spinlock_t cache_spin_lock;
	cacheinfo_t	*cacheinfos;
	u32 *set_lru_next;

	struct dm_io_client *io_client;
	sector_t size, size_nominal;
	unsigned int assoc;
	unsigned int block_size;
	unsigned int block_shift;
	unsigned int block_mask;
	unsigned int consecutive_shift;

	wait_queue_head_t destroyq;	/* Wait queue for I/O completion */
	atomic_t nr_jobs;		/* Number of I/O jobs */

	wait_queue_head_t	inprogq;	/* Wait queue for INPROG state completion */

	/* Stats */
	unsigned long reads;
	unsigned long writes;
	unsigned long cache_hits;
	unsigned long replace;
	unsigned long wr_invalidates;
	unsigned long rd_invalidates;
	unsigned long cached_blocks;
	unsigned long cache_wr_replace;
	unsigned long uncached_reads;
	unsigned long uncached_writes;
	unsigned long cache_reads, cache_writes;
	unsigned long disk_reads, disk_writes;

	char cache_devname[DEV_PATHLEN];
	char disk_devname[DEV_PATHLEN];
};

/* Structure for a kcached job */
struct kcached_job {
	struct list_head list;
	struct cache_context *dmc;
	struct bio *bio;	/* Original bio */
	struct dm_io_region disk;
	int index;
	int rw;
	int error;
};

static struct kmem_cache	*job_cache;
static mempool_t		*job_pool;

static void
dm_io_async_bvec(struct dm_io_region *where, int rw, struct bio *bio, io_notify_fn fn, void *context)
{
	struct kcached_job *job = (struct kcached_job *)context;
	struct dm_io_request iorq;

	iorq.bi_op = rw;
	iorq.bi_op_flags = 0;
	iorq.mem.type = DM_IO_BIO;
	iorq.mem.ptr.bio = bio;
	iorq.notify.fn = fn;
	iorq.notify.context = context;
	iorq.client = job->dmc->io_client;

	dm_io(&iorq, 1, where, NULL);
}

static int
jobs_init(void)
{
	job_cache = kmem_cache_create("kcached-jobs-wt", sizeof(struct kcached_job), __alignof__(struct kcached_job), 0, NULL);
	if (!job_cache)
		return -ENOMEM;

	job_pool = mempool_create(WT_MIN_JOBS, mempool_alloc_slab, mempool_free_slab, job_cache);
	if (!job_pool) {
		kmem_cache_destroy(job_cache);
		return -ENOMEM;
	}
	return 0;
}

static void
jobs_exit(void)
{
	mempool_destroy(job_pool);
	kmem_cache_destroy(job_cache);
	job_pool = NULL;
	job_cache = NULL;
}

static void
job_free(struct kcached_job *job)
{
	struct cache_context *dmc = job->dmc;

	mempool_free(job, job_pool);
	if (atomic_dec_and_test(&dmc->nr_jobs))
		wake_up(&dmc->destroyq);
}

static void
copy_bio_to_pcache(struct cache_context *dmc, struct bio *bio, int index)
{
	cacheinfo_t	*ci = dmc->cacheinfos + index;
	unsigned long	flags;
	int	err;

	if (to_sector(bio->bi_iter.bi_size) == dmc->block_size) {
		sector_t	sector = index << dmc->block_shift;
		int	err;

		dmc->cache_writes++;

		err = pcache_submit(dmc->pcache, true, sector, bio);
	}
	else {
		err = -EINVAL;
	}

	bio_endio(bio);

	spin_lock_irqsave(&dmc->cache_spin_lock, flags);
	ASSERT(ci->state == INPROG);

	if (err != 0) {
		ci->state = INVALID;
	} else {
		ci->state = VALID;
		dmc->cached_blocks++;
	}

	wake_up_all(&dmc->inprogq);
	spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
}

static void
rc_io_callback(unsigned long err, void *context)
{
	struct kcached_job	*job = (struct kcached_job *)context;
	struct cache_context	*dmc = job->dmc;
	int	index = job->index;
	cacheinfo_t	*ci = dmc->cacheinfos + index;
	struct bio	*bio;
	unsigned long	flags;

	bio = job->bio;
	if (err)
		DMERR("%s: io error %ld", __func__, err);

	spin_lock_irqsave(&dmc->cache_spin_lock, flags);

	ASSERT(ci->state == INPROG);
	if (err) {
		ci->state = INVALID;
		wake_up_all(&dmc->inprogq);
		spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);

		bio->bi_status= err;
		bio_io_error(bio);

		job_free(job);
	}
	else {
		spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
		job_free(job);
		copy_bio_to_pcache(dmc, bio, index);
	}
}

static int
kcached_init(struct cache_context *dmc)
{
	init_waitqueue_head(&dmc->destroyq);
	atomic_set(&dmc->nr_jobs, 0);

	init_waitqueue_head(&dmc->inprogq);
	return 0;
}

static void
kcached_client_destroy(struct cache_context *dmc)
{
	wait_event(dmc->destroyq, !atomic_read(&dmc->nr_jobs));
}

static unsigned long
hash_block(struct cache_context *dmc, sector_t dbn)
{
	unsigned long	set_number;
	uint64_t	value;

	value = (dbn >> (dmc->block_shift + dmc->consecutive_shift));
	set_number = do_div(value, (dmc->size >> dmc->consecutive_shift));
	return set_number;
}

static bool
find_valid_dbn(struct cache_context *dmc, sector_t dbn, int start_index, int *pindex, unsigned long *pflags)
{
	cacheinfo_t	*ci;
	int	end_index = start_index + dmc->assoc;
	int	i;

again:
	for (i = start_index, ci = dmc->cacheinfos + start_index; i < end_index; i++, ci++) {
		if (dbn == ci->dbn) {
			switch (ci->state) {
			case VALID:
				*pindex = i;
				return true;
			case INPROG:
				spin_unlock_irqrestore(&dmc->cache_spin_lock, *pflags);
				wait_event(dmc->inprogq, ci->state != INPROG);
				spin_lock_irqsave(&dmc->cache_spin_lock, *pflags);
				goto again;
			default:
				break;
			}
		}
	}
	return false;
}

static bool
find_invalid_dbn(struct cache_context *dmc, int start_index, int *pindex)
{
	int	end_index = start_index + dmc->assoc;
	int	i;

	/* Find INVALID slot that we can reuse */
	for (i = start_index; i < end_index; i++) {
		if (dmc->cacheinfos[i].state == INVALID) {
			if (pindex)
				*pindex = i;
			return true;
		}
	}
	return false;
}

static bool
has_nonprog_dbn(struct cache_context *dmc, int start_index)
{
	int	end_index = start_index + dmc->assoc;
	int	i;

	/* Find INVALID slot that we can reuse */
	for (i = start_index; i < end_index; i++) {
		if (dmc->cacheinfos[i].state != INPROG) {
			return true;
		}
	}
	return false;
}

#define NEXT_INDEX(index, start_index, end_index) \
	((index) + 1 == (end_index)) ? (start_index): ((index) + 1)

static bool
find_reclaim_dbn(struct cache_context *dmc, int start_index, int *pindex_reclaimed)
{
	int	end_index = start_index + dmc->assoc;
	int	set = start_index / dmc->assoc;
	int	slots_searched = 0;
	int	index;

	/* Find the "oldest" VALID slot to recycle. For each set, we keep
	 * track of the next "lru" slot to pick off. Each time we pick off
	 * a VALID entry to recycle we advance this pointer. So  we sweep
	 * through the set looking for next blocks to recycle. This
	 * approximates to FIFO (modulo for blocks written through). */
	index = dmc->set_lru_next[set];
	while (slots_searched < dmc->assoc) {
		ASSERT(index >= start_index && index < end_index);

		if (IS_VALID_CACHE_STATE(dmc->cacheinfos[index].state)) {
			*pindex_reclaimed = index;
			dmc->set_lru_next[set] = NEXT_INDEX(index, start_index, end_index);
			return true;
		}
		slots_searched++;
		index = NEXT_INDEX(index, start_index, end_index);
	}
	return false;
}

/* dbn is the starting sector, io_size is the number of sectors. */
static bool
cache_lookup(struct cache_context *dmc, struct bio *bio, int *pindex, unsigned long *pflags)
{
	sector_t dbn = bio->bi_iter.bi_sector;
	unsigned long	set_number = hash_block(dmc, dbn);
	int	index_invalid;
	int	start_index;

	start_index = dmc->assoc * set_number;

again:
	if (find_valid_dbn(dmc, dbn, start_index, pindex, pflags))
		return true;

	if (find_invalid_dbn(dmc, start_index, &index_invalid))
		*pindex = index_invalid;
	else {
		int	index_reclaimed;

		/* We didn't find an invalid entry, search for oldest valid entry */
		if (!find_reclaim_dbn(dmc, start_index, &index_reclaimed)) {
			spin_unlock_irqrestore(&dmc->cache_spin_lock, *pflags);
			wait_event(dmc->inprogq, has_nonprog_dbn(dmc, start_index));
			spin_lock_irqsave(&dmc->cache_spin_lock, *pflags);
			goto again;
		}
		*pindex = index_reclaimed;
	}

	return INVALID;
}

static struct kcached_job *
new_kcached_job(struct cache_context *dmc, struct bio *bio, int index)
{
	struct kcached_job	*job;

	job = mempool_alloc(job_pool, GFP_NOIO);
	if (job == NULL)
		return NULL;

	job->disk.bdev = dmc->disk_dev->bdev;
	job->disk.sector = bio->bi_iter.bi_sector;
	job->disk.count = to_sector(bio->bi_iter.bi_size);
	job->dmc = dmc;
	job->bio = bio;
	job->index = index;
	job->error = 0;

	return job;
}

static struct kcached_job *
alloc_kcached_job(struct cache_context *dmc, struct bio *bio, int index)
{
	struct kcached_job *job;

	job = new_kcached_job(dmc, bio, index);
	if (unlikely(!job)) {
		unsigned long	flags;

		DMERR("failed to allocate job\n");

		spin_lock_irqsave(&dmc->cache_spin_lock, flags);
		dmc->cacheinfos[index].state = INVALID;
		spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);

		bio->bi_status = -EIO;
		bio_io_error(bio);
	}
	return job;
}

static void
copy_pcache_to_bio(struct cache_context *dmc, struct bio *bio, int index)
{
	sector_t	sector = index << dmc->block_shift;
	cacheinfo_t	*ci = dmc->cacheinfos + index;
	unsigned long	flags;
	int	err;

	dmc->cache_reads++;
	err = pcache_submit(dmc->pcache, false, sector, bio);

	spin_lock_irqsave(&dmc->cache_spin_lock, flags);

	ASSERT(ci->state == VALID);
	ASSERT(ci->n_readers > 0);
	ci->n_readers--;

	spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);

	if (err == 0)
		bio_endio(bio);
	else {
		bio->bi_status = -EIO;
		bio_io_error(bio);
	}
}

static void
cache_read_miss(struct cache_context *dmc, struct bio *bio, int index)
{
	struct kcached_job *job;

	job = alloc_kcached_job(dmc, bio, index);
	if (likely(job)) {
		job->rw = READSOURCE;
		atomic_inc(&dmc->nr_jobs);
		dmc->disk_reads++;

		dm_io_async_bvec(&job->disk, READ, bio, rc_io_callback, job);
	}
}

static void
cache_read(struct cache_context *dmc, struct bio *bio)
{
	cacheinfo_t	*ci;
	int	index;
	unsigned long	flags;

	spin_lock_irqsave(&dmc->cache_spin_lock, flags);

	if (cache_lookup(dmc, bio, &index, &flags)) {
		dmc->cacheinfos[index].n_readers++;
		dmc->cache_hits++;
		spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);

		copy_pcache_to_bio(dmc, bio, index);
		return;
	}

	ci = dmc->cacheinfos + index;

	if (IS_VALID_CACHE_STATE(ci->state)) {
		/* This means that cache read uses a victim cache */
		dmc->cached_blocks--;
		dmc->replace++;
	}

	ci->state = INPROG;
	ci->dbn = bio->bi_iter.bi_sector;

	spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);

	cache_read_miss(dmc, bio, index);
}

static void
cache_write(struct cache_context *dmc, struct bio *bio)
{
	struct kcached_job	*job;
	cacheinfo_t	*ci;
	int	index;
	unsigned long	flags;

	spin_lock_irqsave(&dmc->cache_spin_lock, flags);

	cache_lookup(dmc, bio, &index, &flags);

	ci = dmc->cacheinfos + index;

	if (IS_VALID_CACHE_STATE(ci->state)) {
		dmc->cached_blocks--;
		dmc->cache_wr_replace++;
	}

	ci->state = INPROG;
	ci->dbn = bio->bi_iter.bi_sector;
	spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);

	job = alloc_kcached_job(dmc, bio, index);
	if (likely(job)) {
		job->rw = WRITESOURCE;
		atomic_inc(&job->dmc->nr_jobs);
		dmc->disk_writes++;

		dm_io_async_bvec(&job->disk, WRITE, bio, rc_io_callback, job);
	}
}

#define bio_barrier(bio)		((bio)->bi_opf & REQ_PREFLUSH)

static int
rc_map(struct dm_target *ti, struct bio *bio)
{
	struct cache_context	*dmc = (struct cache_context *)ti->private;

	if (bio_barrier(bio))
		return -EOPNOTSUPP;

	ASSERT(to_sector(bio->bi_iter.bi_size) <= dmc->block_size);
	if (bio_data_dir(bio) == READ)
		dmc->reads++;
	else
		dmc->writes++;

	if (bio_data_dir(bio) == READ)
		cache_read(dmc, bio);
	else
		cache_write(dmc, bio);
	return DM_MAPIO_SUBMITTED;
}

static inline int
rc_get_dev(struct dm_target *ti, char *pth, struct dm_dev **dmd, char *dmc_dname, sector_t tilen)
{
	int	rc;

	rc = dm_get_device(ti, pth, dm_table_get_mode(ti->table), dmd);
	if (!rc)
		strncpy(dmc_dname, pth, DEV_PATHLEN);
	return rc;
}

static unsigned long
get_max_sectors_by_mem(void)
{
	struct sysinfo	si;

	si_meminfo(&si);
	return (si.totalram * PAGE_SIZE / SECTOR_SIZE / 4);
}

/* Construct a cache mapping.
 *  arg[0]: path to source device
 *  arg[1]: path to cache device
 *  arg[2]: pcache size in MB
 *  arg[3]: cache associativity */
static int cache_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct cache_context *dmc;
	unsigned int consecutive_blocks;
	sector_t i, order, tmpsize;
	sector_t max_sectors_bymem;
	int r = -EINVAL;

	if (argc < 2) {
		ti->error = "stolearn-cache: Need at least 2 arguments";
		goto construct_fail;
	}

	dmc = kzalloc(sizeof(*dmc), GFP_KERNEL);
	if (!dmc) {
		ti->error = "stolearn-cache: Failed to allocate cache context";
		r = -ENOMEM;
		goto construct_fail;
	}

	dmc->tgt = ti;

	if (rc_get_dev(ti, argv[0], &dmc->disk_dev,
	    dmc->disk_devname, ti->len)) {
		ti->error = "stolearn-cache: Disk device lookup failed";
		goto construct_fail1;
	}
	if (rc_get_dev(ti, argv[1], &dmc->cache_dev, dmc->cache_devname, 0)) {
		ti->error = "stolearn-cache: Cache device lookup failed";
		goto construct_fail2;
	}

	dmc->io_client = dm_io_client_create();
	if (IS_ERR(dmc->io_client)) {
		r = PTR_ERR(dmc->io_client);
		ti->error = "Failed to create io client\n";
		goto construct_fail3;
	}

	r = kcached_init(dmc);
	if (r) {
		ti->error = "Failed to initialize kcached";
		goto construct_fail4;
	}
	dmc->block_size = CACHE_BLOCK_SIZE;
	dmc->block_shift = ffs(dmc->block_size) - 1;
	dmc->block_mask = dmc->block_size - 1;

	dmc->size_nominal = to_sector(dmc->cache_dev->bdev->bd_inode->i_size);
	dmc->size = dmc->size_nominal;
	max_sectors_bymem = get_max_sectors_by_mem();
	if (dmc->size > max_sectors_bymem)
		dmc->size = max_sectors_bymem;
	if (argc >= 3) {
		unsigned int    size_in_MB;

		if (kstrtouint(argv[2], 0, &size_in_MB)) {
			ti->error = "stolearn-cache: invalid size format";
			r = -EINVAL;
			goto construct_fail5;
		}
		dmc->size = to_sector(size_in_MB * 1024 * 1024);
	}

	if (argc >= 4) {
		if (kstrtoint(argv[3], 10, &dmc->assoc)) {
			ti->error = "stolearn-cache: Invalid cache associativity";
			r = -EINVAL;
			goto construct_fail5;
		}
		if (!dmc->assoc || (dmc->assoc & (dmc->assoc - 1)) ||
		    dmc->size < dmc->assoc) {
			ti->error = "stolearn-cache: Invalid cache associativity";
			r = -EINVAL;
			goto construct_fail5;
		}
	} else {
		dmc->assoc = DEFAULT_CACHE_ASSOC;
	}

	/* Convert size (in sectors) to blocks. Then round size
	 * (in blocks now) down to a multiple of associativity */
	do_div(dmc->size, dmc->block_size);
	tmpsize = dmc->size;
	do_div(tmpsize, dmc->assoc);
	dmc->size = tmpsize * dmc->assoc;

	do_div(dmc->size_nominal, dmc->block_size);
	tmpsize = dmc->size_nominal;
	do_div(tmpsize, dmc->assoc);
	dmc->size_nominal = tmpsize * dmc->assoc;

	consecutive_blocks = dmc->assoc;
	dmc->consecutive_shift = ffs(consecutive_blocks) - 1;

	DMINFO("allocate %lu-entry cache"
	       "(capacity:%luKB, associativity:%u, block size:%u sectors(%uKB))",
	       dmc->size_nominal, (unsigned long)((dmc->size_nominal * sizeof(cacheinfo_t)) >> 10),
	       dmc->assoc, dmc->block_size, dmc->block_size >> (10 - SECTOR_SHIFT));
	dmc->cacheinfos = vmalloc(dmc->size * sizeof(cacheinfo_t));
	if (dmc->cacheinfos == NULL)
		goto construct_fail6;

	order = (dmc->size >> dmc->consecutive_shift) * sizeof(u32);
	dmc->set_lru_next = vmalloc(order);
	if (!dmc->set_lru_next)
		goto construct_fail7;

	for (i = 0; i < dmc->size; i++) {
		dmc->cacheinfos[i].dbn = 0;
		dmc->cacheinfos[i].n_readers = 0;
		dmc->cacheinfos[i].state = INVALID;
	}

	/* Initialize the point where LRU sweeps begin for each set */
	for (i = 0; i < (dmc->size >> dmc->consecutive_shift); i++)
		dmc->set_lru_next[i] = i * dmc->assoc;

	spin_lock_init(&dmc->cache_spin_lock);

	dmc->reads = 0;
	dmc->writes = 0;
	dmc->cache_hits = 0;
	dmc->replace = 0;
	dmc->wr_invalidates = 0;
	dmc->rd_invalidates = 0;
	dmc->cached_blocks = 0;
	dmc->cache_wr_replace = 0;

	r = dm_set_target_max_io_len(ti, dmc->block_size);
	if (r)
		goto construct_fail7;
	ti->private = dmc;

	dmc->pcache = pcache_create();

	return 0;

construct_fail7:
	vfree(dmc->cacheinfos);
construct_fail6:
	r = -ENOMEM;
	ti->error = "Unable to allocate memory";
construct_fail5:
	kcached_client_destroy(dmc);
construct_fail4:
	dm_io_client_destroy(dmc->io_client);
construct_fail3:
	dm_put_device(ti, dmc->cache_dev);
construct_fail2:
	dm_put_device(ti, dmc->disk_dev);
construct_fail1:
	kfree(dmc);
construct_fail:
	return r;
}

static void cache_dtr(struct dm_target *ti)
{
	struct cache_context *dmc = (struct cache_context *) ti->private;

	kcached_client_destroy(dmc);

	if (dmc->reads + dmc->writes > 0) {
		DMINFO("stats:\n\treads(%lu), writes(%lu)\n",
		       dmc->reads, dmc->writes);
		DMINFO("\tcache hits(%lu), replacement(%lu), write replacement(%lu)\n"
			"\tread invalidates(%lu), write invalidates(%lu)\n",
			dmc->cache_hits, dmc->replace, dmc->cache_wr_replace,
			dmc->rd_invalidates, dmc->wr_invalidates);
		DMINFO("conf:\n\tcapacity(%luM), associativity(%u), block size(%uK)\n"
		       "\ttotal blocks(%lu)\n",
		       (unsigned long)dmc->size_nominal * dmc->block_size >> 11,
		       dmc->assoc, dmc->block_size >> (10 - SECTOR_SHIFT),
		       (unsigned long)dmc->size_nominal);
	}

	pcache_delete(dmc->pcache);

	dm_io_client_destroy(dmc->io_client);
	vfree(dmc->cacheinfos);
	vfree(dmc->set_lru_next);

	dm_put_device(ti, dmc->disk_dev);
	dm_put_device(ti, dmc->cache_dev);
	kfree(dmc);
}

static void rc_status_info(struct cache_context *dmc, status_type_t type,
			    char *result, unsigned int maxlen)
{
	int sz = 0;

	DMEMIT("stats:\n\treads(%lu), writes(%lu)\n", dmc->reads, dmc->writes);
	DMEMIT("\tcache hits(%lu), replacement(%lu), write replacement(%lu)\n"
		"\tread invalidates(%lu), write invalidates(%lu)\n"
		"\tuncached reads(%lu), uncached writes(%lu)\n"
		"\tdisk reads(%lu), disk writes(%lu)\n"
		"\tcache reads(%lu), cache writes(%lu)\n",
		dmc->cache_hits, dmc->replace, dmc->cache_wr_replace,
		dmc->rd_invalidates, dmc->wr_invalidates,
		dmc->uncached_reads, dmc->uncached_writes,
		dmc->disk_reads, dmc->disk_writes,
		dmc->cache_reads, dmc->cache_writes);
}

static void rc_status_table(struct cache_context *dmc, status_type_t type,
			     char *result, unsigned int maxlen)
{
	int sz = 0;

	DMEMIT("conf:\n\tStolearn-NN dev (%s), disk dev (%s)"
	       "\tcapacity(%luM), associativity(%u), block size(%uK)\n"
	       "\ttotal blocks(%lu)\n",
	       dmc->cache_devname, dmc->disk_devname,
	       (unsigned long)dmc->size_nominal * dmc->block_size >> 11, dmc->assoc,
	       dmc->block_size >> (10 - SECTOR_SHIFT),
	       (unsigned long)dmc->size_nominal);
}

static void
cache_status(struct dm_target *ti, status_type_t type, unsigned status_flags,
	     char *result, unsigned int maxlen)
{
	struct cache_context *dmc = (struct cache_context *)ti->private;

	switch (type) {
	case STATUSTYPE_INFO:
		rc_status_info(dmc, type, result, maxlen);
		break;
	case STATUSTYPE_TABLE:
		rc_status_table(dmc, type, result, maxlen);
		break;
	}
}

static struct target_type cache_target = {
	.name    = "stolearn-cache",
	.version = {1, 0, 0},
	.module  = THIS_MODULE,
	.ctr	 = cache_ctr,
	.dtr	 = cache_dtr,
	.map	 = rc_map,
	.status  = cache_status,
};

int __init rc_init(void)
{
	int ret;

	ret = jobs_init();
	if (ret)
		return ret;

	ret = dm_register_target(&cache_target);
	if (ret < 0)
		return ret;
	return 0;
}

void rc_exit(void)
{
	dm_unregister_target(&cache_target);
	jobs_exit();
}

module_init(rc_init);
module_exit(rc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("oslab <oslab@oslab.ewha.ac.kr>");
MODULE_DESCRIPTION("Stolearn-Cache is a machine learning based caching target with NN model.");
MODULE_VERSION(VERSION_STR);
MODULE_INFO(Copyright, "Copyleft 2021 OSLAB, Ewha");
MODULE_SOFTDEP("pre: stolearn_nn");
