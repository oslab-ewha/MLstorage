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

#define READ_BACKINGDEV		1
#define WRITE_BACKINGDEV	2

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

/* stolearn */
typedef struct _stolearn {
	struct dm_target	*tgt;
	struct dm_dev		*disk_dev;	/* Source device */
	struct dm_dev		*cache_dev;	/* Cache device */
	pcache_t		*pcache;

	spinlock_t	cache_spin_lock;
	cacheinfo_t	*cacheinfos;
	u32	*set_lru_next;

	struct dm_io_client	*io_client;
	unsigned long	size, size_nominal;
	unsigned int	assoc;
	unsigned int	block_size;
	unsigned int	block_shift;
	unsigned int	consecutive_shift;

	wait_queue_head_t	destroyq;	/* Wait queue for I/O completion */
	atomic_t		nr_jobs;	/* Number of I/O jobs */

	wait_queue_head_t	inprogq;	/* Wait queue for INPROG state completion */

	/* Stats */
	unsigned long	reads, writes;
	unsigned long	cache_hits;
	unsigned long	replace;
	unsigned long	cached_blocks;
	unsigned long	cache_wr_replace;
	unsigned long	cache_reads, cache_writes;
	unsigned long	disk_reads, disk_writes;

	char	cache_devname[DEV_PATHLEN];
	char	disk_devname[DEV_PATHLEN];
} stolearn_t;

/* DM I/O job */
typedef struct _dmio_job {
	stolearn_t	*stl;
	struct bio	*bio;	/* Original bio */
	struct dm_io_region	disk;
	int	index;
	int	type;
	int	error;
} dmio_job_t;

static struct kmem_cache	*job_cache;
static mempool_t		*job_pool;

static void
dm_io_async_bvec(struct dm_io_region *where, int rw, struct bio *bio, io_notify_fn fn, void *context)
{
	dmio_job_t *job = (dmio_job_t *)context;
	struct dm_io_request iorq;

	iorq.bi_op = rw;
	iorq.bi_op_flags = 0;
	iorq.mem.type = DM_IO_BIO;
	iorq.mem.ptr.bio = bio;
	iorq.notify.fn = fn;
	iorq.notify.context = context;
	iorq.client = job->stl->io_client;

	dm_io(&iorq, 1, where, NULL);
}

static int
jobs_init(void)
{
	job_cache = kmem_cache_create("dmio-jobs", sizeof(dmio_job_t), __alignof__(dmio_job_t), 0, NULL);
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
job_free(dmio_job_t *job)
{
	stolearn_t *stl = job->stl;

	mempool_free(job, job_pool);
	if (atomic_dec_and_test(&stl->nr_jobs))
		wake_up(&stl->destroyq);
}

static void
copy_bio_to_pcache(stolearn_t *stl, struct bio *bio, int index)
{
	cacheinfo_t	*ci = stl->cacheinfos + index;
	unsigned long	flags;
	int	err;

	if (to_sector(bio->bi_iter.bi_size) == stl->block_size) {
		sector_t	sector = index << stl->block_shift;
		int	err;

		stl->cache_writes++;

		err = pcache_submit(stl->pcache, true, sector, bio);
	}
	else {
		err = -EINVAL;
	}

	bio_endio(bio);

	spin_lock_irqsave(&stl->cache_spin_lock, flags);
	ASSERT(ci->state == INPROG);

	if (err != 0) {
		ci->state = INVALID;
	} else {
		ci->state = VALID;
		stl->cached_blocks++;
	}

	wake_up_all(&stl->inprogq);
	spin_unlock_irqrestore(&stl->cache_spin_lock, flags);
}

static void
dmio_done(unsigned long err, void *context)
{
	dmio_job_t	*job = (dmio_job_t *)context;
	stolearn_t	*stl = job->stl;
	int	index = job->index;
	cacheinfo_t	*ci = stl->cacheinfos + index;
	struct bio	*bio;
	unsigned long	flags;

	bio = job->bio;
	if (err)
		DMERR("%s: io error %ld", __func__, err);

	spin_lock_irqsave(&stl->cache_spin_lock, flags);

	ASSERT(ci->state == INPROG);
	if (err) {
		ci->state = INVALID;
		wake_up_all(&stl->inprogq);
		spin_unlock_irqrestore(&stl->cache_spin_lock, flags);

		bio->bi_status= err;
		bio_io_error(bio);

		job_free(job);
	}
	else {
		spin_unlock_irqrestore(&stl->cache_spin_lock, flags);
		job_free(job);
		copy_bio_to_pcache(stl, bio, index);
	}
}

static unsigned long
hash_block(stolearn_t *stl, sector_t dbn)
{
	unsigned long	set_number;
	uint64_t	value;

	value = (dbn >> (stl->block_shift + stl->consecutive_shift));
	set_number = do_div(value, (stl->size >> stl->consecutive_shift));
	return set_number;
}

static bool
find_valid_dbn(stolearn_t *stl, sector_t dbn, int start_index, int *pindex, unsigned long *pflags)
{
	cacheinfo_t	*ci;
	int	end_index = start_index + stl->assoc;
	int	i;

again:
	for (i = start_index, ci = stl->cacheinfos + start_index; i < end_index; i++, ci++) {
		if (dbn == ci->dbn) {
			switch (ci->state) {
			case VALID:
				*pindex = i;
				return true;
			case INPROG:
				spin_unlock_irqrestore(&stl->cache_spin_lock, *pflags);
				wait_event(stl->inprogq, ci->state != INPROG);
				spin_lock_irqsave(&stl->cache_spin_lock, *pflags);
				goto again;
			default:
				break;
			}
		}
	}
	return false;
}

static bool
find_invalid_dbn(stolearn_t *stl, int start_index, int *pindex)
{
	int	end_index = start_index + stl->assoc;
	int	i;

	/* Find INVALID slot that we can reuse */
	for (i = start_index; i < end_index; i++) {
		if (stl->cacheinfos[i].state == INVALID) {
			if (pindex)
				*pindex = i;
			return true;
		}
	}
	return false;
}

static bool
has_nonprog_dbn(stolearn_t *stl, int start_index)
{
	int	end_index = start_index + stl->assoc;
	int	i;

	/* Find INVALID slot that we can reuse */
	for (i = start_index; i < end_index; i++) {
		if (stl->cacheinfos[i].state != INPROG) {
			return true;
		}
	}
	return false;
}

#define NEXT_INDEX(index, start_index, end_index) \
	((index) + 1 == (end_index)) ? (start_index): ((index) + 1)

static bool
find_reclaim_dbn(stolearn_t *stl, int start_index, int *pindex_reclaimed)
{
	int	end_index = start_index + stl->assoc;
	int	set = start_index / stl->assoc;
	int	slots_searched = 0;
	int	index;

	/* Find the "oldest" VALID slot to recycle. For each set, we keep
	 * track of the next "lru" slot to pick off. Each time we pick off
	 * a VALID entry to recycle we advance this pointer. So  we sweep
	 * through the set looking for next blocks to recycle. This
	 * approximates to FIFO (modulo for blocks written through). */
	index = stl->set_lru_next[set];
	while (slots_searched < stl->assoc) {
		ASSERT(index >= start_index && index < end_index);

		if (IS_VALID_CACHE_STATE(stl->cacheinfos[index].state)) {
			*pindex_reclaimed = index;
			stl->set_lru_next[set] = NEXT_INDEX(index, start_index, end_index);
			return true;
		}
		slots_searched++;
		index = NEXT_INDEX(index, start_index, end_index);
	}
	return false;
}

/* dbn is the starting sector, io_size is the number of sectors. */
static bool
cache_lookup(stolearn_t *stl, struct bio *bio, int *pindex, unsigned long *pflags)
{
	sector_t dbn = bio->bi_iter.bi_sector;
	unsigned long	set_number = hash_block(stl, dbn);
	int	index_invalid;
	int	start_index;

	start_index = stl->assoc * set_number;

again:
	if (find_valid_dbn(stl, dbn, start_index, pindex, pflags))
		return true;

	if (find_invalid_dbn(stl, start_index, &index_invalid))
		*pindex = index_invalid;
	else {
		int	index_reclaimed;

		/* We didn't find an invalid entry, search for oldest valid entry */
		if (!find_reclaim_dbn(stl, start_index, &index_reclaimed)) {
			spin_unlock_irqrestore(&stl->cache_spin_lock, *pflags);
			wait_event(stl->inprogq, has_nonprog_dbn(stl, start_index));
			spin_lock_irqsave(&stl->cache_spin_lock, *pflags);
			goto again;
		}
		*pindex = index_reclaimed;
	}

	return INVALID;
}

static dmio_job_t *
new_dmio_job(stolearn_t *stl, struct bio *bio, int index)
{
	dmio_job_t	*job;

	job = mempool_alloc(job_pool, GFP_NOIO);
	if (job == NULL)
		return NULL;

	job->disk.bdev = stl->disk_dev->bdev;
	job->disk.sector = bio->bi_iter.bi_sector;
	job->disk.count = to_sector(bio->bi_iter.bi_size);
	job->stl = stl;
	job->bio = bio;
	job->index = index;
	job->error = 0;

	return job;
}

static dmio_job_t *
alloc_dmio_job(stolearn_t *stl, struct bio *bio, int index)
{
	dmio_job_t *job;

	job = new_dmio_job(stl, bio, index);
	if (unlikely(!job)) {
		unsigned long	flags;

		DMERR("failed to allocate job\n");

		spin_lock_irqsave(&stl->cache_spin_lock, flags);
		stl->cacheinfos[index].state = INVALID;
		spin_unlock_irqrestore(&stl->cache_spin_lock, flags);

		bio->bi_status = -EIO;
		bio_io_error(bio);
	}
	return job;
}

static void
copy_pcache_to_bio(stolearn_t *stl, struct bio *bio, int index)
{
	sector_t	sector = index << stl->block_shift;
	cacheinfo_t	*ci = stl->cacheinfos + index;
	unsigned long	flags;
	int	err;

	stl->cache_reads++;
	err = pcache_submit(stl->pcache, false, sector, bio);

	spin_lock_irqsave(&stl->cache_spin_lock, flags);

	ASSERT(ci->state == VALID);
	ASSERT(ci->n_readers > 0);
	ci->n_readers--;

	spin_unlock_irqrestore(&stl->cache_spin_lock, flags);

	if (err == 0)
		bio_endio(bio);
	else {
		bio->bi_status = -EIO;
		bio_io_error(bio);
	}
}

static void
cache_read_miss(stolearn_t *stl, struct bio *bio, int index)
{
	dmio_job_t	*job;

	job = alloc_dmio_job(stl, bio, index);
	if (likely(job)) {
		job->type = READ_BACKINGDEV;
		atomic_inc(&stl->nr_jobs);
		stl->disk_reads++;

		dm_io_async_bvec(&job->disk, READ, bio, dmio_done, job);
	}
}

static void
cache_read(stolearn_t *stl, struct bio *bio)
{
	cacheinfo_t	*ci;
	int	index;
	unsigned long	flags;

	spin_lock_irqsave(&stl->cache_spin_lock, flags);

	if (cache_lookup(stl, bio, &index, &flags)) {
		stl->cacheinfos[index].n_readers++;
		stl->cache_hits++;
		spin_unlock_irqrestore(&stl->cache_spin_lock, flags);

		copy_pcache_to_bio(stl, bio, index);
		return;
	}

	ci = stl->cacheinfos + index;

	if (IS_VALID_CACHE_STATE(ci->state)) {
		/* This means that cache read uses a victim cache */
		stl->cached_blocks--;
		stl->replace++;
	}

	ci->state = INPROG;
	ci->dbn = bio->bi_iter.bi_sector;

	spin_unlock_irqrestore(&stl->cache_spin_lock, flags);

	cache_read_miss(stl, bio, index);
}

static void
cache_write(stolearn_t *stl, struct bio *bio)
{
	dmio_job_t	*job;
	cacheinfo_t	*ci;
	int	index;
	unsigned long	flags;

	spin_lock_irqsave(&stl->cache_spin_lock, flags);

	cache_lookup(stl, bio, &index, &flags);

	ci = stl->cacheinfos + index;

	if (IS_VALID_CACHE_STATE(ci->state)) {
		stl->cached_blocks--;
		stl->cache_wr_replace++;
	}

	ci->state = INPROG;
	ci->dbn = bio->bi_iter.bi_sector;

	spin_unlock_irqrestore(&stl->cache_spin_lock, flags);

	job = alloc_dmio_job(stl, bio, index);
	if (likely(job)) {
		job->type = WRITE_BACKINGDEV;
		atomic_inc(&job->stl->nr_jobs);
		stl->disk_writes++;

		dm_io_async_bvec(&job->disk, WRITE, bio, dmio_done, job);
	}
}

#define bio_barrier(bio)		((bio)->bi_opf & REQ_PREFLUSH)

static int
stolearn_map(struct dm_target *ti, struct bio *bio)
{
	stolearn_t	*stl = (stolearn_t *)ti->private;

	if (bio_barrier(bio))
		return -EOPNOTSUPP;

	ASSERT(to_sector(bio->bi_iter.bi_size) <= stl->block_size);
	if (bio_data_dir(bio) == READ)
		stl->reads++;
	else
		stl->writes++;

	if (bio_data_dir(bio) == READ)
		cache_read(stl, bio);
	else
		cache_write(stl, bio);
	return DM_MAPIO_SUBMITTED;
}

static inline int
rc_get_dev(struct dm_target *ti, char *pth, struct dm_dev **dmd, char *stl_dname, sector_t tilen)
{
	int	rc;

	rc = dm_get_device(ti, pth, dm_table_get_mode(ti->table), dmd);
	if (!rc)
		strncpy(stl_dname, pth, DEV_PATHLEN);
	return rc;
}

static unsigned long
get_max_sectors_by_mem(void)
{
	struct sysinfo	si;

	si_meminfo(&si);
	return (si.totalram * PAGE_SIZE / SECTOR_SIZE / 4);
}

static unsigned long
convert_sectors_to_blocks(stolearn_t *stl, unsigned long sectors)
{
	unsigned	tmpsize;

	do_div(sectors, stl->block_size);
	tmpsize = sectors;
	do_div(tmpsize, stl->assoc);
	return tmpsize * stl->assoc;
}

static void
init_stolearn(stolearn_t *stl)
{
	sector_t	max_sectors_bymem;
	unsigned int	consecutive_blocks;

	init_waitqueue_head(&stl->destroyq);
	atomic_set(&stl->nr_jobs, 0);

	init_waitqueue_head(&stl->inprogq);
	stl->block_size = CACHE_BLOCK_SIZE;
	stl->block_shift = ffs(stl->block_size) - 1;

	stl->size_nominal = to_sector(stl->cache_dev->bdev->bd_inode->i_size);
	stl->size = stl->size_nominal;
	max_sectors_bymem = get_max_sectors_by_mem();
	if (stl->size > max_sectors_bymem)
		stl->size = max_sectors_bymem;

	spin_lock_init(&stl->cache_spin_lock);

	stl->size = convert_sectors_to_blocks(stl, stl->size);
	stl->size_nominal = convert_sectors_to_blocks(stl, stl->size_nominal);

	consecutive_blocks = stl->assoc;
	stl->consecutive_shift = ffs(consecutive_blocks) - 1;

	stl->reads = 0;
	stl->writes = 0;
	stl->cache_hits = 0;
	stl->replace = 0;
	stl->cached_blocks = 0;
	stl->cache_wr_replace = 0;
}

static void
init_caches(stolearn_t *stl)
{
	cacheinfo_t	*ci;
	int	i;

	for (i = 0, ci = stl->cacheinfos; i < stl->size; i++, ci++) {
		ci->dbn = 0;
		ci->n_readers = 0;
		ci->state = INVALID;
	}

	/* Initialize the point where LRU sweeps begin for each set */
	for (i = 0; i < (stl->size >> stl->consecutive_shift); i++)
		stl->set_lru_next[i] = i * stl->assoc;
}

static void
free_stolearn(stolearn_t *stl)
{
	if (stl->pcache)
		pcache_delete(stl->pcache);
	if (stl->io_client)
		dm_io_client_destroy(stl->io_client);
	if (stl->cacheinfos)
		vfree(stl->cacheinfos);
	if (stl->set_lru_next)
		vfree(stl->set_lru_next);

	if (stl->disk_dev)
		dm_put_device(stl->tgt, stl->disk_dev);
	if (stl->cache_dev)
		dm_put_device(stl->tgt, stl->cache_dev);
	kfree(stl);
}

/* Construct a cache mapping.
 *  arg[0]: path to source device
 *  arg[1]: path to cache device
 *  arg[2]: pcache size in MB
 *  arg[3]: cache associativity */
static int
stolearn_ctr(struct dm_target *tgt, unsigned int argc, char **argv)
{
	stolearn_t	*stl;
	int	err;

	if (argc < 2) {
		tgt->error = "stolearn-cache: at least 2 arguments are required";
		return -EINVAL;
	}

	stl = kzalloc(sizeof(*stl), GFP_KERNEL);
	if (stl == NULL) {
		tgt->error = "stolearn-cache: failed to allocate stolearn object";
		return -ENOMEM;
	}
	stl->tgt = tgt;

	if (rc_get_dev(tgt, argv[0], &stl->disk_dev, stl->disk_devname, tgt->len)) {
		tgt->error = "stolearn-cache: failed to lookup backing device";
		kfree(stl);
		return -EINVAL;
	}
	if (rc_get_dev(tgt, argv[1], &stl->cache_dev, stl->cache_devname, 0)) {
		tgt->error = "stolearn-cache: failed to lookup caching device";
		free_stolearn(stl);
		return -EINVAL;
	}

	if (argc >= 3) {
		unsigned int    size_in_MB;

		if (kstrtouint(argv[2], 0, &size_in_MB)) {
			tgt->error = "stolearn-cache: invalid size format";
			free_stolearn(stl);
			return -EINVAL;
		}
		stl->size = to_sector(size_in_MB * 1024 * 1024);
	}

	if (argc >= 4) {
		if (kstrtoint(argv[3], 10, &stl->assoc)) {
			tgt->error = "stolearn-cache: invalid cache associativity format";
			free_stolearn(stl);
			return -EINVAL;
		}
		if (!stl->assoc || (stl->assoc & (stl->assoc - 1)) || stl->size < stl->assoc) {
			tgt->error = "stolearn-cache: inconsistent cache associativity";
			free_stolearn(stl);
			return -EINVAL;
		}
	} else {
		stl->assoc = DEFAULT_CACHE_ASSOC;
	}

	stl->io_client = dm_io_client_create();
	if (IS_ERR(stl->io_client)) {
		err = PTR_ERR(stl->io_client);

		tgt->error = "failed to create io client\n";
		free_stolearn(stl);
		return err;
	}

	stl->pcache = pcache_create();
	if (stl->pcache == NULL) {
		tgt->error = "failed to create pcache\n";
		free_stolearn(stl);
		return -ENOMEM;
	}

	init_stolearn(stl);

	DMINFO("allocate %lu-entry cache"
	       "(capacity:%luKB, associativity:%u, block size:%u sectors(%uKB))",
	       stl->size_nominal, (unsigned long)((stl->size_nominal * sizeof(cacheinfo_t)) >> 10),
	       stl->assoc, stl->block_size, stl->block_size >> (10 - SECTOR_SHIFT));

	stl->cacheinfos = vmalloc(stl->size * sizeof(cacheinfo_t));
	if (stl->cacheinfos == NULL) {
		tgt->error = "failed to allocate cacheinfos\n";
		free_stolearn(stl);
		return -ENOMEM;
	}

	stl->set_lru_next = vmalloc((stl->size >> stl->consecutive_shift) * sizeof(u32));
	if (stl->set_lru_next == NULL) {
		tgt->error = "failed to allocate set_lru_next\n";
		free_stolearn(stl);
		return -ENOMEM;
	}

	init_caches(stl);

	err = dm_set_target_max_io_len(tgt, stl->block_size);
	if (err) {
		tgt->error = "failed to set max io length\n";
		free_stolearn(stl);
		return err;
	}

	tgt->private = stl;

	return 0;
}

static void
stolearn_dtr(struct dm_target *ti)
{
	stolearn_t	*stl = (stolearn_t *) ti->private;

	wait_event(stl->destroyq, !atomic_read(&stl->nr_jobs));

	if (stl->reads + stl->writes > 0) {
		DMINFO("stats:\n\treads(%lu), writes(%lu)\n",
		       stl->reads, stl->writes);
		DMINFO("\tcache hits(%lu), replacement(%lu), write replacement(%lu)\n",
		       stl->cache_hits, stl->replace, stl->cache_wr_replace);
		DMINFO("conf:\n\tcapacity(%luM), associativity(%u), block size(%uK)\n"
		       "\ttotal blocks(%lu)\n",
		       (unsigned long)stl->size_nominal * stl->block_size >> 11,
		       stl->assoc, stl->block_size >> (10 - SECTOR_SHIFT),
		       (unsigned long)stl->size_nominal);
	}

	pcache_delete(stl->pcache);

	dm_io_client_destroy(stl->io_client);
	vfree(stl->cacheinfos);
	vfree(stl->set_lru_next);

	dm_put_device(ti, stl->disk_dev);
	dm_put_device(ti, stl->cache_dev);
	kfree(stl);
}

static void
stolearn_status_info(stolearn_t *stl, status_type_t type, char *result, unsigned int maxlen)
{
	int	sz = 0;
	DMEMIT("stats:\n\treads(%lu), writes(%lu)\n", stl->reads, stl->writes);
	DMEMIT("\tcache hits(%lu), replacement(%lu), write replacement(%lu)\n"
		"\tdisk reads(%lu), disk writes(%lu)\n"
		"\tcache reads(%lu), cache writes(%lu)\n",
		stl->cache_hits, stl->replace, stl->cache_wr_replace,
		stl->disk_reads, stl->disk_writes,
		stl->cache_reads, stl->cache_writes);
}

static void
stolearn_status_table(stolearn_t *stl, status_type_t type, char *result, unsigned int maxlen)
{
	int	sz = 0;
	DMEMIT("conf:\n\tStolearn-NN dev (%s), disk dev (%s)"
	       "\tcapacity(%luM), associativity(%u), block size(%uK)\n"
	       "\ttotal blocks(%lu)\n",
	       stl->cache_devname, stl->disk_devname,
	       (unsigned long)stl->size_nominal * stl->block_size >> 11, stl->assoc,
	       stl->block_size >> (10 - SECTOR_SHIFT),
	       (unsigned long)stl->size_nominal);
}

static void
stolearn_status(struct dm_target *ti, status_type_t type, unsigned status_flags, char *result, unsigned int maxlen)
{
	stolearn_t	*stl = (stolearn_t *)ti->private;

	switch (type) {
	case STATUSTYPE_INFO:
		stolearn_status_info(stl, type, result, maxlen);
		break;
	case STATUSTYPE_TABLE:
		stolearn_status_table(stl, type, result, maxlen);
		break;
	}
}

static struct target_type stolearn_target = {
	.name    = "stolearn-cache",
	.version = {1, 0, 0},
	.module  = THIS_MODULE,
	.ctr	 = stolearn_ctr,
	.dtr	 = stolearn_dtr,
	.map	 = stolearn_map,
	.status  = stolearn_status,
};

int __init
rc_init(void)
{
	int ret;

	ret = jobs_init();
	if (ret)
		return ret;

	ret = dm_register_target(&stolearn_target);
	if (ret < 0)
		return ret;
	return 0;
}

void
rc_exit(void)
{
	dm_unregister_target(&stolearn_target);
	jobs_exit();
}

module_init(rc_init);
module_exit(rc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("oslab <oslab@oslab.ewha.ac.kr>");
MODULE_DESCRIPTION("Stolearn-Cache is a machine learning based caching target with NN model.");
MODULE_VERSION(VERSION_STR);
MODULE_INFO(Copyright, "Copyleft 2021 OSLAB, Ewha");
