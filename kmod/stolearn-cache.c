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

#define BYTES_PER_BLOCK		512
/* Default cache parameters */
#define DEFAULT_CACHE_ASSOC	512
#define CACHE_BLOCK_SIZE	(PAGE_SIZE / BYTES_PER_BLOCK)
#define CONSECUTIVE_BLOCKS	512

#define DEV_PATHLEN	128

#ifndef DM_MAPIO_SUBMITTED
#define DM_MAPIO_SUBMITTED	0
#endif

#define WT_MIN_JOBS	1024
/* Number of pages for I/O */

typedef unsigned long	bno_t;

#define IS_READ_JOB(type)	((type) == READ_BACKINGDEV || (type) == READ_CACHINGDEV)

typedef enum {
	READ_BACKINGDEV = 1,
	READ_CACHINGDEV_PAGE,
	WRITE_BACKINGDEV,
	READ_CACHINGDEV,
	WRITE_CACHINGDEV
} job_type_t;

/* States of a cache block */
typedef enum {
	INVALID = 0,
	VALID,
	INPROG	/* IO (cache fill) is in progress */
} cache_state_t;

#define SECTOR_TO_BNO(stl, sector)	((sector) >> (stl)->block_shift)
#define BNO_TO_SECTOR(stl, bno)		((bno) << (stl)->block_shift)

/* Cache block metadata structure */
#pragma pack(push, 1)
typedef struct _cacheinfo {
	bno_t	bno;		/* block number, index of the cached block */
	u8	n_readers;
	cache_state_t	state:7;
	bool	dirty:1;
} cacheinfo_t;
#pragma pack(pop)

struct _stolearn;
struct _cacheset;

typedef bool (*writeback_t)(struct _cacheset *ccs, cacheinfo_t *ci, bno_t bno_cb, unsigned long *pflags);

typedef struct _cacheset {
	struct _stolearn	*stl;
	unsigned long	size;
	writeback_t	writeback;
	cacheinfo_t	*cacheinfos;
	/* next bno per set for validity test */
	bno_t	*bnos_next;
} cacheset_t;

/* stolearn */
typedef struct _stolearn {
	struct dm_target	*tgt;
	struct dm_dev		*dev_backing, *dev_caching;
	pcache_t		*pcache;

	spinlock_t	lock;
	/* Wait queue for INPROG state completion */
	wait_queue_head_t	inprogq;

	cacheset_t	mcacheset;
	cacheset_t	dcacheset;

	struct dm_io_client	*io_client;

	unsigned long	reads, writes;
	unsigned int	assoc;
	unsigned int	block_size;
	unsigned int	block_shift;
	unsigned int	consecutive_shift;

	atomic_t		nr_jobs;	/* Number of I/O jobs */
	wait_queue_head_t	destroyq;	/* Wait queue for I/O completion */

	/* Stats */
	unsigned long	cache_hits;
	unsigned long	replace;
	unsigned long	cached_blocks;
	unsigned long	cache_wr_replace;
	unsigned long	cache_reads, cache_writes;
	unsigned long	disk_reads, disk_writes;

	char	devname_backing[DEV_PATHLEN];
	char	devname_caching[DEV_PATHLEN];
} stolearn_t;

/* DM I/O job */
typedef struct _dmio_job {
	job_type_t	type;
	stolearn_t	*stl;
	struct page	*page;
	struct bio	*bio;	/* Original bio */
	struct dm_io_region	dm_iorgn;
	bno_t	bno_db, bno_dcb, bno_mcb;
	int	error;
	struct work_struct	work;
} dmio_job_t;

#define WAIT_INPROG_EVENT(stl, flags, cond)	do {		\
		spin_unlock_irqrestore(&(stl)->lock, flags);	\
		wait_event((stl)->inprogq, cond);		\
		spin_lock_irqsave(&(stl)->lock, flags);		\
	} while (0)

static struct kmem_cache	*job_cache;
static mempool_t		*job_pool;

/* 5.x kernel seem to halt if a map thread exeucutes directly writeback */
static struct workqueue_struct	*wq_writeback;

static bool cache_lookup(cacheset_t *ccs, bno_t bno_db, bno_t *pbno_cb, bool for_write, unsigned long *pflags);
static dmio_job_t *new_dmio_job(stolearn_t *stl, job_type_t type, struct bio *bio, bno_t bno_db, bno_t bno_dcb, bno_t bno_mcb);
static void dmio_done(unsigned long err, void *context);

static void
req_dm_io(dmio_job_t *job, int rw)
{
	stolearn_t	*stl = job->stl;
	struct dm_io_request	iorq;
	struct page_list	pagelist;

	iorq.bi_op = rw;
	iorq.bi_op_flags = 0;
	if (job->bio) {
		iorq.mem.type = DM_IO_BIO;
		iorq.mem.ptr.bio = job->bio;
	}
	else {
		pagelist.next = NULL;

		if (job->type == READ_CACHINGDEV_PAGE)
			pagelist.page = job->page = alloc_page(GFP_NOIO);
		else if (job->type == WRITE_BACKINGDEV)
			pagelist.page = job->page;
		else
			pagelist.page = pcache_get_page(stl->pcache, BNO_TO_SECTOR(stl, job->bno_mcb));
		iorq.mem.type = DM_IO_PAGE_LIST;
		iorq.mem.offset = 0;
		iorq.mem.ptr.pl = &pagelist;
	}
	iorq.notify.fn = dmio_done;
	iorq.notify.context = job;
	iorq.client = stl->io_client;

	dm_io(&iorq, 1, &job->dm_iorgn, NULL);
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
	stolearn_t	*stl = job->stl;

	if (job->page)
		__free_page(job->page);
	mempool_free(job, job_pool);
	if (atomic_dec_and_test(&stl->nr_jobs))
		wake_up(&stl->destroyq);
}

static void
copy_bio_to_pcache(cacheset_t *mcs, struct bio *bio, bno_t bno_mcb)
{
	stolearn_t	*stl = mcs->stl;
	cacheinfo_t	*mci = mcs->cacheinfos + bno_mcb;
	unsigned long	flags;
	int	err = -EINVAL;

	if (to_sector(bio->bi_iter.bi_size) == stl->block_size) {
		sector_t	sector = bno_mcb << stl->block_shift;

		stl->cache_writes++;

		err = pcache_submit(stl->pcache, true, sector, bio);
	}

	spin_lock_irqsave(&stl->lock, flags);

	ASSERT(mci->state == INPROG);

	if (err != 0) {
		mci->state = INVALID;
	} else {
		mci->state = VALID;
		mci->dirty = true;
		stl->cached_blocks++;
	}

	wake_up_all(&stl->inprogq);
	spin_unlock_irqrestore(&stl->lock, flags);

	bio_endio(bio);
}

static void
dmio_done(unsigned long err, void *context)
{
	dmio_job_t	*job = (dmio_job_t *)context;
	stolearn_t	*stl = job->stl;
	bno_t		bno_mcb = job->bno_mcb;
	cacheinfo_t	*dci;
	struct bio	*bio;
	unsigned long	flags;
	bool		partial_blk = false;

	bio = job->bio;
	if (err) {
		DMERR("%s: job_type: %d, io error: %ld", __func__, job->type, err);
	}

	if (err == 0 && IS_READ_JOB(job->type)) {
		ASSERT(bio);

		if (to_sector(bio->bi_iter.bi_size) != stl->block_size)
			partial_blk = true;
		else {
			sector_t	sector = bno_mcb << stl->block_shift;
			err = pcache_submit(stl->pcache, true, sector, bio);
		}
	}

	spin_lock_irqsave(&stl->lock, flags);

	if (job->type == READ_CACHINGDEV_PAGE) {
		job->type = WRITE_BACKINGDEV;
		job->dm_iorgn.bdev = stl->dev_backing->bdev;
		job->dm_iorgn.sector = BNO_TO_SECTOR(stl, job->bno_db);
		queue_work(wq_writeback, &job->work);
		spin_unlock_irqrestore(&stl->lock, flags);
		return;
	}

	dci = stl->dcacheset.cacheinfos + job->bno_dcb;

	if (job->type == WRITE_BACKINGDEV) {
		if (err != 0) {
			dci->state = INVALID;
		}
		else {
			dci->state = VALID;
			dci->dirty = false;
		}
	}
	else {
		cacheset_t	*mcs = &stl->mcacheset;
		cacheinfo_t	*mci = mcs->cacheinfos + bno_mcb;

		ASSERT(mci->state == INPROG);

		if (job->type == READ_CACHINGDEV) {
			ASSERT(dci->n_readers > 0);
			dci->n_readers--;
		}

		if (partial_blk || err != 0) {
			mci->state = INVALID;
			if (job->type == WRITE_CACHINGDEV)
				dci->state = INVALID;
		} else {
			mci->state = VALID;
			mci->dirty = false;
			if (job->type == WRITE_CACHINGDEV) {
				dci->state = VALID;
				dci->dirty = true;
			}
		}
	}

	wake_up_all(&stl->inprogq);

	spin_unlock_irqrestore(&stl->lock, flags);

	if (bio) {
		if (err) {
			bio->bi_status= err;
			bio_io_error(bio);
		}
		else
			bio_endio(bio);
	}

	job_free(job);
}

static unsigned long
hash_block(cacheset_t *ccs, bno_t bno)
{
	stolearn_t	*stl = ccs->stl;
	unsigned long	set_number;
	uint64_t	value;

	value = bno >> stl->consecutive_shift;
	set_number = do_div(value, (ccs->size >> stl->consecutive_shift));
	return set_number;
}

static bool
find_valid_cb(cacheset_t *ccs, bool for_write, bno_t bno, bno_t bno_start, bno_t *pbno, unsigned long *pflags)
{
	stolearn_t	*stl = ccs->stl;
	cacheinfo_t	*ci;
	bno_t	bno_end = bno_start + stl->assoc;
	bno_t	i;

again:
	for (i = bno_start, ci = ccs->cacheinfos + bno_start; i < bno_end; i++, ci++) {
		if (bno == ci->bno) {
			switch (ci->state) {
			case VALID:
				if (for_write && ci->n_readers > 0) {
					WAIT_INPROG_EVENT(stl, *pflags, ci->n_readers == 0);
					goto again;
				}
				*pbno = i;
				return true;
			case INPROG:
				WAIT_INPROG_EVENT(stl, *pflags, ci->state != INPROG);
				goto again;
			default:
				break;
			}
		}
	}
	return false;
}

static bool
find_invalid_cb(cacheset_t *ccs, bno_t bno_start, bno_t *pbno)
{
	bno_t	bno_end = bno_start + ccs->stl->assoc;
	bno_t	i;

	/* Find INVALID slot that we can reuse */
	for (i = bno_start; i < bno_end; i++) {
		if (ccs->cacheinfos[i].state == INVALID) {
			*pbno = i;
			return true;
		}
	}
	return false;
}

static bool
has_nonprog_cb(cacheset_t *ccs, bno_t bno_start)
{
	bno_t	bno_end = bno_start + ccs->stl->assoc;
	cacheinfo_t	*ci;
	bno_t	i;

	/* Find INVALID slot that we can reuse */
	for (i = bno_start, ci = ccs->cacheinfos + i; i < bno_end; i++, ci++) {
		if (ci->state != INPROG && ci->n_readers == 0) {
			return true;
		}
	}
	return false;
}

#define NEXT_BNO(bno, bno_start, bno_end) \
	((bno) + 1 == (bno_end)) ? (bno_start): ((bno) + 1)

static void
do_dmio_async(struct work_struct *work)
{
	dmio_job_t	*job = container_of(work, dmio_job_t, work);
	int	op;

	if (job->type == WRITE_CACHINGDEV || job->type == WRITE_BACKINGDEV)
		op = REQ_OP_WRITE;
	else
		op = REQ_OP_READ;
	req_dm_io(job, op);
}

static bool
writeback_mcb(cacheset_t *mcs, cacheinfo_t *ci, bno_t bno_mcb, unsigned long *pflags)
{
	stolearn_t	*stl = mcs->stl;
	cacheset_t	*dcs = &stl->dcacheset;
	cacheinfo_t	*dci;
	bno_t		bno_dcb = 0;
	dmio_job_t	*job;

	cache_lookup(dcs, ci->bno, &bno_dcb, true, pflags);

	dci = dcs->cacheinfos + bno_dcb;
	dci->bno = ci->bno;
	dci->state = INPROG;

	job = new_dmio_job(stl, WRITE_CACHINGDEV, NULL, ci->bno, bno_dcb, bno_mcb);
	if (unlikely(!job)) {
		dci->state = INVALID;
		wake_up_all(&stl->inprogq);
		return false;
	}

	atomic_inc(&stl->nr_jobs);
	stl->disk_writes++;
	INIT_WORK(&job->work, do_dmio_async);
	queue_work(wq_writeback, &job->work);

	return true;
}

static bool
writeback_dcb(cacheset_t *dcs, cacheinfo_t *ci, bno_t bno_dcb, unsigned long *pflags)
{
	stolearn_t	*stl = dcs->stl;
	dmio_job_t	*job;

	job = new_dmio_job(stl, READ_CACHINGDEV_PAGE, NULL, ci->bno, bno_dcb, 0);
	if (unlikely(!job))
		return false;

	atomic_inc(&stl->nr_jobs);
	stl->disk_writes++;
	INIT_WORK(&job->work, do_dmio_async);
	queue_work(wq_writeback, &job->work);

	return true;
}

static bool
find_reclaim_cb(cacheset_t *ccs, bno_t bno_start, bno_t *pbno_reclaimed, unsigned long *pflags)
{
	stolearn_t	*stl = ccs->stl;
	bno_t	bno_end = bno_start + stl->assoc;
	int	set = bno_start / stl->assoc;
	int	slots_searched = 0;
	bno_t	bno_next;

	/* Find the "oldest" VALID slot to recycle. For each set, we keep
	 * track of the next "lru" slot to pick off. Each time we pick off
	 * a VALID entry to recycle we advance this pointer. So  we sweep
	 * through the set looking for next blocks to recycle. This
	 * approximates to FIFO (modulo for blocks written through). */
	bno_next = ccs->bnos_next[set];
	while (slots_searched < stl->assoc) {
		cacheinfo_t	*ci = ccs->cacheinfos + bno_next;

		ASSERT(bno_next >= bno_start && bno_next < bno_end);

		if (ci->state == VALID && ci->n_readers == 0) {
			if (ci->dirty) {
				ci->state = INPROG;
				if (!ccs->writeback(ccs, ci, bno_next, pflags)) {
					/* revert to */
					ci->state = VALID;
				}
			}
			else {
				*pbno_reclaimed = bno_next;
				ccs->bnos_next[set] = NEXT_BNO(bno_next, bno_start, bno_end);
				return true;
			}
		}
		slots_searched++;
		bno_next = NEXT_BNO(bno_next, bno_start, bno_end);
	}
	return false;
}

static bool
cache_lookup(cacheset_t *ccs, bno_t bno_db, bno_t *pbno_cb, bool for_write, unsigned long *pflags)
{
	stolearn_t	*stl = ccs->stl;
	unsigned long	set_number = hash_block(ccs, bno_db);
	bno_t	bno_invalid;
	bno_t	bno_start;

	bno_start = stl->assoc * set_number;

again:
	if (find_valid_cb(ccs, for_write, bno_db, bno_start, pbno_cb, pflags))
		return true;

	if (find_invalid_cb(ccs, bno_start, &bno_invalid))
		*pbno_cb = bno_invalid;
	else {
		bno_t	bno_reclaimed;

		/* We didn't find an invalid entry, search for oldest valid entry */
		if (!find_reclaim_cb(ccs, bno_start, &bno_reclaimed, pflags)) {
			WAIT_INPROG_EVENT(stl, *pflags, has_nonprog_cb(ccs, bno_start));
			goto again;
		}
		*pbno_cb = bno_reclaimed;
	}

	return false;
}

static dmio_job_t *
new_dmio_job(stolearn_t *stl, job_type_t type, struct bio *bio, bno_t bno_db, bno_t bno_dcb, bno_t bno_mcb)
{
	dmio_job_t	*job;

	job = mempool_alloc(job_pool, GFP_NOIO);
	if (job == NULL) {
		DMERR("failed to allocate job\n");
		return NULL;
	}

	if (type == READ_CACHINGDEV || type == WRITE_CACHINGDEV || type == READ_CACHINGDEV_PAGE) {
		job->dm_iorgn.bdev = stl->dev_caching->bdev;
		job->dm_iorgn.sector = BNO_TO_SECTOR(stl, bno_dcb);
		if (bio) {
			job->dm_iorgn.sector += (bio->bi_iter.bi_sector % stl->block_size);
			job->dm_iorgn.count = to_sector(bio->bi_iter.bi_size);
		}
		else {
			job->dm_iorgn.count = stl->block_size;
		}
	}
	else {
		job->dm_iorgn.bdev = stl->dev_backing->bdev;
		job->dm_iorgn.sector = bio->bi_iter.bi_sector;
		job->dm_iorgn.count = to_sector(bio->bi_iter.bi_size);
	}

	job->stl = stl;
	job->type = type;
	job->bio = bio;
	job->bno_db = bno_db;
	job->bno_dcb = bno_dcb;
	job->bno_mcb = bno_mcb;
	job->error = 0;
	job->page = NULL;

	return job;
}

static void
copy_pcache_to_bio(cacheset_t *ccs, struct bio *bio, bno_t bno)
{
	stolearn_t	*stl = ccs->stl;
	sector_t	sector = BNO_TO_SECTOR(stl, bno);
	cacheinfo_t	*ci = ccs->cacheinfos + bno;
	unsigned long	flags;
	int	err;

	stl->cache_reads++;

	// bio sector alignment
	sector += (bio->bi_iter.bi_sector % stl->block_size);
	err = pcache_submit(stl->pcache, false, sector, bio);

	spin_lock_irqsave(&stl->lock, flags);

	ASSERT(ci->state == VALID);
	ASSERT(ci->n_readers > 0);
	ci->n_readers--;

	if (ci->n_readers == 0)
		wake_up_all(&stl->inprogq);
	spin_unlock_irqrestore(&stl->lock, flags);

	if (err == 0)
		bio_endio(bio);
	else {
		bio->bi_status = -EIO;
		bio_io_error(bio);
	}
}

static bool
mcache_read_fault(stolearn_t *stl, struct bio *bio, bno_t bno_mcb)
{
	cacheset_t	*dcs = &stl->dcacheset;
	dmio_job_t	*job;
	bno_t	bno_db = SECTOR_TO_BNO(stl, bio->bi_iter.bi_sector);
	bno_t	bno_dcb;
	cacheinfo_t	*dci = NULL;
	unsigned long	flags;

	spin_lock_irqsave(&stl->lock, flags);

	if (cache_lookup(dcs, bno_db, &bno_dcb, false, &flags)) {
		dci = stl->dcacheset.cacheinfos + bno_dcb;
		dci->n_readers++;
		job = new_dmio_job(stl, READ_CACHINGDEV, bio, 0, bno_dcb, bno_mcb);
	}
	else {
		job = new_dmio_job(stl, READ_BACKINGDEV, bio, 0, 0, bno_mcb);
	}

	if (unlikely(!job)) {
		if (dci) {
			ASSERT(dci->n_readers > 0);
			dci->n_readers--;
			if (dci->n_readers == 0)
				wake_up_all(&stl->inprogq);
		}
		spin_unlock_irqrestore(&stl->lock, flags);
		return false;
	}

	atomic_inc(&stl->nr_jobs);
	stl->disk_reads++;

	spin_unlock_irqrestore(&stl->lock, flags);

	req_dm_io(job, REQ_OP_READ);

	return true;
}

static void
mcache_read(stolearn_t *stl, struct bio *bio)
{
	cacheset_t	*mcs = &stl->mcacheset;
	cacheinfo_t	*ci;
	bno_t	bno_db = SECTOR_TO_BNO(stl, bio->bi_iter.bi_sector);
	bno_t	bno_mcb;
	unsigned long	flags;

	spin_lock_irqsave(&stl->lock, flags);

	if (cache_lookup(mcs, bno_db, &bno_mcb, false, &flags)) {
		mcs->cacheinfos[bno_mcb].n_readers++;
		stl->cache_hits++;
		spin_unlock_irqrestore(&stl->lock, flags);

		copy_pcache_to_bio(mcs, bio, bno_mcb);
		return;
	}

	ci = mcs->cacheinfos + bno_mcb;

	if (ci->state == VALID) {
		/* This means that cache read uses a victim cache */
		stl->cached_blocks--;
		stl->replace++;
	}

	ci->state = INPROG;
	ci->bno = SECTOR_TO_BNO(stl, bio->bi_iter.bi_sector);

	spin_unlock_irqrestore(&stl->lock, flags);

	if (!mcache_read_fault(stl, bio, bno_mcb)) {
		spin_lock_irqsave(&stl->lock, flags);
		ci->state = INVALID;
		wake_up_all(&stl->inprogq);
		spin_unlock_irqrestore(&stl->lock, flags);

		bio->bi_status = -EIO;
		bio_io_error(bio);
	}
}

static void
mcache_write(stolearn_t *stl, struct bio *bio)
{
	cacheset_t	*mcs = &stl->mcacheset;
	cacheinfo_t	*ci;
	bno_t	bno_db = SECTOR_TO_BNO(stl, bio->bi_iter.bi_sector);
	bno_t	bno_mcb;
	unsigned long	flags;

	spin_lock_irqsave(&stl->lock, flags);

	cache_lookup(mcs, bno_db, &bno_mcb, true, &flags);

	ci = mcs->cacheinfos + bno_mcb;

	if (ci->state == VALID) {
		stl->cached_blocks--;
		stl->cache_wr_replace++;
	}

	ci->state = INPROG;
	ci->bno = SECTOR_TO_BNO(stl, bio->bi_iter.bi_sector);

	spin_unlock_irqrestore(&stl->lock, flags);

	copy_bio_to_pcache(mcs, bio, bno_mcb);
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
		mcache_read(stl, bio);
	else
		mcache_write(stl, bio);
	return DM_MAPIO_SUBMITTED;
}

static void
writeback_all_dirty(cacheset_t *ccs)
{
	stolearn_t	*stl = ccs->stl;
	cacheinfo_t	*ci;
	unsigned long	flags;
	bno_t	i;

	spin_lock_irqsave(&stl->lock, flags);

	for (i = 0, ci = ccs->cacheinfos; i < ccs->size; i++, ci++) {
		if (ci->state == VALID && ci->dirty) {
			while (ci->n_readers > 0) {
				WAIT_INPROG_EVENT(stl, flags, ci->n_readers == 0);
			}
			ci->state = INPROG;
			writeback_mcb(ccs, ci, i, &flags);
		}
	}

	spin_unlock_irqrestore(&stl->lock, flags);
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
init_caches(cacheset_t *ccs)
{
	stolearn_t	*stl = ccs->stl;
	cacheinfo_t	*ci;
	int	i;

	for (i = 0, ci = ccs->cacheinfos; i < ccs->size; i++, ci++) {
		ci->bno = 0;
		ci->n_readers = 0;
		ci->state = INVALID;
		ci->dirty = false;
	}

	/* Initialize the point where LRU sweeps begin for each set */
	for (i = 0; i < (ccs->size >> stl->consecutive_shift); i++)
		ccs->bnos_next[i] = i * stl->assoc;
}

static bool
init_cacheset(stolearn_t *stl, cacheset_t *ccs, unsigned long size, unsigned int assoc)
{
	ccs->stl = stl;
	ccs->size = convert_sectors_to_blocks(stl, size);

	ccs->cacheinfos = vmalloc(ccs->size * sizeof(cacheinfo_t));
	if (ccs->cacheinfos == NULL)
		return false;

	ccs->bnos_next = vmalloc((ccs->size >> stl->consecutive_shift) * sizeof(u32));
	if (ccs->bnos_next == NULL)
		return false;

	init_caches(ccs);

	return true;
}

static bool
init_stolearn(stolearn_t *stl, unsigned long size_mcache, unsigned int assoc)
{
	unsigned int	consecutive_blocks;
	sector_t	size_dcache;
	sector_t	max_sectors_bymem;

	init_waitqueue_head(&stl->destroyq);
	atomic_set(&stl->nr_jobs, 0);

	stl->block_size = CACHE_BLOCK_SIZE;
	stl->assoc = assoc;

	init_waitqueue_head(&stl->inprogq);
	stl->block_size = CACHE_BLOCK_SIZE;
	stl->block_shift = ffs(stl->block_size) - 1;

	spin_lock_init(&stl->lock);

	consecutive_blocks = assoc;
	stl->consecutive_shift = ffs(consecutive_blocks) - 1;

	stl->reads = 0;
	stl->writes = 0;
	stl->cache_hits = 0;
	stl->replace = 0;
	stl->cached_blocks = 0;
	stl->cache_wr_replace = 0;

	size_dcache = to_sector(stl->dev_caching->bdev->bd_inode->i_size);
	max_sectors_bymem = get_max_sectors_by_mem();
	if (size_mcache == 0)
		size_mcache = size_dcache;
	if (size_mcache > max_sectors_bymem)
		size_mcache = max_sectors_bymem;

	if (!init_cacheset(stl, &stl->mcacheset, size_mcache, assoc))
		return false;
	if (!init_cacheset(stl, &stl->dcacheset, size_dcache, assoc))
		return false;

	stl->mcacheset.writeback = writeback_mcb;
	stl->dcacheset.writeback = writeback_dcb;
	return true;
}

static void
free_cacheset(cacheset_t *ccs)
{
	if (ccs->cacheinfos)
		vfree(ccs->cacheinfos);
	if (ccs->bnos_next)
		vfree(ccs->bnos_next);
}

static void
free_stolearn(stolearn_t *stl)
{
	free_cacheset(&stl->mcacheset);
	free_cacheset(&stl->dcacheset);

	if (stl->pcache)
		pcache_delete(stl->pcache);
	if (stl->io_client)
		dm_io_client_destroy(stl->io_client);

	if (stl->dev_backing)
		dm_put_device(stl->tgt, stl->dev_backing);
	if (stl->dev_caching)
		dm_put_device(stl->tgt, stl->dev_caching);

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
	cacheset_t	*dcs;
	unsigned long	size;
	unsigned int	assoc;
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

	if (rc_get_dev(tgt, argv[0], &stl->dev_backing, stl->devname_backing, tgt->len)) {
		tgt->error = "stolearn-cache: failed to lookup backing device";
		kfree(stl);
		return -EINVAL;
	}
	if (rc_get_dev(tgt, argv[1], &stl->dev_caching, stl->devname_caching, 0)) {
		tgt->error = "stolearn-cache: failed to lookup caching device";
		free_stolearn(stl);
		return -EINVAL;
	}

	if (argc >= 3) {
		if (kstrtoul(argv[2], 0, &size)) {
			tgt->error = "stolearn-cache: invalid size format";
			free_stolearn(stl);
			return -EINVAL;
		}
		size = to_sector(size * 1024 * 1024);
	}
	else
		size = 0;

	if (argc >= 4) {
		if (kstrtoint(argv[3], 10, &assoc)) {
			tgt->error = "stolearn-cache: invalid cache associativity format";
			free_stolearn(stl);
			return -EINVAL;
		}
		if (!assoc || (assoc & (assoc - 1)) || size < assoc) {
			tgt->error = "stolearn-cache: inconsistent cache associativity";
			free_stolearn(stl);
			return -EINVAL;
		}
	} else {
		assoc = DEFAULT_CACHE_ASSOC;
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

	if (!init_stolearn(stl, size, assoc)) {
		tgt->error = "failed to cacheset\n";
		free_stolearn(stl);
		return -ENOMEM;
	}

	dcs = &stl->dcacheset;

	DMINFO("allocate %lu-entry cache"
	       "(capacity:%luKB, associativity:%u, block size:%u sectors(%uKB))",
	       dcs->size, (unsigned long)((dcs->size * sizeof(cacheinfo_t)) >> 10),
	       stl->assoc, stl->block_size, stl->block_size >> (10 - SECTOR_SHIFT));

	err = dm_set_target_max_io_len(tgt, CACHE_BLOCK_SIZE);
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
	stolearn_t	*stl = (stolearn_t *)ti->private;
	cacheset_t	*dcs = &stl->dcacheset;

	writeback_all_dirty(&stl->mcacheset);
	writeback_all_dirty(dcs);
	wait_event(stl->destroyq, !atomic_read(&stl->nr_jobs));

	if (stl->reads + stl->writes > 0) {
		DMINFO("stats:\n\treads(%lu), writes(%lu)\n",
		       stl->reads, stl->writes);
		DMINFO("\tcache hits(%lu), replacement(%lu), write replacement(%lu)\n",
		       stl->cache_hits, stl->replace, stl->cache_wr_replace);
		DMINFO("conf:\n\tcapacity(%luM), associativity(%u), block size(%uK)\n"
		       "\ttotal blocks(%lu)\n",
		       (unsigned long)dcs->size * stl->block_size >> 11,
		       stl->assoc, stl->block_size >> (10 - SECTOR_SHIFT),
		       (unsigned long)dcs->size);
	}

	free_stolearn(stl);
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
	cacheset_t	*ccs = &stl->mcacheset;

	DMEMIT("conf:\n\tStolearn-NN dev (%s), disk dev (%s)"
	       "\tcapacity(%luM), associativity(%u), block size(%uK)\n"
	       "\ttotal blocks(%lu)\n",
	       stl->devname_caching, stl->devname_backing,
	       (unsigned long)ccs->size * stl->block_size >> 11, stl->assoc,
	       stl->block_size >> (10 - SECTOR_SHIFT),
	       (unsigned long)ccs->size);
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

	wq_writeback = create_singlethread_workqueue("writeback");
	if (wq_writeback == NULL) {
		jobs_exit();
		return -ENOMEM;
	}

	ret = dm_register_target(&stolearn_target);
	if (ret < 0) {
		jobs_exit();
		destroy_workqueue(wq_writeback);
		return ret;
	}
	return 0;
}

void
rc_exit(void)
{
	dm_unregister_target(&stolearn_target);
	destroy_workqueue(wq_writeback);
	jobs_exit();
}

module_init(rc_init);
module_exit(rc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("oslab <oslab@oslab.ewha.ac.kr>");
MODULE_DESCRIPTION("Stolearn-Cache is a machine learning based caching target with NN model.");
MODULE_VERSION(VERSION_STR);
MODULE_INFO(Copyright, "Copyleft 2021 OSLAB, Ewha");
