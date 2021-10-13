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
#include "stolearn.h"

#define ASSERT(x) do { \
	if (unlikely(!(x))) { \
		dump_stack(); \
		panic("ASSERT: assertion (%s) failed at %s (%d)\n", \
		#x,  __FILE__, __LINE__); \
	} \
} while (0)

#define VERSION_STR	"1.0.0"
#define DM_MSG_PREFIX	"mlstor-cache"

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

#define SECTOR_TO_BNO(mls, sector)	((sector) >> (mls)->block_shift)
#define BNO_TO_SECTOR(mls, bno)		((bno) << (mls)->block_shift)

/* Cache block metadata structure */
#pragma pack(push, 1)
typedef struct _cacheinfo {
	bno_t	bno;		/* block number, index of the cached block */
	u8	n_readers;
	cache_state_t	state:7;
	bool	dirty:1;
} cacheinfo_t;
#pragma pack(pop)

struct _mlstor;
struct _cacheset;

typedef bool (*writeback_t)(struct _cacheset *ccs, cacheinfo_t *ci, bno_t bno_cb, unsigned long *pflags);

typedef struct _cacheset {
	struct _mlstor	*mls;
	unsigned long	size;
	writeback_t	writeback;
	cacheinfo_t	*cacheinfos;
	unsigned long	n_valids;
	/* next bno per set for validity test */
	bno_t	*bnos_next;
} cacheset_t;

/* mlstor */
typedef struct _mlstor {
	struct dm_target	*tgt;
	struct dm_dev		*dev_backing, *dev_caching;
	stolearn_t		*stl;
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

	unsigned long	n_hit_streaks;
	u64		ns_start_hit_check;
	unsigned long	n_write_streaks;
	u64		ns_start_write_check;

	/* Stats */
	unsigned long	cache_hits;
	unsigned long	replace;
	unsigned long	cached_blocks;
	unsigned long	cache_wr_replace;
	unsigned long	cache_reads, cache_writes;
	unsigned long	disk_reads, disk_writes, disk_writes1, reclaims;

	char	devname_backing[DEV_PATHLEN];
	char	devname_caching[DEV_PATHLEN];
} mlstor_t;

/* DM I/O job */
typedef struct _dmio_job {
	job_type_t	type;
	mlstor_t	*mls;
	struct page	*page;
	struct bio	*bio;	/* Original bio */
	struct dm_io_region	dm_iorgn;
	bno_t	bno_db, bno_dcb, bno_mcb;
	int	error;
	struct work_struct	work;
} dmio_job_t;

#define WAIT_INPROG_EVENT(mls, flags, cond)	do {		\
		spin_unlock_irqrestore(&(mls)->lock, flags);	\
		wait_event((mls)->inprogq, cond);		\
		spin_lock_irqsave(&(mls)->lock, flags);		\
	} while (0)

static struct kmem_cache	*job_cache;
static mempool_t		*job_pool;

/* 5.x kernel seem to halt if a map thread exeucutes directly writeback */
static struct workqueue_struct	*wq_writeback;

static int	*randidx;

static bool cache_lookup(cacheset_t *ccs, bno_t bno_db, bno_t *pbno_cb, bool for_write, unsigned long *pflags);
static dmio_job_t *new_dmio_job(mlstor_t *mls, job_type_t type, struct bio *bio, bno_t bno_db, bno_t bno_dcb, bno_t bno_mcb);
static void dmio_done(unsigned long err, void *context);

static void
req_dm_io(dmio_job_t *job, int rw)
{
	mlstor_t	*mls = job->mls;
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
			pagelist.page = pcache_get_page(mls->pcache, BNO_TO_SECTOR(mls, job->bno_mcb));
		iorq.mem.type = DM_IO_PAGE_LIST;
		iorq.mem.offset = 0;
		iorq.mem.ptr.pl = &pagelist;
	}
	iorq.notify.fn = dmio_done;
	iorq.notify.context = job;
	iorq.client = mls->io_client;

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
	mlstor_t	*mls = job->mls;

	if (job->page)
		__free_page(job->page);
	mempool_free(job, job_pool);
	if (atomic_dec_and_test(&mls->nr_jobs))
		wake_up(&mls->destroyq);
}

static void
copy_bio_to_pcache(cacheset_t *mcs, struct bio *bio, bno_t bno_mcb)
{
	mlstor_t	*mls = mcs->mls;
	cacheinfo_t	*mci = mcs->cacheinfos + bno_mcb;
	unsigned long	flags;
	int	err = -EINVAL;

	if (to_sector(bio->bi_iter.bi_size) == mls->block_size) {
		sector_t	sector = bno_mcb << mls->block_shift;

		mls->cache_writes++;

		err = pcache_submit(mls->pcache, true, sector, bio);
	}

	spin_lock_irqsave(&mls->lock, flags);

	ASSERT(mci->state == INPROG);

	if (err != 0) {
		mci->state = INVALID;
		mcs->n_valids--;
	} else {
		mci->state = VALID;
		mcs->n_valids++;
		mci->dirty = true;
		mls->cached_blocks++;
	}

	wake_up_all(&mls->inprogq);
	spin_unlock_irqrestore(&mls->lock, flags);

	bio_endio(bio);
}

static void
dmio_done(unsigned long err, void *context)
{
	dmio_job_t	*job = (dmio_job_t *)context;
	mlstor_t	*mls = job->mls;
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

		if (to_sector(bio->bi_iter.bi_size) != mls->block_size)
			partial_blk = true;
		else {
			sector_t	sector = bno_mcb << mls->block_shift;
			err = pcache_submit(mls->pcache, true, sector, bio);
		}
	}

	if (job->type == READ_CACHINGDEV_PAGE) {
		job->type = WRITE_BACKINGDEV;
		job->dm_iorgn.bdev = mls->dev_backing->bdev;
		job->dm_iorgn.sector = BNO_TO_SECTOR(mls, job->bno_db);
		queue_work(wq_writeback, &job->work);
		return;
	}

	spin_lock_irqsave(&mls->lock, flags);

	dci = mls->dcacheset.cacheinfos + job->bno_dcb;

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
		cacheset_t	*mcs = &mls->mcacheset;
		cacheinfo_t	*mci = mcs->cacheinfos + bno_mcb;

		ASSERT(mci->state == INPROG);

		if (job->type == READ_CACHINGDEV) {
			ASSERT(dci->n_readers > 0);
			dci->n_readers--;
		}

		if (partial_blk || err != 0) {
			mci->state = INVALID;
			mcs->n_valids--;
			if (job->type == WRITE_CACHINGDEV)
				dci->state = INVALID;
		} else {
			mci->state = VALID;
			mcs->n_valids++;
			mci->dirty = false;
			if (job->type == WRITE_CACHINGDEV) {
				dci->state = VALID;
				dci->dirty = true;
			}
		}
	}

	wake_up_all(&mls->inprogq);

	spin_unlock_irqrestore(&mls->lock, flags);

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
	mlstor_t	*mls = ccs->mls;
	unsigned long	set_number;
	uint64_t	value;

	value = bno >> mls->consecutive_shift;
	set_number = do_div(value, (ccs->size >> mls->consecutive_shift));
	return set_number;
}

static bool
find_valid_cb(cacheset_t *ccs, bool for_write, bno_t bno, bno_t bno_start, bno_t *pbno, unsigned long *pflags)
{
	mlstor_t	*mls = ccs->mls;
	cacheinfo_t	*ci;
	bno_t	bno_end = bno_start + mls->assoc;
	bno_t	i;

again:
	for (i = bno_start, ci = ccs->cacheinfos + bno_start; i < bno_end; i++, ci++) {
		if (bno == ci->bno) {
			switch (ci->state) {
			case VALID:
				if (for_write && ci->n_readers > 0) {
					WAIT_INPROG_EVENT(mls, *pflags, ci->n_readers == 0);
					goto again;
				}
				*pbno = i;
				return true;
			case INPROG:
				WAIT_INPROG_EVENT(mls, *pflags, ci->state != INPROG);
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
	bno_t	bno_end = bno_start + ccs->mls->assoc;
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
	bno_t	bno_end = bno_start + ccs->mls->assoc;
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
	mlstor_t	*mls = mcs->mls;
	cacheset_t	*dcs = &mls->dcacheset;
	cacheinfo_t	*dci;
	bno_t		bno_dcb = 0;
	dmio_job_t	*job;

	cache_lookup(dcs, ci->bno, &bno_dcb, true, pflags);

	dci = dcs->cacheinfos + bno_dcb;
	dci->bno = ci->bno;
	dci->state = INPROG;

	spin_unlock_irqrestore(&mls->lock, *pflags);
	job = new_dmio_job(mls, WRITE_CACHINGDEV, NULL, ci->bno, bno_dcb, bno_mcb);
	spin_lock_irqsave(&mls->lock, *pflags);
	if (unlikely(!job)) {
		dci->state = INVALID;
		wake_up_all(&mls->inprogq);
		return false;
	}

	atomic_inc(&mls->nr_jobs);
	mls->disk_writes++;
	INIT_WORK(&job->work, do_dmio_async);
	queue_work(wq_writeback, &job->work);

	return true;
}

static bool
writeback_dcb(cacheset_t *dcs, cacheinfo_t *ci, bno_t bno_dcb, unsigned long *pflags)
{
	mlstor_t	*mls = dcs->mls;
	dmio_job_t	*job;

	spin_unlock_irqrestore(&mls->lock, *pflags);
	job = new_dmio_job(mls, READ_CACHINGDEV_PAGE, NULL, ci->bno, bno_dcb, 0);
	spin_lock_irqsave(&mls->lock, *pflags);
	if (unlikely(!job))
		return false;

	atomic_inc(&mls->nr_jobs);
	mls->disk_writes1++;
	INIT_WORK(&job->work, do_dmio_async);
	queue_work(wq_writeback, &job->work);

	return true;
}

static bno_t
get_next_bno(replace_pol_t repol, bno_t bno, bno_t bno_start, bno_t bno_end)
{
	switch (repol) {
	case REPOL_LRU:
		return (bno + 1 == bno_end) ? bno_start: bno + 1;
	case REPOL_MRU:
		return (bno == 0) ? bno_end: bno - 1;
	default:
		return bno_start + randidx[bno + 1];
	}
}

static bool
find_reclaim_cb(cacheset_t *ccs, bno_t bno_start, bno_t *pbno_reclaimed, unsigned long *pflags)
{
	mlstor_t	*mls = ccs->mls;
	replace_pol_t	repol;
	bno_t	bno_end = bno_start + mls->assoc;
	int	set = bno_start / mls->assoc;
	int	slots_searched = 0;
	bno_t	bno_next;

	repol = stolearn_get_replace_policy(mls->stl);
	bno_next = ccs->bnos_next[set];
	while (slots_searched < mls->assoc) {
		cacheinfo_t	*ci = ccs->cacheinfos + bno_next;

		ASSERT(bno_next >= bno_start && bno_next < bno_end);

		if (ci->state == VALID && ci->n_readers == 0) {
			if (ci->dirty) {
				ci->state = INPROG;
				ccs->n_valids--;
				if (stolearn_need_writeback(mls->stl)) {
					if (!ccs->writeback(ccs, ci, bno_next, pflags)) {
						/* revert to */
						ci->state = VALID;
						ccs->n_valids++;
					}
				}
			}
			else {
				*pbno_reclaimed = bno_next;
				ccs->bnos_next[set] = get_next_bno(repol, bno_next, bno_start, bno_end);
				return true;
			}
		}
		slots_searched++;
		bno_next = get_next_bno(repol, bno_next, bno_start, bno_end);
	}
	return false;
}

static bool
cache_lookup(cacheset_t *ccs, bno_t bno_db, bno_t *pbno_cb, bool for_write, unsigned long *pflags)
{
	mlstor_t	*mls = ccs->mls;
	unsigned long	set_number = hash_block(ccs, bno_db);
	bno_t	bno_invalid;
	bno_t	bno_start;

	bno_start = mls->assoc * set_number;

again:
	if (find_valid_cb(ccs, for_write, bno_db, bno_start, pbno_cb, pflags))
		return true;

	if (find_invalid_cb(ccs, bno_start, &bno_invalid))
		*pbno_cb = bno_invalid;
	else {
		bno_t	bno_reclaimed;

		/* We didn't find an invalid entry, search for oldest valid entry */
		if (!find_reclaim_cb(ccs, bno_start, &bno_reclaimed, pflags)) {
			WAIT_INPROG_EVENT(mls, *pflags, has_nonprog_cb(ccs, bno_start));
			goto again;
		}
		mls->reclaims++;
		*pbno_cb = bno_reclaimed;
	}

	return false;
}

static dmio_job_t *
new_dmio_job(mlstor_t *mls, job_type_t type, struct bio *bio, bno_t bno_db, bno_t bno_dcb, bno_t bno_mcb)
{
	dmio_job_t	*job;

	job = mempool_alloc(job_pool, GFP_NOIO);
	if (job == NULL) {
		DMERR("failed to allocate job\n");
		return NULL;
	}

	if (type == READ_CACHINGDEV || type == WRITE_CACHINGDEV || type == READ_CACHINGDEV_PAGE) {
		job->dm_iorgn.bdev = mls->dev_caching->bdev;
		job->dm_iorgn.sector = BNO_TO_SECTOR(mls, bno_dcb);
		if (bio) {
			job->dm_iorgn.sector += (bio->bi_iter.bi_sector % mls->block_size);
			job->dm_iorgn.count = to_sector(bio->bi_iter.bi_size);
		}
		else {
			job->dm_iorgn.count = mls->block_size;
		}
	}
	else {
		job->dm_iorgn.bdev = mls->dev_backing->bdev;
		job->dm_iorgn.sector = bio->bi_iter.bi_sector;
		job->dm_iorgn.count = to_sector(bio->bi_iter.bi_size);
	}

	job->mls = mls;
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
	mlstor_t	*mls = ccs->mls;
	sector_t	sector = BNO_TO_SECTOR(mls, bno);
	cacheinfo_t	*ci = ccs->cacheinfos + bno;
	unsigned long	flags;
	int	err;

	mls->cache_reads++;

	// bio sector alignment
	sector += (bio->bi_iter.bi_sector % mls->block_size);
	err = pcache_submit(mls->pcache, false, sector, bio);

	spin_lock_irqsave(&mls->lock, flags);

	ASSERT(ci->state == VALID);
	ASSERT(ci->n_readers > 0);
	ci->n_readers--;

	if (ci->n_readers == 0)
		wake_up_all(&mls->inprogq);
	spin_unlock_irqrestore(&mls->lock, flags);

	if (err == 0)
		bio_endio(bio);
	else {
		bio->bi_status = -EIO;
		bio_io_error(bio);
	}
}

static bool
mcache_read_fault(mlstor_t *mls, struct bio *bio, bno_t bno_mcb)
{
	cacheset_t	*dcs = &mls->dcacheset;
	dmio_job_t	*job;
	bno_t	bno_db = SECTOR_TO_BNO(mls, bio->bi_iter.bi_sector);
	bno_t	bno_dcb;
	cacheinfo_t	*dci = NULL;
	unsigned long	flags;

	spin_lock_irqsave(&mls->lock, flags);

	if (cache_lookup(dcs, bno_db, &bno_dcb, false, &flags)) {
		dci = mls->dcacheset.cacheinfos + bno_dcb;
		dci->n_readers++;
		spin_unlock_irqrestore(&mls->lock, flags);
		job = new_dmio_job(mls, READ_CACHINGDEV, bio, 0, bno_dcb, bno_mcb);
		spin_lock_irqsave(&mls->lock, flags);
	}
	else {
		spin_unlock_irqrestore(&mls->lock, flags);
		job = new_dmio_job(mls, READ_BACKINGDEV, bio, 0, 0, bno_mcb);
		spin_lock_irqsave(&mls->lock, flags);
	}

	if (unlikely(!job)) {
		if (dci) {
			ASSERT(dci->n_readers > 0);
			dci->n_readers--;
			if (dci->n_readers == 0)
				wake_up_all(&mls->inprogq);
		}
		spin_unlock_irqrestore(&mls->lock, flags);
		return false;
	}

	atomic_inc(&mls->nr_jobs);
	mls->disk_reads++;

	spin_unlock_irqrestore(&mls->lock, flags);

	req_dm_io(job, REQ_OP_READ);

	return true;
}

static bool
throttle_read(mlstor_t *mls)
{
	unsigned long	metric;
	u64	ns_cur;

	if (!stolearn_need_throttle_read(mls->stl))
		return false;

	mls->n_hit_streaks++;

	if (mls->n_hit_streaks == 1) {
		mls->ns_start_hit_check = ktime_get_ns();
		return false;
	}

	ns_cur = ktime_get_ns();
	if (ns_cur - mls->ns_start_hit_check > 50000000) {
		mls->ns_start_hit_check = ns_cur;
		mls->n_hit_streaks = 1;
		return false;
	}

	if (mls->n_hit_streaks < 3)
		return false;

	metric = (mls->n_hit_streaks) * 4096 * 1000000000 / (ns_cur - mls->ns_start_hit_check) / 1024 / 1024;
	if (metric > 900) {
		mls->ns_start_hit_check = ns_cur;
		mls->n_hit_streaks = 1;
		return true;
	}
	return false;
}

static void
mcache_read(mlstor_t *mls, struct bio *bio)
{
	cacheset_t	*mcs = &mls->mcacheset;
	cacheinfo_t	*ci;
	bno_t	bno_db = SECTOR_TO_BNO(mls, bio->bi_iter.bi_sector);
	bno_t	bno_mcb;
	unsigned long	flags;

	spin_lock_irqsave(&mls->lock, flags);

	if (cache_lookup(mcs, bno_db, &bno_mcb, false, &flags)) {
		if (throttle_read(mls))
			goto throttle_miss;

		mcs->cacheinfos[bno_mcb].n_readers++;
		mls->cache_hits++;
		spin_unlock_irqrestore(&mls->lock, flags);

		copy_pcache_to_bio(mcs, bio, bno_mcb);
		return;
	}
	else {
		mls->n_hit_streaks = 0;
	}
throttle_miss:

	ci = mcs->cacheinfos + bno_mcb;

	if (ci->state == VALID) {
		/* This means that cache read uses a victim cache */
		mls->cached_blocks--;
		mls->replace++;
		mcs->n_valids--;
	}

	ci->state = INPROG;
	ci->bno = SECTOR_TO_BNO(mls, bio->bi_iter.bi_sector);

	spin_unlock_irqrestore(&mls->lock, flags);

	if (!mcache_read_fault(mls, bio, bno_mcb)) {
		spin_lock_irqsave(&mls->lock, flags);
		ci->state = INVALID;
		wake_up_all(&mls->inprogq);
		spin_unlock_irqrestore(&mls->lock, flags);

		bio->bi_status = -EIO;
		bio_io_error(bio);
	}
}

static void
throttle_write(mlstor_t *mls, unsigned long *pflags)
{
	u64	ns_cur;

	if (!stolearn_need_throttle_write(mls->stl))
		return;

	mls->n_write_streaks++;

	if (mls->n_write_streaks == 1) {
		mls->ns_start_write_check = ktime_get_ns();
		return;
	}

	ns_cur = ktime_get_ns();
	if (ns_cur - mls->ns_start_write_check > 1000000) {
		mls->ns_start_write_check = ns_cur;
		mls->n_write_streaks = 1;
		return;
	}

	while (true) {
		if (ns_cur > mls->ns_start_write_check) {
			unsigned long	metric;

			metric = mls->n_write_streaks * 4096 * 1000000000 / (ns_cur - mls->ns_start_write_check) / 1024 / 1024;
			if (metric < 175)
				break;
		}

		spin_unlock_irqrestore(&mls->lock, *pflags);
		yield();
		spin_lock_irqsave(&mls->lock, *pflags);
		ns_cur = ktime_get_ns();
	}
}

static void
mcache_write(mlstor_t *mls, struct bio *bio)
{
	cacheset_t	*mcs = &mls->mcacheset;
	cacheinfo_t	*ci;
	bno_t	bno_db = SECTOR_TO_BNO(mls, bio->bi_iter.bi_sector);
	bno_t	bno_mcb;
	unsigned long	flags;

	spin_lock_irqsave(&mls->lock, flags);

	throttle_write(mls, &flags);

	cache_lookup(mcs, bno_db, &bno_mcb, true, &flags);

	ci = mcs->cacheinfos + bno_mcb;

	if (ci->state == VALID) {
		mls->cached_blocks--;
		mls->cache_wr_replace++;
		mcs->n_valids--;
	}

	ci->state = INPROG;
	ci->bno = SECTOR_TO_BNO(mls, bio->bi_iter.bi_sector);

	spin_unlock_irqrestore(&mls->lock, flags);

	copy_bio_to_pcache(mcs, bio, bno_mcb);
}

#define bio_barrier(bio)		((bio)->bi_opf & REQ_PREFLUSH)

static int
mlstor_map(struct dm_target *ti, struct bio *bio)
{
	mlstor_t	*mls = (mlstor_t *)ti->private;

	if (bio_barrier(bio))
		return -EOPNOTSUPP;

	stolearn_add_bio(mls->stl, bio);

	ASSERT(to_sector(bio->bi_iter.bi_size) <= mls->block_size);
	if (bio_data_dir(bio) == READ)
		mls->reads++;
	else
		mls->writes++;

	if (bio_data_dir(bio) == READ)
		mcache_read(mls, bio);
	else
		mcache_write(mls, bio);
	return DM_MAPIO_SUBMITTED;
}

static void
writeback_all_dirty(cacheset_t *ccs)
{
	mlstor_t	*mls = ccs->mls;
	cacheinfo_t	*ci;
	unsigned long	flags;
	bno_t	i;

	spin_lock_irqsave(&mls->lock, flags);

	for (i = 0, ci = ccs->cacheinfos; i < ccs->size; i++, ci++) {
		if (ci->state == VALID && ci->dirty) {
			while (ci->n_readers > 0) {
				WAIT_INPROG_EVENT(mls, flags, ci->n_readers == 0);
			}
			ccs->n_valids--;
			ci->state = INPROG;
			ccs->writeback(ccs, ci, i, &flags);
		}
	}

	spin_unlock_irqrestore(&mls->lock, flags);
}

static inline int
rc_get_dev(struct dm_target *ti, char *pth, struct dm_dev **dmd, char *mls_dname, sector_t tilen)
{
	int	rc;

	rc = dm_get_device(ti, pth, dm_table_get_mode(ti->table), dmd);
	if (!rc)
		strncpy(mls_dname, pth, DEV_PATHLEN);
	return rc;
}

static unsigned long
get_max_sectors_by_mem(void)
{
	struct sysinfo	si;

	si_meminfo(&si);
	return (si.totalram * PAGE_SIZE / SECTOR_SIZE);
}

static unsigned long
convert_sectors_to_blocks(mlstor_t *mls, unsigned long sectors)
{
	unsigned long	tmpsize;

	do_div(sectors, mls->block_size);
	tmpsize = sectors;
	do_div(tmpsize, mls->assoc);
	return tmpsize * mls->assoc;
}

static void
init_caches(cacheset_t *ccs)
{
	mlstor_t	*mls = ccs->mls;
	cacheinfo_t	*ci;
	unsigned long	i;

	for (i = 0, ci = ccs->cacheinfos; i < ccs->size; i++, ci++) {
		ci->bno = 0;
		ci->n_readers = 0;
		ci->state = INVALID;
		ci->dirty = false;
	}

	/* Initialize the point where LRU sweeps begin for each set */
	for (i = 0; i < (ccs->size >> mls->consecutive_shift); i++)
		ccs->bnos_next[i] = i * mls->assoc;
}

static bool
init_cacheset(mlstor_t *mls, cacheset_t *ccs, unsigned long size, unsigned int assoc)
{
	ccs->mls = mls;
	ccs->size = convert_sectors_to_blocks(mls, size);

	ccs->cacheinfos = vmalloc(ccs->size * sizeof(cacheinfo_t));
	if (ccs->cacheinfos == NULL)
		return false;

	ccs->bnos_next = vmalloc((ccs->size >> mls->consecutive_shift) * sizeof(bno_t));
	if (ccs->bnos_next == NULL)
		return false;

	init_caches(ccs);

	return true;
}

static bool
init_mlstor(mlstor_t *mls, unsigned long size_mcache, unsigned int assoc)
{
	unsigned int	consecutive_blocks;
	sector_t	size_dcache;
	sector_t	max_sectors_bymem;

	init_waitqueue_head(&mls->destroyq);
	atomic_set(&mls->nr_jobs, 0);

	mls->block_size = CACHE_BLOCK_SIZE;
	mls->assoc = assoc;

	init_waitqueue_head(&mls->inprogq);
	mls->block_size = CACHE_BLOCK_SIZE;
	mls->block_shift = ffs(mls->block_size) - 1;

	spin_lock_init(&mls->lock);

	consecutive_blocks = assoc;
	mls->consecutive_shift = ffs(consecutive_blocks) - 1;

	mls->reads = 0;
	mls->writes = 0;
	mls->cache_hits = 0;
	mls->replace = 0;
	mls->cached_blocks = 0;
	mls->cache_wr_replace = 0;

	size_dcache = to_sector(mls->dev_caching->bdev->bd_inode->i_size);
	max_sectors_bymem = get_max_sectors_by_mem();
	if (size_mcache == 0)
		size_mcache = size_dcache * 4;

	if (size_mcache > max_sectors_bymem)
		size_mcache = max_sectors_bymem;

	if (!init_cacheset(mls, &mls->mcacheset, size_mcache, assoc))
		return false;
	if (!init_cacheset(mls, &mls->dcacheset, size_dcache, assoc))
		return false;

	mls->mcacheset.writeback = writeback_mcb;
	mls->dcacheset.writeback = writeback_dcb;
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
free_mlstor(mlstor_t *mls)
{
	free_cacheset(&mls->mcacheset);
	free_cacheset(&mls->dcacheset);

	if (mls->stl)
		free_stolearn(mls->stl);
	if (mls->pcache)
		pcache_delete(mls->pcache);
	if (mls->io_client)
		dm_io_client_destroy(mls->io_client);

	if (mls->dev_backing)
		dm_put_device(mls->tgt, mls->dev_backing);
	if (mls->dev_caching)
		dm_put_device(mls->tgt, mls->dev_caching);

	kfree(mls);
}

/* Construct a cache mapping.
 *  arg[0]: path to source device
 *  arg[1]: path to cache device
 *  arg[2]: pcache size in MB
 *  arg[3]: cache associativity */
static int
mlstor_ctr(struct dm_target *tgt, unsigned int argc, char **argv)
{
	mlstor_t	*mls;
	cacheset_t	*dcs;
	unsigned long	size;
	unsigned int	assoc;
	int	err;

	if (argc < 2) {
		tgt->error = "mlstor-cache: at least 2 arguments are required";
		return -EINVAL;
	}

	mls = kzalloc(sizeof(*mls), GFP_KERNEL);
	if (mls == NULL) {
		tgt->error = "mlstor-cache: failed to allocate mlstor object";
		return -ENOMEM;
	}
	mls->tgt = tgt;

	if (rc_get_dev(tgt, argv[0], &mls->dev_backing, mls->devname_backing, tgt->len)) {
		tgt->error = "mlstor-cache: failed to lookup backing device";
		kfree(mls);
		return -EINVAL;
	}
	if (rc_get_dev(tgt, argv[1], &mls->dev_caching, mls->devname_caching, 0)) {
		tgt->error = "mlstor-cache: failed to lookup caching device";
		free_mlstor(mls);
		return -EINVAL;
	}

	if (argc >= 3) {
		if (kstrtoul(argv[2], 0, &size)) {
			tgt->error = "mlstor-cache: invalid size format";
			free_mlstor(mls);
			return -EINVAL;
		}
		size = to_sector(size * 1024 * 1024);
	}
	else
		size = 0;

	if (argc >= 4) {
		if (kstrtoint(argv[3], 10, &assoc)) {
			tgt->error = "mlstor-cache: invalid cache associativity format";
			free_mlstor(mls);
			return -EINVAL;
		}
		if (!assoc || (assoc & (assoc - 1)) || size < assoc) {
			tgt->error = "mlstor-cache: inconsistent cache associativity";
			free_mlstor(mls);
			return -EINVAL;
		}
	} else {
		assoc = DEFAULT_CACHE_ASSOC;
	}

	mls->io_client = dm_io_client_create();
	if (IS_ERR(mls->io_client)) {
		err = PTR_ERR(mls->io_client);

		tgt->error = "failed to create io client\n";
		free_mlstor(mls);
		return err;
	}

	mls->stl = create_stolearn(to_sector(mls->dev_backing->bdev->bd_inode->i_size));
	if (mls->stl == NULL) {
		tgt->error = "failed to initialize stolearn\n";
		free_mlstor(mls);
		return -EIO;
	}
	if (mls->pcache == NULL) {
		tgt->error = "failed to create pcache\n";
		free_mlstor(mls);
		return -ENOMEM;
	}
	mls->pcache = pcache_create();
	if (mls->pcache == NULL) {
		tgt->error = "failed to create pcache\n";
		free_mlstor(mls);
		return -ENOMEM;
	}

	if (!init_mlstor(mls, size, assoc)) {
		tgt->error = "failed to cacheset\n";
		free_mlstor(mls);
		return -ENOMEM;
	}

	dcs = &mls->dcacheset;

	DMINFO("allocate %lu-entry cache"
	       "(capacity:%luKB, associativity:%u, block size:%u sectors(%uKB))",
	       dcs->size, (unsigned long)((dcs->size * sizeof(cacheinfo_t)) >> 10),
	       mls->assoc, mls->block_size, mls->block_size >> (10 - SECTOR_SHIFT));

	err = dm_set_target_max_io_len(tgt, CACHE_BLOCK_SIZE);
	if (err) {
		tgt->error = "failed to set max io length\n";
		free_mlstor(mls);
		return err;
	}

	tgt->private = mls;

	return 0;
}

static void
mlstor_dtr(struct dm_target *ti)
{
	mlstor_t	*mls = (mlstor_t *)ti->private;
	cacheset_t	*dcs = &mls->dcacheset;

	writeback_all_dirty(&mls->mcacheset);
	writeback_all_dirty(dcs);
	wait_event(mls->destroyq, !atomic_read(&mls->nr_jobs));

	if (mls->reads + mls->writes > 0) {
		DMINFO("stats:\n\treads(%lu), writes(%lu)\n",
		       mls->reads, mls->writes);
		DMINFO("\tcache hits(%lu), replacement(%lu), write replacement(%lu)\n",
		       mls->cache_hits, mls->replace, mls->cache_wr_replace);
		DMINFO("conf:\n\tcapacity(%luM), associativity(%u), block size(%uK)\n"
		       "\ttotal blocks(%lu)\n",
		       (unsigned long)dcs->size * mls->block_size >> 11,
		       mls->assoc, mls->block_size >> (10 - SECTOR_SHIFT),
		       (unsigned long)dcs->size);
	}

	free_mlstor(mls);
}

static void
mlstor_status_info(mlstor_t *mls, status_type_t type, char *result, unsigned int maxlen)
{
	int	sz = 0;

	DMEMIT("stats:\n\treads(%lu), writes(%lu)\n", mls->reads, mls->writes);
	DMEMIT("\tcache hits(%lu), replacement(%lu), write replacement(%lu)\n"
		"\tdisk reads(%lu), disk writes(%lu,%lu)\n"
		"\tcache reads(%lu), cache writes(%lu)\n"
		"\tn_valids(%lu), reclaims(%lu)\n",
		mls->cache_hits, mls->replace, mls->cache_wr_replace,
	       mls->disk_reads, mls->disk_writes, mls->disk_writes1,
	       mls->cache_reads, mls->cache_writes,
	       mls->mcacheset.n_valids, mls->reclaims);
}

static void
mlstor_status_table(mlstor_t *mls, status_type_t type, char *result, unsigned int maxlen)
{
	int	sz = 0;
	cacheset_t	*ccs = &mls->mcacheset;

	DMEMIT("conf:\n\tMLStorage-cache dev (%s), disk dev (%s)"
	       "\tcapacity(%luM), associativity(%u), block size(%uK)\n"
	       "\ttotal blocks(%lu)\n",
	       mls->devname_caching, mls->devname_backing,
	       (unsigned long)ccs->size * mls->block_size >> 11, mls->assoc,
	       mls->block_size >> (10 - SECTOR_SHIFT),
	       (unsigned long)ccs->size);
}

static void
mlstor_status(struct dm_target *ti, status_type_t type, unsigned status_flags, char *result, unsigned int maxlen)
{
	mlstor_t	*mls = (mlstor_t *)ti->private;

	switch (type) {
	case STATUSTYPE_INFO:
		mlstor_status_info(mls, type, result, maxlen);
		break;
	case STATUSTYPE_TABLE:
		mlstor_status_table(mls, type, result, maxlen);
		break;
	}
}

static struct target_type	mlstor_target = {
	.name    = "mlstor-cache",
	.version = {1, 0, 0},
	.module  = THIS_MODULE,
	.ctr	 = mlstor_ctr,
	.dtr	 = mlstor_dtr,
	.map	 = mlstor_map,
	.status  = mlstor_status,
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

	ret = dm_register_target(&mlstor_target);
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
	dm_unregister_target(&mlstor_target);
	destroy_workqueue(wq_writeback);
	jobs_exit();
}

module_init(rc_init);
module_exit(rc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("oslab <oslab@oslab.ewha.ac.kr>");
MODULE_DESCRIPTION("MLStorage-Cache is a machine learning based caching target with NN model.");
MODULE_VERSION(VERSION_STR);
MODULE_INFO(Copyright, "Copyleft 2021 OSLAB, Ewha");
