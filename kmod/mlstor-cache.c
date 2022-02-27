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

#define INVALID_BNO	((bno_t)(-1))
#define IS_VALID_BNO(bno)	((bno) != INVALID_BNO)

typedef unsigned long	bno_t;

#define IS_FULL_BIO(mls, bio)	(to_sector((bio)->bi_iter.bi_size) == (mls)->block_size)

typedef enum {
	READ_BACKINGDEV = 1,
	READ_BACKINGDEV_WC,	/* read backing device and write cache */
	READ_CACHINGDEV_WB,
	WRITE_BACKINGDEV,
	WRITE_BACKINGDEV_WB,
	READ_CACHINGDEV,
	WRITE_CACHINGDEV
} job_type_t;

#define IS_WRITE_JOB_TYPE(job_type)	((job_type) == WRITE_BACKINGDEV || (job_type) == WRITE_CACHINGDEV || \
					 (job_type) == WRITE_BACKINGDEV_WB)

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
	cache_state_t	state:6;
	bool	dirty:1;
	bool	writeback:1;
} cacheinfo_t;
#pragma pack(pop)

typedef struct _cacheset {
	unsigned long	size;
	cacheinfo_t	*cacheinfos;
	/* next bno per set for validity test */
	bno_t	*bnos_next;
} cacheset_t;

/* mlstor */
typedef struct _mlstor {
	struct dm_target	*tgt;
	struct dm_dev		*dev_backing, *dev_caching;

	spinlock_t	lock;
	/* Wait queue for INPROG state completion */
	wait_queue_head_t	inprogq;

	cacheset_t	cacheset;

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
	bno_t	bno_db, bno_cb;
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
static struct workqueue_struct	*wq_dmio_job;

static dmio_job_t *new_dmio_job(mlstor_t *mls, job_type_t type, struct bio *bio, bno_t bno_db, bno_t bno_cb);
static void dmio_done(unsigned long err, void *context);

static void
req_dmio_job(dmio_job_t *job)
{
	mlstor_t	*mls = job->mls;
	struct dm_io_request	iorq;
	struct page_list	pagelist;

	iorq.bi_op = IS_WRITE_JOB_TYPE(job->type) ? REQ_OP_WRITE: REQ_OP_READ;
	iorq.bi_op_flags = 0;
	if (job->bio) {
		iorq.mem.type = DM_IO_BIO;
		iorq.mem.ptr.bio = job->bio;
	}
	else {
		pagelist.next = NULL;

		if (job->type == READ_CACHINGDEV_WB)
			pagelist.page = job->page = alloc_page(GFP_NOIO);
		else if (job->type == WRITE_BACKINGDEV_WB)
			pagelist.page = job->page;

		iorq.mem.type = DM_IO_PAGE_LIST;
		iorq.mem.offset = 0;
		iorq.mem.ptr.pl = &pagelist;
	}
	iorq.notify.fn = dmio_done;
	iorq.notify.context = job;
	iorq.client = mls->io_client;

	dm_io(&iorq, 1, &job->dm_iorgn, NULL);
}

static void
do_req_dmio_job_async(struct work_struct *work)
{
	dmio_job_t	*job = container_of(work, dmio_job_t, work);
	req_dmio_job(job);
}

static void
req_dmio_job_async(dmio_job_t *job)
{
	INIT_WORK(&job->work, do_req_dmio_job_async);
	queue_work(wq_dmio_job, &job->work);
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
update_cache_state(mlstor_t *mls, dmio_job_t *job, unsigned long err)
{
	cacheinfo_t	*ci;
	unsigned long	flags;

	spin_lock_irqsave(&mls->lock, flags);

	ci = mls->cacheset.cacheinfos + job->bno_cb;

	switch (job->type) {
	case READ_CACHINGDEV:
	case READ_CACHINGDEV_WB:
		ASSERT(ci->n_readers > 0);
		ci->n_readers--;
		break;
	default:
		break;
	}

	if (err == 0) {
		switch (job->type) {
		case WRITE_BACKINGDEV_WB:
			ci->dirty = false;
			ci->writeback = false;
			break;
		case WRITE_CACHINGDEV:
			ci->state = VALID;
			ci->dirty = true;
			break;
		default:
			break;
		}
	}
	else {
		switch (job->type) {
		case WRITE_CACHINGDEV:
			ci->state = INVALID;
			break;
		default:
			break;
		}
	}

	wake_up_all(&mls->inprogq);

	spin_unlock_irqrestore(&mls->lock, flags);
}

static void
dmio_done(unsigned long err, void *context)
{
	dmio_job_t	*job = (dmio_job_t *)context;
	mlstor_t	*mls = job->mls;
	struct bio	*bio;

	bio = job->bio;
	if (err) {
		DMERR("%s: job_type: %d, io error: %ld", __func__, job->type, err);
	}

	if (IS_VALID_BNO(job->bno_cb))
		update_cache_state(mls, job, err);

	if (err == 0) {
		if (job->type == READ_CACHINGDEV_WB) {
			job->type = WRITE_BACKINGDEV_WB;
			job->dm_iorgn.bdev = mls->dev_backing->bdev;
			job->dm_iorgn.sector = BNO_TO_SECTOR(mls, job->bno_db);
			req_dmio_job_async(job);
			return;
		}
		else if (job->type == READ_BACKINGDEV_WC) {
			job->type = WRITE_CACHINGDEV;
			job->dm_iorgn.bdev = mls->dev_caching->bdev;
			job->dm_iorgn.sector = BNO_TO_SECTOR(mls, job->bno_cb);
			req_dmio_job_async(job);
			return;
		}
	}

	if (bio) {
		if (err) {
			bio->bi_status = err;
			bio_io_error(bio);
		}
		else
			bio_endio(bio);
	}

	job_free(job);
}

static unsigned long
hash_block(mlstor_t *mls, bno_t bno)
{
	unsigned long	set_number;
	uint64_t	value;

	value = bno >> mls->consecutive_shift;
	set_number = do_div(value, (mls->cacheset.size >> mls->consecutive_shift));
	return set_number;
}

static bool
find_valid_cb(mlstor_t *mls, bool for_write, bno_t bno, bno_t bno_start, bno_t *pbno, unsigned long *pflags)
{
	cacheinfo_t	*ci;
	bno_t	bno_end = bno_start + mls->assoc;
	bno_t	i;

again:
	for (i = bno_start, ci = mls->cacheset.cacheinfos + bno_start; i < bno_end; i++, ci++) {
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
find_invalid_cb(mlstor_t *mls, bno_t bno_start, bno_t *pbno)
{
	bno_t	bno_end = bno_start + mls->assoc;
	bno_t	i;

	/* Find INVALID slot that we can reuse */
	for (i = bno_start; i < bno_end; i++) {
		if (mls->cacheset.cacheinfos[i].state == INVALID) {
			*pbno = i;
			return true;
		}
	}
	return false;
}

static bool
has_nonprog_cb(mlstor_t *mls, bno_t bno_start)
{
	bno_t	bno_end = bno_start + mls->assoc;
	cacheinfo_t	*ci;
	bno_t	i;

	/* Find INVALID slot that we can reuse */
	for (i = bno_start, ci = mls->cacheset.cacheinfos + i; i < bno_end; i++, ci++) {
		if (ci->state != INPROG && ci->n_readers == 0) {
			return true;
		}
	}
	return false;
}

#define NEXT_BNO(bno, bno_start, bno_end) \
	((bno) + 1 == (bno_end)) ? (bno_start): ((bno) + 1)

static void
writeback_cb(mlstor_t *mls, cacheinfo_t *ci, bno_t bno_cb, unsigned long *pflags)
{
	dmio_job_t	*job;

	if (ci->writeback)
		return;

	spin_unlock_irqrestore(&mls->lock, *pflags);
	job = new_dmio_job(mls, READ_CACHINGDEV_WB, NULL, ci->bno, bno_cb);
	spin_lock_irqsave(&mls->lock, *pflags);
	if (unlikely(!job))
		return;
	ci->n_readers++;
	ci->writeback = true;
	mls->disk_writes1++;
	req_dmio_job_async(job);
}

static bool
find_reclaim_cb(mlstor_t *mls, bno_t bno_start, bno_t *pbno_reclaimed, unsigned long *pflags)
{
	cacheset_t	*cs = &mls->cacheset;
	bno_t	bno_end = bno_start + mls->assoc;
	int	set = bno_start / mls->assoc;
	int	slots_searched = 0;
	bno_t	bno_next;

	/* Find the "oldest" VALID slot to recycle. For each set, we keep
	 * track of the next "lru" slot to pick off. Each time we pick off
	 * a VALID entry to recycle we advance this pointer. So  we sweep
	 * through the set looking for next blocks to recycle. This
	 * approximates to FIFO (modulo for blocks written through). */
	bno_next = cs->bnos_next[set];
	while (slots_searched < mls->assoc) {
		cacheinfo_t	*ci = cs->cacheinfos + bno_next;

		ASSERT(bno_next >= bno_start && bno_next < bno_end);

		if (ci->state == VALID && ci->n_readers == 0) {
			if (ci->dirty)
				writeback_cb(mls, ci, bno_next, pflags);
			else {
				*pbno_reclaimed = bno_next;
				cs->bnos_next[set] = NEXT_BNO(bno_next, bno_start, bno_end);
				return true;
			}
		}
		slots_searched++;
		bno_next = NEXT_BNO(bno_next, bno_start, bno_end);
	}
	return false;
}

static bool
cache_lookup(mlstor_t *mls, bno_t bno_db, bno_t *pbno_cb, bool for_write, unsigned long *pflags)
{
	unsigned long	set_number = hash_block(mls, bno_db);
	bno_t	bno_invalid;
	bno_t	bno_start;

	bno_start = mls->assoc * set_number;

again:
	if (find_valid_cb(mls, for_write, bno_db, bno_start, pbno_cb, pflags))
		return true;

	if (find_invalid_cb(mls, bno_start, &bno_invalid))
		*pbno_cb = bno_invalid;
	else {
		bno_t	bno_reclaimed;

		/* We didn't find an invalid entry, search for oldest valid entry */
		if (!find_reclaim_cb(mls, bno_start, &bno_reclaimed, pflags)) {
			WAIT_INPROG_EVENT(mls, *pflags, has_nonprog_cb(mls, bno_start));
			goto again;
		}
		mls->reclaims++;
		*pbno_cb = bno_reclaimed;
	}

	return false;
}

static dmio_job_t *
new_dmio_job(mlstor_t *mls, job_type_t type, struct bio *bio, bno_t bno_db, bno_t bno_cb)
{
	dmio_job_t	*job;

	job = mempool_alloc(job_pool, GFP_NOIO);
	if (job == NULL) {
		DMERR("failed to allocate job\n");
		return NULL;
	}

	if (type == READ_CACHINGDEV || type == WRITE_CACHINGDEV || type == READ_CACHINGDEV_WB) {
		job->dm_iorgn.bdev = mls->dev_caching->bdev;
		job->dm_iorgn.sector = BNO_TO_SECTOR(mls, bno_cb);
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
	job->bno_cb = bno_cb;
	job->error = 0;
	job->page = NULL;

	atomic_inc(&mls->nr_jobs);

	return job;
}

static void
read_backingdev(mlstor_t *mls, struct bio *bio)
{
	dmio_job_t	*job;
	bno_t	bno_db = SECTOR_TO_BNO(mls, bio->bi_iter.bi_sector);

	job = new_dmio_job(mls, READ_BACKINGDEV, bio, bno_db, INVALID_BNO);
	if (unlikely(!job)) {
		bio->bi_status = -EIO;
		bio_io_error(bio);
		return;
	}
	mls->disk_reads++;
	req_dmio_job(job);
}

static bool
cache_read_fault(mlstor_t *mls, struct bio *bio, bno_t bno_cb)
{
	dmio_job_t	*job;
	bno_t	bno_db = SECTOR_TO_BNO(mls, bio->bi_iter.bi_sector);

	job = new_dmio_job(mls, READ_BACKINGDEV_WC, bio, bno_db, bno_cb);
	if (unlikely(!job))
		return false;

	mls->disk_reads++;
	req_dmio_job(job);

	return true;
}

static void
cache_read(mlstor_t *mls, struct bio *bio)
{
	cacheset_t	*cs = &mls->cacheset;
	cacheinfo_t	*ci;
	bno_t	bno_db = SECTOR_TO_BNO(mls, bio->bi_iter.bi_sector);
	bno_t	bno_cb;
	unsigned long	flags;

	spin_lock_irqsave(&mls->lock, flags);

	if (cache_lookup(mls, bno_db, &bno_cb, false, &flags)) {
		dmio_job_t	*job;
		
		cs->cacheinfos[bno_cb].n_readers++;
		mls->cache_hits++;
		spin_unlock_irqrestore(&mls->lock, flags);

		job = new_dmio_job(mls, READ_CACHINGDEV, bio, bno_db, bno_cb);
		req_dmio_job(job);
		return;
	}

	if (IS_FULL_BIO(mls, bio)) {
		ci = cs->cacheinfos + bno_cb;

		if (ci->state == VALID) {
			/* This means that cache read uses a victim cache */
			mls->cached_blocks--;
			mls->replace++;
		}

		ci->state = INPROG;
		ci->bno = SECTOR_TO_BNO(mls, bio->bi_iter.bi_sector);

		spin_unlock_irqrestore(&mls->lock, flags);

		if (!cache_read_fault(mls, bio, bno_cb)) {
			spin_lock_irqsave(&mls->lock, flags);
			ci->state = INVALID;
			wake_up_all(&mls->inprogq);
			spin_unlock_irqrestore(&mls->lock, flags);

			bio->bi_status = -EIO;
			bio_io_error(bio);
		}
	}
	else {
		spin_unlock_irqrestore(&mls->lock, flags);
		read_backingdev(mls, bio);
	}
}

static void
cache_write(mlstor_t *mls, struct bio *bio)
{
	cacheset_t	*cs = &mls->cacheset;
	dmio_job_t	*job;
	cacheinfo_t	*ci;
	bno_t	bno_db = SECTOR_TO_BNO(mls, bio->bi_iter.bi_sector);
	bno_t	bno_cb;
	unsigned long	flags;

	spin_lock_irqsave(&mls->lock, flags);

	cache_lookup(mls, bno_db, &bno_cb, true, &flags);

	ci = cs->cacheinfos + bno_cb;

	if (ci->state == VALID) {
		mls->cached_blocks--;
		mls->cache_wr_replace++;
	}
	else {
		if (!IS_FULL_BIO(mls, bio)) {
			spin_unlock_irqrestore(&mls->lock, flags);
			job = new_dmio_job(mls, WRITE_CACHINGDEV, bio, ci->bno, bno_cb);
			req_dmio_job(job);
			return;////TODO
		}
	}
	ci->state = INPROG;
	ci->bno = SECTOR_TO_BNO(mls, bio->bi_iter.bi_sector);

	spin_unlock_irqrestore(&mls->lock, flags);

	job = new_dmio_job(mls, WRITE_CACHINGDEV, bio, ci->bno, bno_cb);
	req_dmio_job(job);
}

#define bio_barrier(bio)		((bio)->bi_opf & REQ_PREFLUSH)

static int
mlstor_map(struct dm_target *ti, struct bio *bio)
{
	mlstor_t	*mls = (mlstor_t *)ti->private;

	if (bio_barrier(bio))
		return -EOPNOTSUPP;

	ASSERT(to_sector(bio->bi_iter.bi_size) <= mls->block_size);
	if (bio_data_dir(bio) == READ)
		mls->reads++;
	else
		mls->writes++;

	if (bio_data_dir(bio) == READ)
		cache_read(mls, bio);
	else
		cache_write(mls, bio);
	return DM_MAPIO_SUBMITTED;
}

static void
writeback_all_dirty(mlstor_t *mls)
{
	cacheset_t	*cs = &mls->cacheset;
	cacheinfo_t	*ci;
	unsigned long	flags;
	bno_t	i;

	spin_lock_irqsave(&mls->lock, flags);

	for (i = 0, ci = cs->cacheinfos; i < cs->size; i++, ci++) {
		while (ci->state == VALID && ci->dirty) {
			if (ci->n_readers > 0 || ci->writeback) {
				WAIT_INPROG_EVENT(mls, flags, ci->n_readers == 0 && !ci->writeback);
				continue;
			}
			writeback_cb(mls, ci, i, &flags);
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
convert_sectors_to_blocks(mlstor_t *mls, unsigned long sectors)
{
	unsigned long	tmpsize;

	do_div(sectors, mls->block_size);
	tmpsize = sectors;
	do_div(tmpsize, mls->assoc);
	return tmpsize * mls->assoc;
}

static void
init_caches(mlstor_t *mls)
{
	cacheset_t	*cs = &mls->cacheset;
	cacheinfo_t	*ci;
	unsigned long	i;

	for (i = 0, ci = cs->cacheinfos; i < cs->size; i++, ci++) {
		ci->bno = 0;
		ci->n_readers = 0;
		ci->state = INVALID;
		ci->dirty = false;
		ci->writeback = false;
	}

	/* Initialize the point where LRU sweeps begin for each set */
	for (i = 0; i < (cs->size >> mls->consecutive_shift); i++)
		cs->bnos_next[i] = i * mls->assoc;
}

static bool
init_cacheset(mlstor_t *mls, unsigned long size, unsigned int assoc)
{
	cacheset_t	*cs = &mls->cacheset;

	cs->size = convert_sectors_to_blocks(mls, size);

	cs->cacheinfos = vmalloc(cs->size * sizeof(cacheinfo_t));
	if (cs->cacheinfos == NULL)
		return false;

	cs->bnos_next = vmalloc((cs->size >> mls->consecutive_shift) * sizeof(bno_t));
	if (cs->bnos_next == NULL)
		return false;

	init_caches(mls);

	return true;
}

static bool
init_mlstor(mlstor_t *mls, unsigned long size_cache, unsigned int assoc)
{
	unsigned int	consecutive_blocks;
	sector_t	size_dcache;

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

	if (size_cache == 0)
		size_dcache = to_sector(mls->dev_caching->bdev->bd_inode->i_size);
	else
		size_dcache = size_cache;

	if (!init_cacheset(mls, size_dcache, assoc))
		return false;

	return true;
}

static void
free_cacheset(cacheset_t *cs)
{
	if (cs->cacheinfos)
		vfree(cs->cacheinfos);
	if (cs->bnos_next)
		vfree(cs->bnos_next);
}

static void
free_mlstor(mlstor_t *mls)
{
	free_cacheset(&mls->cacheset);

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
 *  arg[2]: cache size in MB
 *  arg[3]: cache associativity */
static int
mlstor_ctr(struct dm_target *tgt, unsigned int argc, char **argv)
{
	mlstor_t	*mls;
	cacheset_t	*cs;
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

	if (!init_mlstor(mls, size, assoc)) {
		tgt->error = "failed to cacheset\n";
		free_mlstor(mls);
		return -ENOMEM;
	}

	cs = &mls->cacheset;

	DMINFO("allocate %lu-entry cache"
	       "(capacity:%luKB, associativity:%u, block size:%u sectors(%uKB))",
	       cs->size, (unsigned long)((cs->size * sizeof(cacheinfo_t)) >> 10),
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
	cacheset_t	*cs = &mls->cacheset;

	writeback_all_dirty(mls);
	wait_event(mls->destroyq, !atomic_read(&mls->nr_jobs));

	if (mls->reads + mls->writes > 0) {
		DMINFO("stats:\n\treads(%lu), writes(%lu)\n",
		       mls->reads, mls->writes);
		DMINFO("\tcache hits(%lu), replacement(%lu), write replacement(%lu)\n",
		       mls->cache_hits, mls->replace, mls->cache_wr_replace);
		DMINFO("conf:\n\tcapacity(%luM), associativity(%u), block size(%uK)\n"
		       "\ttotal blocks(%lu)\n",
		       (unsigned long)cs->size * mls->block_size >> 11,
		       mls->assoc, mls->block_size >> (10 - SECTOR_SHIFT),
		       (unsigned long)cs->size);
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
		"\treclaims(%lu)\n",
		mls->cache_hits, mls->replace, mls->cache_wr_replace,
	       mls->disk_reads, mls->disk_writes, mls->disk_writes1,
	       mls->cache_reads, mls->cache_writes,
	       mls->reclaims);
}

static void
mlstor_status_table(mlstor_t *mls, status_type_t type, char *result, unsigned int maxlen)
{
	int	sz = 0;

	DMEMIT("conf:\n\tMLStorage-cache dev (%s), disk dev (%s)"
	       "\tassociativity(%u), block size(%uK)\n",
	       mls->devname_caching, mls->devname_backing,
	       mls->assoc, mls->block_size >> (10 - SECTOR_SHIFT));
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

	wq_dmio_job = create_singlethread_workqueue("async_dmio");
	if (wq_dmio_job == NULL) {
		jobs_exit();
		return -ENOMEM;
	}

	ret = dm_register_target(&mlstor_target);
	if (ret < 0) {
		jobs_exit();
		destroy_workqueue(wq_dmio_job);
		return ret;
	}
	return 0;
}

void
rc_exit(void)
{
	dm_unregister_target(&mlstor_target);
	destroy_workqueue(wq_dmio_job);
	jobs_exit();
}

module_init(rc_init);
module_exit(rc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("oslab <oslab@oslab.ewha.ac.kr>");
MODULE_DESCRIPTION("MLStorage-Cache is a machine learning based caching target with NN model.");
MODULE_VERSION(VERSION_STR);
MODULE_INFO(Copyright, "Copyleft 2021 OSLAB, Ewha");
