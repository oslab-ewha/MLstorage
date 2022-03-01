#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/dm-io.h>
#include <linux/device-mapper.h>

#include "mlstor-cache.h"
#include "dmio-job.h"

#define DM_MSG_PREFIX	"dmio-job"

#define WT_MIN_JOBS	1024

#define IS_WRITE_JOB_TYPE(job_type)	((job_type) == WRITE_BACKINGDEV || (job_type) == WRITE_CACHINGDEV || \
					 (job_type) == WRITE_BACKINGDEV_WB)

static struct kmem_cache	*job_cache;
static mempool_t		*job_pool;

/* 5.x kernel seem to halt if a map thread exeucutes directly writeback */
static struct workqueue_struct	*wq_dmio_job;

static void
free_dmio_job(dmio_job_t *job)
{
	mlstor_t	*mls = job->mls;

	if (job->page)
		__free_page(job->page);
	mempool_free(job, job_pool);
	if (atomic_dec_and_test(&mls->n_active_jobs))
		wake_up(&mls->job_idleq);
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
		update_cache_state(mls, job->type, job->bno_cb, err);

	if (err == 0) {
		if (job->type == READ_CACHINGDEV_WB) {
			mls->disk_writes++;	/* TODO: locking ? */
			job->type = WRITE_BACKINGDEV_WB;
			job->dm_iorgn.bdev = mls->dev_backing->bdev;
			job->dm_iorgn.sector = BNO_TO_SECTOR(mls, job->bno_db);
			req_dmio_job_async(job);
			return;
		}
		else if (job->type == READ_BACKINGDEV && IS_VALID_BNO(job->bno_cb)) {
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

	free_dmio_job(job);
}

void
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

void
req_dmio_job_async(dmio_job_t *job)
{
	INIT_WORK(&job->work, do_req_dmio_job_async);
	queue_work(wq_dmio_job, &job->work);
}

dmio_job_t *
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

	atomic_inc(&mls->n_active_jobs);

	return job;
}

void
jobs_wait_idle(mlstor_t *mls)
{
	wait_event(mls->job_idleq, !atomic_read(&mls->n_active_jobs));
}

bool
jobs_init(void)
{
	job_cache = kmem_cache_create("dmio-jobs", sizeof(dmio_job_t), __alignof__(dmio_job_t), 0, NULL);
	if (job_cache == NULL)
		return false;

	job_pool = mempool_create(WT_MIN_JOBS, mempool_alloc_slab, mempool_free_slab, job_cache);
	if (job_pool == NULL) {
		kmem_cache_destroy(job_cache);
		return false;
	}

	wq_dmio_job = create_singlethread_workqueue("async_dmio");
	if (wq_dmio_job == NULL) {
		jobs_exit();
		return false;
	}

	return true;
}

void
jobs_exit(void)
{
	if (wq_dmio_job)
		destroy_workqueue(wq_dmio_job);

	mempool_destroy(job_pool);
	kmem_cache_destroy(job_cache);
}
