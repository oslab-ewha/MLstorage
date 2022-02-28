#ifndef _DMIO_JOB_H_
#define _DMIO_JOB_H_

#include <linux/dm-io.h>
#include <linux/workqueue.h>

#include "mlstor-type.h"

struct _mlstor;

/* DM I/O job */
typedef struct _dmio_job {
	job_type_t	type;
	struct _mlstor	*mls;
	struct page	*page;
	struct bio	*bio;	/* original bio */
	struct dm_io_region	dm_iorgn;
	bno_t	bno_db, bno_cb;
	int	error;
	struct work_struct	work;
} dmio_job_t;

dmio_job_t *new_dmio_job(struct _mlstor *mls, job_type_t type, struct bio *bio, bno_t bno_db, bno_t bno_cb);

void req_dmio_job(dmio_job_t *job);
void req_dmio_job_async(dmio_job_t *job);

bool jobs_init(void);
void jobs_exit(void);

#endif
