#ifndef _MLSTOR_CACHE_H_
#define _MLSTOR_CACHE_H_

#include <linux/spinlock.h>
#include <linux/wait.h>

#include "mlstor-type.h"

#define INVALID_BNO	((bno_t)(-1))
#define IS_VALID_BNO(bno)	((bno) != INVALID_BNO)

typedef unsigned long	bno_t;

#define SECTOR_TO_BNO(mls, sector)	((sector) >> (mls)->block_shift)
#define BNO_TO_SECTOR(mls, bno)		((bno) << (mls)->block_shift)

/* States of a cache block */
typedef enum {
	INVALID = 0,
	VALID,
	INPROG	/* IO (cache fill) is in progress */
} cache_state_t;

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

#define DEV_PATHLEN	128

/* mlstor */
typedef struct _mlstor {
	struct dm_target	*tgt;
	struct dm_dev		*dev_backing, *dev_caching;

	spinlock_t	lock;
	/* Wait queue for INPROG state completion */
	wait_queue_head_t	inprogq;

	cacheset_t	cacheset;

	struct dm_io_client	*io_client;

	unsigned int	assoc;
	unsigned int	block_size;
	unsigned int	block_shift;
	unsigned int	consecutive_shift;

	atomic_t		n_active_jobs;	/* # of active dmio jobs */
	wait_queue_head_t	job_idleq;	/* wait queue for I/O completion */

	/* Stats */
	unsigned long	reads, writes;
	unsigned long	cache_hits;
	unsigned long	replaces_rd, replaces_wr;
	unsigned long	cached_blocks;
	unsigned long	cache_reads, cache_writes;
	unsigned long	writebacks;
	unsigned long	disk_reads, disk_writes;

	char	devname_backing[DEV_PATHLEN];
	char	devname_caching[DEV_PATHLEN];
} mlstor_t;

void update_cache_state(mlstor_t *mls, job_type_t job_type, bno_t bno_cb, unsigned long err);

bool mlstor_cache_init(void);
void mlstor_cache_fini(void);

#endif
