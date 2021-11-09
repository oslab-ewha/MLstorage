#ifndef _STOLEARN_H_
#define _STOLEARN_H_

#include <linux/bio.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/mutex.h>

#include "libstolearn.h"

typedef enum {
	REPOL_LRU,
	REPOL_MRU,
	REPOL_RANDOM
} replace_pol_t;

#define STL_WORKLOAD_MAX	(STL_WORKLOAD_JUMPSEQ + 1)

typedef struct {
	void	*h_libstl;
	struct mutex	lock;
	unsigned long	n_pids;
	unsigned long	n_e_read, n_e_write, n_e_read_1, n_e_write_1;
	unsigned long	n_sectors;
	unsigned weights_r[STL_WORKLOAD_MAX];
	unsigned weights_w[STL_WORKLOAD_MAX];
	struct task_struct	*analyzer;
	DECLARE_HASHTABLE(hash_workload, 16);
} stolearn_t;

void stolearn_add_bio(stolearn_t *stl, struct bio *bio);
bool stolearn_need_throttle_read(stolearn_t *stl);
bool stolearn_need_throttle_write(stolearn_t *stl);
replace_pol_t stolearn_get_replace_policy(stolearn_t *stl);
bool stolearn_need_writeback(stolearn_t *stl);

stolearn_t *create_stolearn(sector_t n_sectors);
void free_stolearn(stolearn_t *stl);

void init_stolearn(void);
void fini_stolearn(void);

#endif
