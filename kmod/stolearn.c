#include <linux/slab.h>
#include <linux/kthread.h>

#include "libstolearn.h"
#include "stolearn.h"

#define N_THROTTLE_START	10
#define WEIGHT_DECAY_NUMER	91
#define WEIGHT_DECAY_DENOM	100

#define DECAY_WEIGHT(w)	do { (w) *= WEIGHT_DECAY_NUMER; (w) /= WEIGHT_DECAY_DENOM; } while (0)

static struct kmem_cache	*wkinfo_cache __read_mostly;

typedef struct {
	pid_t	pid;
	stl_workload_t	wl_r, wl_w;
	unsigned long	jiffies_last;
	struct hlist_node	list;
} wkinfo_t;

static int
policy_analyzer(void *ctx)
{
	stolearn_t	*stl = (stolearn_t *)ctx;

	mutex_lock(&stl->lock);

	while (!kthread_should_stop()) {
		wkinfo_t	*wkinfo;
		struct hlist_node	*tmp;
		stl_workload_t	wt;
		int	bkt;

		hash_for_each_safe (stl->hash_workload, bkt, tmp, wkinfo, list) {
			libstl_get_workload(stl->h_libstl, wkinfo->pid, &wkinfo->wl_r, &wkinfo->wl_w);
			if (wkinfo->jiffies_last != 0 && (jiffies - wkinfo->jiffies_last) > 3 * HZ) {
				stl->weights_r[wkinfo->wl_r]++;
				stl->weights_r[wkinfo->wl_w]++;
			}
			else {
				hash_del(&wkinfo->list);
				kmem_cache_free(wkinfo_cache, wkinfo);
				stl->n_pids--;
			}
		}

		mutex_unlock(&stl->lock);
		schedule_timeout_idle(10);
		mutex_lock(&stl->lock);

		for (wt = STL_WORKLOAD_UNKNOWN; wt < STL_WORKLOAD_MAX; wt++) {
			DECAY_WEIGHT(stl->weights_r[wt]);
			DECAY_WEIGHT(stl->weights_w[wt]);
		}
		DECAY_WEIGHT(stl->n_sectors);
	}

	mutex_unlock(&stl->lock);
	return 0;
}

static wkinfo_t *
try_to_add_pid(stolearn_t *stl, pid_t pid)
{
	wkinfo_t	*wkinfo;

	hash_for_each_possible (stl->hash_workload, wkinfo, list, pid) {
		if (wkinfo->pid == pid)
			return wkinfo;
	}

	wkinfo = kmem_cache_alloc(wkinfo_cache, GFP_KERNEL);
	wkinfo->pid = pid;
	wkinfo->wl_r = STL_WORKLOAD_UNKNOWN;
	wkinfo->wl_w = STL_WORKLOAD_UNKNOWN;
	wkinfo->jiffies_last = jiffies;
	INIT_HLIST_NODE(&wkinfo->list);
	hash_add(stl->hash_workload, &wkinfo->list, pid);
	stl->n_pids++;

	return wkinfo;
}

void
stolearn_add_bio(stolearn_t *stl, struct bio *bio)
{
	stl_iotype_t	type;
	sector_t	sector, n_sectors;
	wkinfo_t	*wkinfo;

	if (bio == NULL)
		return;

	type = (bio_data_dir(bio) == READ) ? STL_READ: STL_WRITE;

	mutex_lock(&stl->lock);

	wkinfo = try_to_add_pid(stl, current->pid);
	sector = bio->bi_iter.bi_sector;
	n_sectors = bio_sectors(bio);
	libstl_pulse_access(stl->h_libstl, jiffies, current->pid, type, sector, n_sectors);

	wkinfo->jiffies_last = jiffies;
	stl->n_sectors += n_sectors;
	if (type == STL_READ) {
		stl->n_e_read++;
		if (n_sectors == 1)
			stl->n_e_read_1++;
	}
	else {
		stl->n_e_write++;
		if (n_sectors == 1)
			stl->n_e_write_1++;
	}

	mutex_unlock(&stl->lock);
}

bool
stolearn_need_throttle_read(stolearn_t *stl)
{
	if (stl->n_pids > N_THROTTLE_START &&
	    stl->weights_r[STL_WORKLOAD_SEQ] > (stl->weights_r[STL_WORKLOAD_UNKNOWN] + stl->weights_r[STL_WORKLOAD_RANDOM]) &&
	    stl->n_e_read > stl->n_e_write && stl->n_e_read_1 < stl->n_e_write_1)
		return true;
	return false;
}

bool
stolearn_need_throttle_write(stolearn_t *stl)
{
	if (stl->n_pids > N_THROTTLE_START &&
	    (stl->weights_w[STL_WORKLOAD_LOOP] > stl->weights_w[STL_WORKLOAD_SEQ] / 2 ||
	     stl->weights_w[STL_WORKLOAD_SEQ] < stl->weights_w[STL_WORKLOAD_RANDOM]) &&
	    stl->n_e_read < stl->n_e_write && stl->n_e_read_1 < stl->n_e_write_1)
		return true;
	return false;
}

replace_pol_t
stolearn_get_replace_policy(stolearn_t *stl)
{
	stl_iotype_t	t, t_max = 0;
	unsigned long	max_wt = 0;

	for (t = STL_WORKLOAD_UNKNOWN; t < STL_WORKLOAD_MAX; t++) {
		if (max_wt < stl->weights_r[t]) {
			t_max = t;
			max_wt = stl->weights_r[t];
		}
		if (max_wt < stl->weights_w[t]) {
			t_max = t;
			max_wt = stl->weights_w[t];
		}
	}
	switch (t_max) {
	case STL_WORKLOAD_RANDOM:
		return REPOL_LRU;
	case STL_WORKLOAD_LOOP:
		return REPOL_MRU;
	default:
		break;
	}
	return REPOL_RANDOM;
}

bool
stolearn_need_writeback(stolearn_t *stl)
{
	if (stl->weights_w[STL_WORKLOAD_JUMPSEQ] < stl->weights_w[STL_WORKLOAD_SEQ] * 2)
		return true;
	if (stl->n_sectors > stl->n_e_read_1 + stl->n_e_write_1)
		return true;
	return false;
}

stolearn_t *
create_stolearn(sector_t sectors)
{
	stolearn_t	*stl;

	stl = kzalloc(sizeof(stolearn_t), GFP_KERNEL);
	if (stl == NULL) {
		printk("out of memory\n");
		return NULL;
	}
	stl->h_libstl = libstl_init(sectors);
	mutex_init(&stl->lock);
	hash_init(stl->hash_workload);
	stl->analyzer = kthread_run(policy_analyzer, stl, "stl_pol_analyzer");
	return stl;
}

void
free_stolearn(stolearn_t *stl)
{
	if (stl) {
		libstl_fini(stl->h_libstl);
		kthread_stop(stl->analyzer);
		kfree(stl);
	}
}

void
init_stolearn(void)
{
	wkinfo_cache = kmem_cache_create("wkinfo", sizeof(wkinfo_t), 0, SLAB_HWCACHE_ALIGN, NULL);
}

void
fini_stolearn(void)
{
	kmem_cache_destroy(wkinfo_cache);
}
