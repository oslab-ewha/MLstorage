#ifndef _LIBSTOLEARN_H_
#define _LIBSTOLEARN_H_

#include <linux/types.h>

#define STL_READ	1
#define STL_WRITE	2

typedef unsigned short	stl_iotype_t;

typedef enum {
	STL_WORKLOAD_UNKNOWN = 0,
	STL_WORKLOAD_SEQ,
	STL_WORKLOAD_RANDOM,
	STL_WORKLOAD_LOOP,
	STL_WORKLOAD_JUMPSEQ,
} stl_workload_t;
	
void *libstl_init(unsigned long max_sectors);
void libstl_fini(void *h_libstl);
void libstl_pulse_access(void *h_libstl, unsigned long timestamp, pid_t pid, stl_iotype_t type, sector_t sector, unsigned long count);
void libstl_get_workload(void *h_libstl, pid_t pid, stl_workload_t *pwt_r, stl_workload_t *pwt_w);

#endif
