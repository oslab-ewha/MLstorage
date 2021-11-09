#include <linux/types.h>

#include "libstolearn.h"

void *
libstl_init(unsigned long sectors)
{
	return NULL;
}

void
libstl_fini(void *h_libstl)
{
}

void
libstl_pulse_access(void *h_libstl, unsigned long timestamp, pid_t pid, stl_iotype_t type, sector_t sector, unsigned long count)
{
}

void
libstl_get_workload(void *h_libstl, pid_t pid, stl_workload_t *pwt_r, stl_workload_t *pwt_w)
{
}
       
