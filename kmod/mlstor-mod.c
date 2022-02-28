#include "mlstor-cache.h"
#include "dmio-job.h"

#include <linux/module.h>

int __init
rc_init(void)
{
	if (!jobs_init())
		return -ENOMEM;

	if (!mlstor_cache_init()) {
		jobs_exit();
		return -ENOMEM;
	}

	return 0;
}

void
rc_exit(void)
{
	mlstor_cache_fini();
	jobs_exit();
}

module_init(rc_init);
module_exit(rc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("oslab <oslab@oslab.ewha.ac.kr>");
MODULE_DESCRIPTION("MLStorage-Cache is a machine learning based caching target with NN model.");
MODULE_VERSION("1.0.0");
MODULE_INFO(Copyright, "Copyleft 2021 OSLAB, Ewha");
