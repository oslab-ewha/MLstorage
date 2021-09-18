#ifndef _PCACHE_H_
#define _PCACHE_H_

#include <linux/version.h>
#include <linux/radix-tree.h>

typedef struct pcache_t {
	spinlock_t	lock;
	struct radix_tree_root tree_pages;
} pcache_t;

pcache_t *pcache_create(void);
void pcache_delete(pcache_t *pcache);
int pcache_submit(pcache_t *pcache, bool is_write, sector_t sector, struct bio *bio);
struct page *pcache_get_page(pcache_t *pcache, sector_t sector);

#endif
