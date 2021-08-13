#include <linux/module.h>
#include <linux/slab.h>
#include <linux/bio.h>
#include <linux/errno.h>

#include "pcache.h"

#define FREE_BATCH		16
#define SECTOR_SHIFT	9
#define PAGE_SECTORS_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define PAGE_SECTORS		BIT(PAGE_SECTORS_SHIFT)

static struct page *
pcache_lookup_page(pcache_t *pcache, sector_t sector)
{
	pgoff_t	idx;
	struct page	*page;

	rcu_read_lock();
	idx = sector >> PAGE_SECTORS_SHIFT; /* sector to page index */
	page = radix_tree_lookup(&pcache->tree_pages, idx);
	rcu_read_unlock();

	BUG_ON(page && page->index != idx);

	return page;
}

static struct page *
pcache_insert_page(pcache_t *pcache, sector_t sector)
{
	pgoff_t	idx;
	gfp_t	gfp_flags;
	struct page	*page;

	page = pcache_lookup_page(pcache, sector);
	if (page)
		return page;

	/*
	 * Must use NOIO because we don't want to recurse back into the
	 * block or filesystem layers from page reclaim.
	 *
	 * Cannot support XIP and highmem, because our ->direct_access
	 * routine for XIP must return memory that is always addressable.
	 * If XIP was reworked to use pfns and kmap throughout, this
	 * restriction might be able to be lifted.
	 */
	gfp_flags = GFP_NOIO | __GFP_ZERO;
#ifndef CONFIG_BLK_DEV_XIP
	gfp_flags |= __GFP_HIGHMEM;
#endif
	page = alloc_page(gfp_flags);
	if (!page)
		return NULL;

	if (radix_tree_preload(GFP_NOIO)) {
		__free_page(page);
		return NULL;
	}

	spin_lock(&pcache->lock);
	idx = sector >> PAGE_SECTORS_SHIFT;
	if (radix_tree_insert(&pcache->tree_pages, idx, page)) {
		__free_page(page);
		page = radix_tree_lookup(&pcache->tree_pages, idx);
		BUG_ON(!page);
		BUG_ON(page->index != idx);
	} else {
		page->index = idx;
	}
	spin_unlock(&pcache->lock);

	radix_tree_preload_end();

	return page;
}

static void
pcache_zero_page(pcache_t *pcache, sector_t sector)
{
	struct page	*page;

	page = pcache_lookup_page(pcache, sector);
	if (page)
		clear_highpage(page);
}

static void
discard_from_pcache(pcache_t *pcache, sector_t sector, size_t n)
{
	while (n >= PAGE_SIZE) {
		pcache_zero_page(pcache, sector);
		sector += PAGE_SIZE >> SECTOR_SHIFT;
		n -= PAGE_SIZE;
	}
}

static int
copy_to_pcache_setup(pcache_t *pcache, sector_t sector, size_t n)
{
	unsigned int	offset = (sector & (PAGE_SECTORS - 1)) << SECTOR_SHIFT;
	size_t	copy;

	copy = min_t(size_t, n, PAGE_SIZE - offset);
	if (!pcache_insert_page(pcache, sector))
		return -ENOSPC;
	if (copy < n) {
		sector += copy >> SECTOR_SHIFT;
		if (!pcache_insert_page(pcache, sector))
			return -ENOSPC;
	}
	return 0;
}

static void
copy_to_pcache(pcache_t *pcache, const void *src, sector_t sector, size_t n)
{
	void	*dst;
	struct page	*page;
	unsigned int	offset = (sector & (PAGE_SECTORS - 1)) << SECTOR_SHIFT;
	size_t	copy;

	copy = min_t(size_t, n, PAGE_SIZE - offset);
	page = pcache_lookup_page(pcache, sector);
	BUG_ON(!page);

	dst = kmap_atomic(page);
	memcpy(dst + offset, src, copy);
	kunmap_atomic(dst);

	if (copy < n) {
		src += copy;
		sector += copy >> SECTOR_SHIFT;
		copy = n - copy;
		page = pcache_lookup_page(pcache, sector);
		BUG_ON(!page);
		dst = kmap_atomic(page);
		memcpy(dst, src, copy);
		kunmap_atomic(dst);
	}
}

static void
copy_from_pcache(void *dst, pcache_t *pcache, sector_t sector, size_t n)
{
	void	*src;
	struct page	*page;
	unsigned int	offset = (sector & (PAGE_SECTORS - 1)) << SECTOR_SHIFT;
	size_t	copy;

	copy = min_t(size_t, n, PAGE_SIZE - offset);
	page = pcache_lookup_page(pcache, sector);

	if (page) {
		src = kmap_atomic(page);
		memcpy(dst, src + offset, copy);
		kunmap_atomic(src);
	} else {
		memset(dst, 0, copy);
	}

	if (copy < n) {
		dst += copy;
		sector += copy >> SECTOR_SHIFT;
		copy = n - copy;
		page = pcache_lookup_page(pcache, sector);
		if (page) {
			src = kmap_atomic(page);
			memcpy(dst, src, copy);
			kunmap_atomic(src);
		} else {
			memset(dst, 0, copy);
		}
	}
}

static int
pcache_do_bvec(pcache_t *pcache, struct page *page,
	       unsigned int len, unsigned int off, bool is_write, sector_t sector)
{
	void	*mem;
	int	err = 0;

	if (is_write) {
		err = copy_to_pcache_setup(pcache, sector, len);
		if (err)
			goto out;
	}
	mem = kmap_atomic(page);
	if (!is_write) {
		copy_from_pcache(mem + off, pcache, sector, len);
		flush_dcache_page(page);
	} else {
		flush_dcache_page(page);
		copy_to_pcache(pcache, mem + off, sector, len);
	}
	kunmap_atomic(mem);
out:
	return err;
}

static void
pcache_free_pages(pcache_t *pcache)
{
	struct page	*pages[FREE_BATCH];
	unsigned long	pos = 0;
	int	nr_pages;

	do {
		int	i;

		nr_pages = radix_tree_gang_lookup(&pcache->tree_pages, (void **)pages, pos, FREE_BATCH);

		for (i = 0; i < nr_pages; i++) {
			void	*ret;

			BUG_ON(pages[i]->index < pos);
			pos = pages[i]->index;
			ret = radix_tree_delete(&pcache->tree_pages, pos);
			BUG_ON(!ret || ret != pages[i]);
			__free_page(pages[i]);
		}
		pos++;
	} while (nr_pages == FREE_BATCH);
}

int
pcache_submit(pcache_t *pcache, bool is_write, sector_t sector, struct bio *bio)
{
	struct bio_vec	bvec;
	struct bvec_iter	iter;

	if (unlikely(bio_op(bio) == REQ_OP_DISCARD)) {
		if (sector & ((PAGE_SIZE >> SECTOR_SHIFT) - 1) ||
		    bio->bi_iter.bi_size & ~PAGE_MASK)
			return -EIO;
		discard_from_pcache(pcache, sector, bio->bi_iter.bi_size);
		return 0;
	}

	bio_for_each_segment(bvec, bio, iter) {
		unsigned int len = bvec.bv_len;
		int	err;

		err = pcache_do_bvec(pcache, bvec.bv_page, len, bvec.bv_offset, is_write, sector);
		if (err) {
			return -EIO;
		}
		sector += len >> SECTOR_SHIFT;
	}
	return 0;
}

pcache_t *
pcache_create(void)
{
	pcache_t	*pcache;

	pcache = kzalloc(sizeof(*pcache), GFP_KERNEL);
	if (pcache == NULL)
		return NULL;

	spin_lock_init(&pcache->lock);
	INIT_RADIX_TREE(&pcache->tree_pages, GFP_ATOMIC);

	return pcache;
}

void
pcache_delete(pcache_t *pcache)
{
	if (pcache == NULL)
		return;
	pcache_free_pages(pcache);
	kfree(pcache);
}
