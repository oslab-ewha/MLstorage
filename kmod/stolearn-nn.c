/*******************************************************************************
 ** Copyright © 2011 - 2021 Petros Koutoupis
 ** All rights reserved.
 **
 ** This program is free software: you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation; under version 2 of the License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **
 ** SPDX-License-Identifier: GPL-2.0-only
 **
 ** filename: stolearn-nn.c
 **
 ******************************************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/errno.h>
#include <linux/radix-tree.h>
#include <linux/io.h>

#define VERSION_STR		"1.0.0"
#define PREFIX			"stolearn-nn"
#define BYTES_PER_SECTOR	512
#define MAX_RDSKS		128
#define DEFAULT_MAX_SECTS	127
#define DEFAULT_REQUESTS	128
#define GENERIC_ERROR		-1

#define FREE_BATCH		16
#define SECTOR_SHIFT		9
#define PAGE_SECTORS_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define PAGE_SECTORS		BIT(PAGE_SECTORS_SHIFT)

/* ioctls */
#define INVALID_CDQUERY_IOCTL	0x5331
#define RD_GET_STATS		0x0529

static DEFINE_MUTEX(sysfs_mutex);
static DEFINE_MUTEX(ioctl_mutex);

struct rdsk_device {
	int num;
	struct request_queue *rdsk_queue;
	struct gendisk *rdsk_disk;
	struct list_head rdsk_list;
	unsigned long long max_blk_alloc;	/* rdsk: to keep track of highest sector write	*/
	unsigned long long size;
	unsigned long error_cnt;
	spinlock_t rdsk_lock;
	struct radix_tree_root rdsk_pages;
};

static int rd_ma_no, rd_total; /* no. of attached devices */
static int rd_max_nr = MAX_RDSKS;
static int max_sectors = DEFAULT_MAX_SECTS, nr_requests = DEFAULT_REQUESTS;
static LIST_HEAD(rdsk_devices);
static struct kobject *rdsk_kobj;

module_param(max_sectors, int, S_IRUGO);
MODULE_PARM_DESC(max_sectors, " max sectors (in KB) for the request queue. (Default = 127)");
module_param(nr_requests, int, S_IRUGO);
MODULE_PARM_DESC(nr_requests, " # of requests at a given time for the request queue. (Default = 128)");
module_param(rd_max_nr, int, S_IRUGO);
MODULE_PARM_DESC(rd_max_nr, " max number of RAM Disks. (Default = 128)");

static int rdsk_do_bvec(struct rdsk_device *, struct page *,
			unsigned int, unsigned int, bool, sector_t);
static int rdsk_ioctl(struct block_device *, fmode_t,
		      unsigned int, unsigned long);
static blk_qc_t rdsk_make_request(struct request_queue *, struct bio *);
static int attach_device(int);    /* disk size(in MB) */
static int detach_device(int);	  /* disk num */
static ssize_t mgmt_show(struct kobject *, struct kobj_attribute *, char *);
static ssize_t mgmt_store(struct kobject *, struct kobj_attribute *,
			  const char *, size_t);

static ssize_t mgmt_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	int len;
	struct rdsk_device *rdsk;

	len = sprintf(buf, "Stolearn-NN %s\n\nMaximum Number of Attachable Devices: %d\nNumber of Attached Devices: %d\nMax Sectors (KB): %d\nNumber of Requests: %d\n\n",
		      VERSION_STR, rd_max_nr, rd_total, max_sectors, nr_requests);
	list_for_each_entry(rdsk, &rdsk_devices, rdsk_list) {
		len += sprintf(buf + len, "stolearn-nn%d\tSize: %llu MBs\tErrors: %lu\n",
			       rdsk->num, (rdsk->size / 1024 / 1024),
			       rdsk->error_cnt);
	}
	return len;
}

static ssize_t
mgmt_attach_device(char *buf)
{
	unsigned int	size;
	int	n_scanned;

	n_scanned = sscanf(buf, "%u", &size);
	if (n_scanned <= 0) {
		pr_err("%s: wrong attach format: %s\n", PREFIX, buf);
		return -EINVAL;
	}

	if (attach_device(size) != 0) {
		pr_err("%s: Unable to attach a new stolearn-nn device.\n", PREFIX);
		return -EINVAL;
	}

	return 0;
}

static ssize_t
mgmt_detach_device(char *buf)
{
	unsigned int	num;

	if (kstrtouint(buf, 0, &num) < 0) {
		pr_err("%s: wrong detach format: %s\n", PREFIX, buf);
		return -EINVAL;
	}

	if (detach_device(num) != 0) {
		pr_err("%s: Unable to detach stolearn-nn%d\n", PREFIX, num);
		return -EINVAL;
	}
	return 0;
}

static ssize_t
mgmt_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buffer, size_t count)
{
	char	*buf;
	int	err;

	if (!buffer || count > PAGE_SIZE)
		return -EINVAL;

	mutex_lock(&sysfs_mutex);
	buf = (char *)__get_free_page(GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto write_sysfs_error;
	}
	strcpy(buf, buffer);

	if (!strncmp("stolearn-nn attach ", buffer, 19))
		err = mgmt_attach_device(buf + 19);
	else if (!strncmp("stolearn-nn detach ", buffer, 19))
		err = mgmt_detach_device(buf + 19);
	else {
		pr_err("%s: Unsupported command: %s\n", PREFIX, buffer);
		err = -EINVAL;
	}

	free_page((unsigned long)buf);
write_sysfs_error:
	mutex_unlock(&sysfs_mutex);
	if (err == 0)
		return count;
	return err;
}

static struct kobj_attribute mgmt_attribute =
	__ATTR(mgmt, 0664, mgmt_show, mgmt_store);

static struct attribute *attrs[] = {
	&mgmt_attribute.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static struct page *rdsk_lookup_page(struct rdsk_device *rdsk, sector_t sector)
{
	pgoff_t idx;
	struct page *page;

	rcu_read_lock();
	idx = sector >> PAGE_SECTORS_SHIFT; /* sector to page index */
	page = radix_tree_lookup(&rdsk->rdsk_pages, idx);
	rcu_read_unlock();

	BUG_ON(page && page->index != idx);

	return page;
}

static struct page *rdsk_insert_page(struct rdsk_device *rdsk, sector_t sector)
{
	pgoff_t idx;
	struct page *page;
	gfp_t gfp_flags;

	page = rdsk_lookup_page(rdsk, sector);
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

	spin_lock(&rdsk->rdsk_lock);
	idx = sector >> PAGE_SECTORS_SHIFT;
	if (radix_tree_insert(&rdsk->rdsk_pages, idx, page)) {
		__free_page(page);
		page = radix_tree_lookup(&rdsk->rdsk_pages, idx);
		BUG_ON(!page);
		BUG_ON(page->index != idx);
	} else {
		page->index = idx;
	}
	spin_unlock(&rdsk->rdsk_lock);

	radix_tree_preload_end();

	return page;
}

static void rdsk_zero_page(struct rdsk_device *rdsk, sector_t sector)
{
	struct page *page;

	page = rdsk_lookup_page(rdsk, sector);
	if (page)
		clear_highpage(page);
}

static void rdsk_free_pages(struct rdsk_device *rdsk)
{
	unsigned long pos = 0;
	struct page *pages[FREE_BATCH];
	int nr_pages;

	do {
		int i;

		nr_pages = radix_tree_gang_lookup(&rdsk->rdsk_pages,
						  (void **)pages, pos,
						  FREE_BATCH);

		for (i = 0; i < nr_pages; i++) {
			void *ret;

			BUG_ON(pages[i]->index < pos);
			pos = pages[i]->index;
			ret = radix_tree_delete(&rdsk->rdsk_pages, pos);
			BUG_ON(!ret || ret != pages[i]);
			__free_page(pages[i]);
		}
		pos++;
	} while (nr_pages == FREE_BATCH);
}

static int copy_to_rdsk_setup(struct rdsk_device *rdsk,
			      sector_t sector, size_t n)
{
	unsigned int offset = (sector & (PAGE_SECTORS - 1)) << SECTOR_SHIFT;
	size_t copy;

	copy = min_t(size_t, n, PAGE_SIZE - offset);
	if (!rdsk_insert_page(rdsk, sector))
		return -ENOSPC;
	if (copy < n) {
		sector += copy >> SECTOR_SHIFT;
		if (!rdsk_insert_page(rdsk, sector))
			return -ENOSPC;
	}
	return 0;
}

static void discard_from_rdsk(struct rdsk_device *rdsk,
			      sector_t sector, size_t n)
{
	while (n >= PAGE_SIZE) {
		rdsk_zero_page(rdsk, sector);
		sector += PAGE_SIZE >> SECTOR_SHIFT;
		n -= PAGE_SIZE;
	}
}

static void copy_to_rdsk(struct rdsk_device *rdsk, const void *src,
			 sector_t sector, size_t n)
{
	struct page *page;
	void *dst;
	unsigned int offset = (sector & (PAGE_SECTORS - 1)) << SECTOR_SHIFT;
	size_t copy;

	copy = min_t(size_t, n, PAGE_SIZE - offset);
	page = rdsk_lookup_page(rdsk, sector);
	BUG_ON(!page);

	dst = kmap_atomic(page);
	memcpy(dst + offset, src, copy);
	kunmap_atomic(dst);

	if (copy < n) {
		src += copy;
		sector += copy >> SECTOR_SHIFT;
		copy = n - copy;
		page = rdsk_lookup_page(rdsk, sector);
		BUG_ON(!page);
		dst = kmap_atomic(page);
		memcpy(dst, src, copy);
		kunmap_atomic(dst);
	}

	if ((sector + (n / BYTES_PER_SECTOR)) > rdsk->max_blk_alloc)
		rdsk->max_blk_alloc = (sector + (n / BYTES_PER_SECTOR));
}

static void copy_from_rdsk(void *dst, struct rdsk_device *rdsk,
			   sector_t sector, size_t n)
{
	struct page *page;
	void *src;
	unsigned int offset = (sector & (PAGE_SECTORS - 1)) << SECTOR_SHIFT;
	size_t copy;

	copy = min_t(size_t, n, PAGE_SIZE - offset);
	page = rdsk_lookup_page(rdsk, sector);

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
		page = rdsk_lookup_page(rdsk, sector);
		if (page) {
			src = kmap_atomic(page);
			memcpy(dst, src, copy);
			kunmap_atomic(src);
		} else {
			memset(dst, 0, copy);
		}
	}
}

static int rdsk_do_bvec(struct rdsk_device *rdsk, struct page *page,
			unsigned int len, unsigned int off, bool is_write,
			sector_t sector){
	void *mem;
	int err = 0;

	if (is_write) {
		err = copy_to_rdsk_setup(rdsk, sector, len);
		if (err)
			goto out;
	}
	mem = kmap_atomic(page);
	if (!is_write) {
		copy_from_rdsk(mem + off, rdsk, sector, len);
		flush_dcache_page(page);
	} else {
		flush_dcache_page(page);
		copy_to_rdsk(rdsk, mem + off, sector, len);
	}
	kunmap_atomic(mem);
out:
	return err;
}

int
rdsk_submit_bio(struct gendisk *disk, sector_t sector, struct bio *bio)
{
	struct rdsk_device *rdsk = disk->private_data;
	struct bio_vec bvec;
	struct bvec_iter iter;

	if (unlikely(bio_op(bio) == REQ_OP_DISCARD)) {
		if (sector & ((PAGE_SIZE >> SECTOR_SHIFT) - 1) ||
		    bio->bi_iter.bi_size & ~PAGE_MASK)
			return -EIO;
		discard_from_rdsk(rdsk, sector, bio->bi_iter.bi_size);
		return 0;
	}

	bio_for_each_segment(bvec, bio, iter) {
		unsigned int len = bvec.bv_len;
		int	err;

		err = rdsk_do_bvec(rdsk, bvec.bv_page, len,
				   bvec.bv_offset, op_is_write(bio_op(bio)), sector);
		if (err) {
			rdsk->error_cnt++;
			return -EIO;
		}
		sector += len >> SECTOR_SHIFT;
	}
	return 0;
}
EXPORT_SYMBOL(rdsk_submit_bio);

static blk_qc_t
rdsk_make_request(struct request_queue *q, struct bio *bio)
{
	struct rdsk_device *rdsk = bio->bi_disk->private_data;
	sector_t sector;
	struct bio_vec bvec;
	struct bvec_iter iter;
	int err = -EIO;

	sector = bio->bi_iter.bi_sector;
	if ((sector + bio_sectors(bio)) > get_capacity(bio->bi_disk)) {
		goto io_error;
	}

	err = 0;
	if (unlikely(bio_op(bio) == REQ_OP_DISCARD)) {
		if (sector & ((PAGE_SIZE >> SECTOR_SHIFT) - 1) ||
		    bio->bi_iter.bi_size & ~PAGE_MASK)
		goto io_error;
		discard_from_rdsk(rdsk, sector, bio->bi_iter.bi_size);
		goto out;
	}

	bio_for_each_segment(bvec, bio, iter) {
		unsigned int len = bvec.bv_len;

		err = rdsk_do_bvec(rdsk, bvec.bv_page, len,
				   bvec.bv_offset, op_is_write(bio_op(bio)), sector);
		if (err) {
			rdsk->error_cnt++;
			goto io_error;
		}
		sector += len >> SECTOR_SHIFT;
	}

out:
	bio_endio(bio);
	return BLK_QC_T_NONE;
io_error:
	bio->bi_status= err;
	bio_io_error(bio);
	return BLK_QC_T_NONE;
}

static int rdsk_ioctl(struct block_device *bdev, fmode_t mode,
		      unsigned int cmd, unsigned long arg)
{
	loff_t size;
	int error = 0;
	struct rdsk_device *rdsk = bdev->bd_disk->private_data;

	switch (cmd) {
	case BLKGETSIZE:
		size = bdev->bd_inode->i_size;
		if ((size >> 9) > ~0UL)
			return -EFBIG;
		return copy_to_user((void __user *)arg, &size,
				    sizeof(size)) ? -EFAULT : 0;
	case BLKGETSIZE64:
		return copy_to_user((void __user *)arg,
				    &bdev->bd_inode->i_size,
				    sizeof(bdev->bd_inode->i_size)) ? -EFAULT : 0;
	case BLKFLSBUF:
		/* We are killing the RAM disk data. */
		mutex_lock(&ioctl_mutex);
		mutex_lock(&bdev->bd_mutex);
		error = -EBUSY;
		if (bdev->bd_openers <= 1) {
			kill_bdev(bdev);
			rdsk_free_pages(rdsk);
			error = 0;
		}
		mutex_unlock(&bdev->bd_mutex);
		mutex_unlock(&ioctl_mutex);
		return error;
	case INVALID_CDQUERY_IOCTL:
		return -EINVAL;
	case RD_GET_STATS:
		return copy_to_user((void __user *)arg,
			&rdsk->max_blk_alloc,
			sizeof(rdsk->max_blk_alloc)) ? -EFAULT : 0;
	case BLKPBSZGET:
	case BLKBSZGET:
	case BLKSSZGET:
		size = BYTES_PER_SECTOR;
		return copy_to_user((void __user *)arg, &size,
			sizeof(size)) ? -EFAULT : 0;
	}

	pr_warn("%s: 0x%x invalid ioctl.\n", PREFIX, cmd);
	return -ENOTTY;		/* unknown command */
}

static const struct block_device_operations rdsk_fops = {
	.owner = THIS_MODULE,
	.ioctl = rdsk_ioctl,
};

static int
attach_device(int size)
{
	int num = 0;
	struct rdsk_device *rdsk, *tmp;
	struct gendisk *disk;
	unsigned char *string, name[32];

	if (rd_total >= rd_max_nr) {
		pr_warn("%s: Reached maximum number of attached disks.\n",
			PREFIX);
		goto out;
	}

	string = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!string)
		goto out;
	list_for_each_entry(tmp, &rdsk_devices, rdsk_list) {
		sprintf(string, "%sstolearn-nn%d,", string, tmp->num);
		num++;
	}
	while (num >= 0) {
		memset(name, 0x0, sizeof(name));
		sprintf(name, "stolearn-nn%d,", num);
                if (strstr(string, (const char *)name) == NULL) {
                        break;
                }
                num--;
        }
	kfree(string);

	rdsk = kzalloc(sizeof(*rdsk), GFP_KERNEL);
	if (!rdsk)
		goto out;
	rdsk->num = num;
	rdsk->error_cnt = 0;
	rdsk->max_blk_alloc = 0;
	rdsk->size = ((unsigned long long)size * 2 * 1024 * BYTES_PER_SECTOR);
	spin_lock_init(&rdsk->rdsk_lock);
	INIT_RADIX_TREE(&rdsk->rdsk_pages, GFP_ATOMIC);

	rdsk->rdsk_queue = blk_alloc_queue(GFP_KERNEL);
	if (!rdsk->rdsk_queue)
		goto out_free_dev;
	blk_queue_make_request(rdsk->rdsk_queue, rdsk_make_request);
	blk_queue_logical_block_size(rdsk->rdsk_queue, BYTES_PER_SECTOR);
	blk_queue_physical_block_size(rdsk->rdsk_queue, PAGE_SIZE);
	blk_queue_write_cache(rdsk->rdsk_queue, true, false);

	rdsk->rdsk_queue->limits.max_sectors = (max_sectors * 2);
	rdsk->rdsk_queue->nr_requests = nr_requests;
	rdsk->rdsk_queue->limits.discard_granularity = PAGE_SIZE;
	rdsk->rdsk_queue->limits.max_discard_sectors = UINT_MAX;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, rdsk->rdsk_queue);
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, rdsk->rdsk_queue);

	disk = rdsk->rdsk_disk = alloc_disk(1);
	if (!disk)
		goto out_free_queue;
	disk->major = rd_ma_no;
	disk->first_minor = num;
	disk->fops = &rdsk_fops;
	disk->private_data = rdsk;
	disk->queue = rdsk->rdsk_queue;
	disk->flags |= GENHD_FL_SUPPRESS_PARTITION_INFO;
	sprintf(disk->disk_name, "stolearn-nn%d", num);
	set_capacity(disk, rdsk->size / BYTES_PER_SECTOR);

	add_disk(rdsk->rdsk_disk);
	list_add_tail(&rdsk->rdsk_list, &rdsk_devices);
	rd_total++;
	pr_info("%s: Attached stolearn-nn%d of %llu bytes in size.\n", PREFIX, num, rdsk->size);
	return 0;

out_free_queue:
	blk_cleanup_queue(rdsk->rdsk_queue);
out_free_dev:
	kfree(rdsk);
out:
	return GENERIC_ERROR;
}

static struct rdsk_device *
find_device(int num)
{
	struct rdsk_device	*rdsk;

	list_for_each_entry(rdsk, &rdsk_devices, rdsk_list)
		if (rdsk->num == num)
			return rdsk;
	return NULL;
}

static int detach_device(int num)
{
	struct rdsk_device	*rdsk;

	rdsk = find_device(num);
	if (rdsk == NULL)
		return -1;

	list_del(&rdsk->rdsk_list);
	del_gendisk(rdsk->rdsk_disk);
	put_disk(rdsk->rdsk_disk);
	blk_cleanup_queue(rdsk->rdsk_queue);
	rdsk_free_pages(rdsk);
	kfree(rdsk);
	rd_total--;
	pr_info("%s: Detached stolearn-nn%d.\n", PREFIX, num);

	return 0;
}

static int __init init_rd(void)
{
	int	retval;

	rd_total = rd_ma_no = 0;
	rd_ma_no = register_blkdev(rd_ma_no, PREFIX);
	if (rd_ma_no < 0) {
		pr_err("%s: Failed registering rdsk, returned %d\n",
		       PREFIX, rd_ma_no);
		return rd_ma_no;
	}

	rdsk_kobj = kobject_create_and_add("stolearn-nn", kernel_kobj);
	if (!rdsk_kobj)
		goto init_failure;
	retval = sysfs_create_group(rdsk_kobj, &attr_group);
	if (retval)
		goto init_failure2;

	return 0;

init_failure2:
	kobject_put(rdsk_kobj);
init_failure:
	unregister_blkdev(rd_ma_no, PREFIX);
	return -ENOMEM;
}

static void __exit exit_rd(void)
{
	struct rdsk_device *rdsk, *next;

	kobject_put(rdsk_kobj);
	list_for_each_entry_safe(rdsk, next, &rdsk_devices, rdsk_list)
		detach_device(rdsk->num);
	unregister_blkdev(rd_ma_no, PREFIX);
}

module_init(init_rd);
module_exit(exit_rd);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("oslab <oslab@oslab.ewha.ac.kr>");
MODULE_DESCRIPTION("Stolearn NN is a neural network for learning storage access pattern.");
MODULE_VERSION(VERSION_STR);
MODULE_INFO(Copyright, "Copyleft 2021 OSLAB, Ewha");
