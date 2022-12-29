#include <mm/mmap.h>
#include <mm/paging.h>
#include <proc/sched.h>
#include <fcntl.h>
#include <stderr.h>

/*
 * Fill a page.
 */
static struct page_t *fill_page(struct inode_t *inode, off_t offset)
{
	struct page_t *page;
	uint32_t new_page;

	/* try to get page from cache */
	page = find_page(inode, offset);
	if (page)
		return page;

	/* get a new page */
	new_page = (uint32_t) get_free_page();
	if (!new_page)
		return NULL;

	/* get page and add it to cache */
	page = &page_table[MAP_NR(new_page)];
	add_to_page_cache(page, inode, offset);

	/* read page */
	inode->i_op->readpage(inode, page);

	return page;
}

/*
 * Handle a page fault = read page from file.
 */
static struct page_t *filemap_nopage(struct vm_area_t *vma, uint32_t address)
{
	struct inode_t *inode = vma->vm_inode;
	struct page_t *page, *new_page;
	uint32_t offset;

	/* page align address */
	address = PAGE_ALIGN_DOWN(address);

	/* compute offset */
	offset = address - vma->vm_start + vma->vm_offset;
	if (offset >= inode->i_size)
		return NULL;

	/* fill in page */
	page = fill_page(inode, offset);

	/* no share : copy to new page and keep old page in offset */
	if (page && !(vma->vm_flags & VM_SHARED)) {
		/* get a new page */
		new_page = __get_free_page();
		if (new_page)
			memcpy((void *) PAGE_ADDRESS(new_page), (void *) PAGE_ADDRESS(page), PAGE_SIZE);

		/* release cache page */
		__free_page(page);
		return new_page;
	}

	return page;
}

/*
 * File mapping operations.
 */
static struct vm_operations_t file_mmap = {
	.nopage		= filemap_nopage,
};

/*
 * Generic mmap file.
 */
int generic_file_mmap(struct inode_t *inode, struct vm_area_t *vma)
{
	/* inode must be a regular file */
	if (!inode->i_sb || !S_ISREG(inode->i_mode))
		return -EACCES;

	/* offset must be block aligned */
	if (vma->vm_offset & (inode->i_sb->s_blocksize - 1))
		return -EINVAL;

	/* update inode */
	inode->i_atime = CURRENT_TIME;
	inode->i_dirt = 1;
	inode->i_ref++;

	/* set memory region */
	vma->vm_inode = inode;
	vma->vm_ops = &file_mmap;

	return 0;
}

/*
 * Truncate inode pages.
 */
void truncate_inode_pages(struct inode_t *inode, off_t start)
{
	struct list_head_t *pos, *n;
	struct page_t *page;
	off_t offset;

	list_for_each_safe(pos, n, &inode->i_pages) {
		page = list_entry(pos, struct page_t, list);
		offset = page->offset;

		/* full page truncate */
		if (offset >= start) {
			htable_delete(&page->htable);
			__free_page(page);
			continue;
		}

		/* partial page truncate */
		offset = start - offset;
		if (offset < PAGE_SIZE)
			memset((void *) (PAGE_ADDRESS(page) + offset), 0, PAGE_SIZE - offset);
	}
}

/*
 * Update a page cache copy.
 */
void update_vm_cache(struct inode_t *inode, const char *buf, size_t pos, size_t count)
{
	struct page_t *page;
	off_t offset;
	size_t len;
	void *addr;

	offset = pos & ~PAGE_MASK;
	pos = pos & PAGE_MASK;
	len = PAGE_SIZE - offset;

	while (count > 0) {
		/* adjust size */
		if (len > count)
			len = count;

		/* find page in cache */
		page = find_page(inode, pos);
		if (page) {
			/* update page */
			addr = (void *) PAGE_ADDRESS(page);
			memcpy(addr + offset, buf, len);

			/* release page */
			__free_page(page);
		}

		count -= len;
		buf += len;
		pos += PAGE_SIZE;
		len = PAGE_SIZE;
		offset = 0;
	}
}
