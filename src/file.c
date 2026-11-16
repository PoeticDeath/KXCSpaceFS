// Copyright (c) Anthony Kerr 2026-

#define pr_fmt(fmt) KBUILD_MODNAME ":%s:%s:%d: " fmt, __FILE__, __func__, __LINE__

#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mpage.h>
#include <linux/writeback.h>

#include "super.h"

#include "linuxfs.h"
#include "Dict.h"
#include "cspacefs.h"

void folio_buffers_set_uptodate(struct folio* folio)
{
    struct buffer_head* head = folio_buffers(folio);
    if (head)
    {
	    struct buffer_head* bh;

	    bh = head;
	    do {
		    set_buffer_uptodate(bh);
		    bh = bh->b_this_page;
	    } while (bh != head);
    }
}

void folio_buffers_clear_dirty(struct folio* folio)
{
    struct buffer_head* head = folio_buffers(folio);
    if (head)
    {
	    struct buffer_head* bh;

	    bh = head;
	    do {
		    clear_buffer_dirty(bh);
		    bh = bh->b_this_page;
	    } while (bh != head);
    }
}

static int kxcspacefs_getfrag_block(struct inode* inode, sector_t fragment, struct buffer_head* bh_result, int create)
{
    struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    UNICODE_STRING* fn = inode->i_private;
    unsigned long long phys = 0;
    fragment *= 512;

    unsigned int nofs_flags = memalloc_nofs_save();
    down_read(KMCSFS->op_lock);
    unsigned long long index = get_filename_index(*fn, KMCSFS);
    unsigned long long dindex = FindDictEntry(KMCSFS->dict, KMCSFS->table, KMCSFS->tableend, KMCSFS->DictSize, fn->Buffer, fn->Length);
    unsigned long long loc = get_strloc(index, dindex, KMCSFS);

	bool notzero = false;
	bool multisector = false;
	unsigned cur = 0;
	unsigned long long int0 = 0;
	unsigned long long int1 = 0;
	unsigned long long int2 = 0;
	unsigned long long int3 = 0;
	unsigned long long filesize = 0;

	for (unsigned long long i = loc; i < KMCSFS->tablestrlen; i++)
	{
		if (KMCSFS->tablestr[i] == *"," || KMCSFS->tablestr[i] == *".")
		{
			if (notzero)
			{
				if (multisector)
				{
					for (unsigned long long o = 0; o < int0 - int3; o++)
					{
                        filesize += KMCSFS->sectorsize;
                        if (filesize > fragment)
                        {
                            phys = KMCSFS->size - KMCSFS->sectorsize - (int3 + o) * KMCSFS->sectorsize;
                            filesize += KMCSFS->sectorsize;
                            break;
                        }
					}
                    if (filesize > fragment)
                    {
                        break;
                    }
				}
				switch (cur)
				{
				case 0:
                    filesize += KMCSFS->sectorsize;
                    break;
				case 1:
					break;
				case 2:
					//filesize += int2 - int1;
					break;
				}
                if (filesize > fragment)
                {
                    phys = KMCSFS->size - KMCSFS->sectorsize - int0 * KMCSFS->sectorsize;
                    break;
                }
			}
			cur = 0;
			int0 = 0;
			int1 = 0;
			int2 = 0;
			int3 = 0;
			multisector = false;
			if (KMCSFS->tablestr[i] == *".")
			{
				break;
			}
		}
		else if (KMCSFS->tablestr[i] == *";")
		{
			cur++;
		}
		else if (KMCSFS->tablestr[i] == *"-")
		{
			int3 = int0;
			multisector = true;
			cur = 0;
			int0 = 0;
			int1 = 0;
			int2 = 0;
		}
		else
		{
			notzero = true;
			switch (cur)
			{
			case 0:
				int0 += toint(KMCSFS->tablestr[i] & 0xff);
				if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
				{
					int0 *= 10;
				}
				break;
			case 1:
				int1 += toint(KMCSFS->tablestr[i] & 0xff);
				if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
				{
					int1 *= 10;
				}
				break;
			case 2:
				int2 += toint(KMCSFS->tablestr[i] & 0xff);
				if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
				{
					int2 *= 10;
				}
				break;
			}
		}
	}
    up_read(KMCSFS->op_lock);
    memalloc_nofs_restore(nofs_flags);

    if (phys)
    {
        map_bh(bh_result, sb, phys / 512 + fragment % KMCSFS->sectorsize / 512);
    }
    return 0;
}

static sector_t kxcspacefs_bmap(struct address_space* mapping, sector_t block)
{
	return generic_block_bmap(mapping, block, kxcspacefs_getfrag_block);
}

/*
 * Called when a file is opened in the kxcspacefs.
 * It checks the flags associated with the file opening mode (O_WRONLY, O_RDWR,
 * O_TRUNC) and performs truncation if the file is being opened for write or
 * read/write and the O_TRUNC flag is set.
 */
static int kxcspacefs_open(struct inode* inode, struct file* filp)
{
    bool wronly = (filp->f_flags & O_WRONLY);
    bool rdwr = (filp->f_flags & O_RDWR);
    bool trunc = (filp->f_flags & O_TRUNC);

    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(inode->i_sb);
    unsigned int nofs_flags = memalloc_nofs_save();
    down_write(KMCSFS->op_lock);
    if ((wronly || rdwr) && trunc && inode->i_size)
    {
        UNICODE_STRING* fn = inode->i_private;
        unsigned long long dindex = FindDictEntry(KMCSFS->dict, KMCSFS->table, KMCSFS->tableend, KMCSFS->DictSize, fn->Buffer, fn->Length);
        dealloc(KMCSFS, get_filename_index(*fn, KMCSFS), inode->i_size, 0, dindex);
        /* Update inode metadata */
        inode->i_size = 0;
        inode->i_blocks = 0;
    }
    up_write(KMCSFS->op_lock);
    memalloc_nofs_restore(nofs_flags);
    return 0;
}

static ssize_t kxcspacefs_read(struct file* file, char __user* buf, size_t len, loff_t* ppos, readlocks* readlock)
{
    struct inode* inode = file_inode(file);
    struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    unsigned long long bytes_to_read = 0;
    ssize_t bytes_read = 0;
    loff_t pos = *ppos;

    unsigned int nofs_flags = memalloc_nofs_save();
    down_read(KMCSFS->op_lock);
    if (pos >= inode->i_size)
    {
        up_read(KMCSFS->op_lock);
        memalloc_nofs_restore(nofs_flags);
        return 0;
    }

    if (pos + len > inode->i_size)
    {
        len = inode->i_size - pos;
    }

    UNICODE_STRING* fn = inode->i_private;
    unsigned long long dindex = FindDictEntry(KMCSFS->dict, KMCSFS->table, KMCSFS->tableend, KMCSFS->DictSize, fn->Buffer, fn->Length);
    bytes_read = read_file(sb->s_bdev, KMCSFS, buf, pos, len, get_filename_index(*fn, KMCSFS), &bytes_to_read, dindex, readlock);
    up_read(KMCSFS->op_lock);
    memalloc_nofs_restore(nofs_flags);
    if (!bytes_read)
    {
        /* successfully read data */
        bytes_read += bytes_to_read;
        len -= bytes_to_read;
        pos += bytes_to_read;
    }
    *ppos = pos;

    return bytes_read;
}

static ssize_t kxcspacefs_read_lock(struct file* file, char __user* buf, size_t len, loff_t* ppos)
{
    struct inode* inode = file_inode(file);
    struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    unsigned long long lock = acquire_readlock(KMCSFS);
    ssize_t ret = kxcspacefs_read(file, buf, len, ppos, &KMCSFS->readlocks[lock]);
    up_write(&KMCSFS->readlocks[lock].readbuflock);
    return ret;
}

ssize_t kxcspacefs_write(struct file* file, const char __user* buf, size_t len, loff_t* ppos)
{
    struct inode* inode = file_inode(file);
    struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    UNICODE_STRING* fn = inode->i_private;
    unsigned long long bytes_to_write = 0;
    ssize_t bytes_write = 0;
    loff_t pos = *ppos;

    unsigned long long plen = pos + len;
    unsigned int nofs_flags = memalloc_nofs_save();
    down_write(KMCSFS->op_lock);
    unsigned long long index = get_filename_index(*fn, KMCSFS);
    unsigned long long dindex = FindDictEntry(KMCSFS->dict, KMCSFS->table, KMCSFS->tableend, KMCSFS->DictSize, fn->Buffer, fn->Length);
    if (plen > inode->i_size)
    {
        if (find_block(sb->s_bdev, KMCSFS, index, plen - inode->i_size, dindex))
        {
            inode->i_size = plen;
            inode->i_blocks = (inode->i_size + 511) / 512;
        }
        else
        {
            up_write(KMCSFS->op_lock);
            memalloc_nofs_restore(nofs_flags);
            return -ENOSPC;
        }
    }

    bytes_write = write_file(sb->s_bdev, KMCSFS, buf, pos, len, index, inode->i_size, &bytes_to_write, dindex, false);
    if (!bytes_write)
    {
        /* successfully wrote data */
        bytes_write += bytes_to_write;
        len -= bytes_to_write;
        pos += bytes_to_write;
    }
    *ppos = pos;

    unsigned long long time = current_time(inode).tv_sec;
    chtime(index, time, 3, KMCSFS);
    inode->i_mtime_sec = time;
    up_write(KMCSFS->op_lock);
    memalloc_nofs_restore(nofs_flags);

    return bytes_write;
}

static int kxcspacefs_read_folio(struct file* file, struct folio* folio)
{
    if (!folio_test_uptodate(folio))
    {
        struct super_block* sb = folio_inode(folio)->i_sb;
        KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
        struct address_space* mapping = folio_mapping(folio);
        loff_t pos = folio_pos(folio);
        pos -= pos % folio_size(folio);
        unsigned long index = folio->index;

        unsigned long pagesrem = 0;
        loff_t lastpos = pos - PAGE_SIZE;

        for (unsigned long i = index; i < mapping->nrpages; i++)
        {
            struct folio* nfolio = xa_load(&mapping->i_pages, i);
            if (nfolio && virt_addr_valid(nfolio))
            {   
                if (!folio_test_uptodate(nfolio))
                {
                    loff_t nextpos = folio_pos(nfolio);
                    if ((nextpos == lastpos + PAGE_SIZE) && (nextpos / KMCSFS->sectorsize == (lastpos + PAGE_SIZE) / KMCSFS->sectorsize) && (pagesrem < KMCSFS->sectorsize / PAGE_SIZE))
                    {
                        lastpos = nextpos;
                        pagesrem++;
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }

        size_t len = max(pagesrem, 1) * PAGE_SIZE;
        unsigned long long lock = acquire_readlock(KMCSFS);
        char* buf = KMCSFS->readlocks[lock].readmembuf;
        kxcspacefs_read(file, buf, len, &pos, &KMCSFS->readlocks[lock]);

        if (pagesrem)
        {
            for (unsigned long i = 0; i < pagesrem; i++)
            {
                struct folio* nfolio = xa_load(&mapping->i_pages, index + i);
                if (nfolio)
                {
                    char* nbuf = kmap_local_folio(nfolio, 0);
                    memmove(nbuf, buf + i * PAGE_SIZE, PAGE_SIZE);
                    folio_mark_uptodate(nfolio);
                    folio_buffers_set_uptodate(nfolio);
                    kunmap_local(nbuf);
                }
            }
        }
        else
        {
            if (folio)
            {
                char* nbuf = kmap_local_folio(folio, 0);
                memmove(nbuf, buf, PAGE_SIZE);
                folio_mark_uptodate(folio);
                folio_buffers_set_uptodate(folio);
                kunmap_local(nbuf);
            }
        }

        up_write(&KMCSFS->readlocks[lock].readbuflock);
    }
    folio_unlock(folio);
    return 0;
}

static void kxcspacefs_readahead(struct readahead_control* ractl)
{
    struct file* file = ractl->file;
    struct inode* inode = ractl->mapping->host;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(inode->i_sb);
    struct folio* folio;

    unsigned long long lock = acquire_readlock(KMCSFS);
    char* buf = KMCSFS->readlocks[lock].readmembuf;

    /* Allocate a small array on stack or dynamically to track folios in the current batch */
    unsigned long max_pages = KMCSFS->sectorsize / PAGE_SIZE;
    struct folio** folios = kvmalloc_array(max_pages, sizeof(struct folio*), GFP_NOFS);
    if (!folios)
    {
        up_write(&KMCSFS->readlocks[lock].readbuflock);
        return; /* VFS will automatically clean up and fall back to read_folio */
    }

    while ((folio = readahead_folio(ractl)))
    {
        loff_t start_pos = folio_pos(folio);
        size_t total_len = folio_size(folio);
        unsigned long count = 0;

        folios[count++] = folio;

        /* Batch consecutive folios up to KMCSFS->sectorsize */
        while (count < max_pages && total_len < KMCSFS->sectorsize)
        {
            struct folio *next = readahead_folio(ractl);
            if (!next)
            {
                break;
            }

            folios[count++] = next;
            total_len += folio_size(next);
        }

        /* Read the entire batched chunk in one call */
        loff_t pos = start_pos;
        ssize_t bytes_read = kxcspacefs_read(file, buf, total_len, &pos, &KMCSFS->readlocks[lock]);

        /* Distribute data into the batched folios and unlock them */
        size_t offset = 0;
        for (unsigned long i = 0; i < count; i++)
        {
            struct folio* f = folios[i];
            size_t flen = folio_size(f);

            if (bytes_read > offset)
            {
                size_t copy_len = min_t(size_t, flen, bytes_read - offset);
                char *nbuf = kmap_local_folio(f, 0);

                memmove(nbuf, buf + offset, copy_len);
                /* Zero-fill any trailing bytes if we hit EOF mid-folio */
                if (copy_len < flen)
                {
                    memset(nbuf + copy_len, 0, flen - copy_len);
                }

                kunmap_local(nbuf);

                folio_mark_uptodate(f);
                folio_buffers_set_uptodate(f);
            }
            /* Note: If bytes_read <= offset (error/EOF), we leave it not-uptodate */
            folio_unlock(f);
            offset += flen;
        }
    }

    kvfree(folios);
    up_write(&KMCSFS->readlocks[lock].readbuflock);
}

static void kxcspacefs_flush_folio_batch(struct inode* inode, struct file* file, KMCSpaceFS* KMCSFS, struct folio** batch, unsigned int count, loff_t start_pos, size_t total_len)
{
    loff_t isize = i_size_read(inode);
    size_t write_len = (start_pos >= isize) ? 0 : min_t(loff_t, total_len, isize - start_pos);

    down_write(&KMCSFS->writebuflock);
    memset(KMCSFS->writemembuf, 0, KMCSFS->sectorsize);

    size_t offset = 0;
    for (unsigned int i = 0; i < count; i++)
    {
        size_t flen = folio_size(batch[i]);
        if (offset < write_len)
        {
            size_t copy_len = min_t(size_t, flen, write_len - offset);
            char* nbuf = kmap_local_folio(batch[i], 0);
            memmove(KMCSFS->writemembuf + offset, nbuf, copy_len);
            kunmap_local(nbuf);
        }
        offset += flen;
    }

    if (write_len > 0)
    {
        loff_t wpos = start_pos;
        kxcspacefs_write(file, KMCSFS->writemembuf, write_len, &wpos);
    }
    up_write(&KMCSFS->writebuflock);

    for (unsigned int i = 0; i < count; i++)
    {
        folio_clear_dirty(batch[i]);
        folio_buffers_clear_dirty(batch[i]);
        folio_start_writeback(batch[i]);
        folio_unlock(batch[i]);
        folio_end_writeback(batch[i]);
    }
}

static int kxcspacefs_writepages(struct address_space* mapping, struct writeback_control* wbc)
{
    struct inode* inode = mapping->host;
    struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    struct file file = { .f_inode = inode };
    struct folio* single_folio = NULL;
    struct folio* folio = NULL;
    struct blk_plug plug;
    unsigned int nofs_flags = memalloc_nofs_save();
    unsigned long long max_folios = KMCSFS->sectorsize / PAGE_SIZE;
    struct folio** batch = vmalloc(max_folios * sizeof(struct folio*));
    bool allocated = (batch != NULL);
    int error = 0;

    /* Fall back to 1-folio-at-a-time on stack if vmalloc fails during reclaim */
    if (!batch)
    {
        batch = &single_folio;
        max_folios = 1;
    }

    blk_start_plug(&plug);

    while ((folio = writeback_iter(mapping, wbc, folio, &error)))
    {
        unsigned int count = 0;
        loff_t start_pos = folio_pos(folio);
        loff_t expected_next_pos = start_pos + folio_size(folio);
        size_t total_len = folio_size(folio);

        batch[count++] = folio;

        /* Gather contiguous folios BEFORE acquiring writebuflock */
        while (count < max_folios && total_len < KMCSFS->sectorsize)
        {
            struct folio* next = writeback_iter(mapping, wbc, folio, &error);
            if (!next)
            {
                folio = NULL;
                break;
            }
            folio = next;

            /* If next folio is NOT contiguous, flush current batch first */
            if (folio_pos(folio) != expected_next_pos)
            {
                kxcspacefs_flush_folio_batch(inode, &file, KMCSFS, batch, count, start_pos, total_len);
                count = 0;
                start_pos = folio_pos(folio);
                total_len = 0;
            }

            batch[count++] = folio;
            expected_next_pos = folio_pos(folio) + folio_size(folio);
            total_len += folio_size(folio);
        }

        if (count > 0)
        {
            kxcspacefs_flush_folio_batch(inode, &file, KMCSFS, batch, count, start_pos, total_len);
        }

        if (!folio)
        {
            break;
        }
    }

    blk_finish_plug(&plug);
    if (allocated)
    {
        vfree(batch);
    }
    memalloc_nofs_restore(nofs_flags);
    return error;
}



#if KXCSPACEFS_AT_LEAST(6, 17, 0)
static int kxcspacefs_write_begin(const struct kiocb* kiocb, struct address_space* mapping, loff_t pos, unsigned len, struct folio** foliop, void** fsdata)
{
    struct inode* inode = file_inode(kiocb->ki_filp);
    struct file* file = kiocb->ki_filp;
#elif KXCSPACEFS_AT_LEAST(6, 12, 0)
static int kxcspacefs_write_begin(struct file* file, struct address_space* mapping, loff_t pos, unsigned len, struct folio** foliop, void** fsdata)
{
    struct inode* inode = file_inode(file);
#endif
    struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    UNICODE_STRING* fn = inode->i_private;

    unsigned long long plen = pos + len;
    unsigned int nofs_flags = memalloc_nofs_save();
    down_write(KMCSFS->op_lock);
    if (plen > inode->i_size)
    {
        unsigned long long index = get_filename_index(*fn, KMCSFS);
        unsigned long long dindex = FindDictEntry(KMCSFS->dict, KMCSFS->table, KMCSFS->tableend, KMCSFS->DictSize, fn->Buffer, fn->Length);
        if (find_block(sb->s_bdev, KMCSFS, index, plen - inode->i_size, dindex))
        {
            inode->i_size = plen;
            inode->i_blocks = (inode->i_size + 511) / 512;
        }
        else
        {
            up_write(KMCSFS->op_lock);
            memalloc_nofs_restore(nofs_flags);
            return -ENOSPC;
        }
    }
    up_write(KMCSFS->op_lock);
    memalloc_nofs_restore(nofs_flags);

	*foliop = __filemap_get_folio(mapping, pos / PAGE_SIZE, FGP_WRITEBEGIN, mapping_gfp_mask(mapping));
    struct buffer_head* bh = folio_buffers(*foliop);
    if (!bh)
    {
        bh = create_empty_buffers(*foliop, PAGE_SIZE, 0);
        loff_t toff = pos - pos % PAGE_SIZE;
        if ((toff != pos) || (len < PAGE_SIZE))
        {
            kxcspacefs_read_lock(file, bh->b_data, PAGE_SIZE, &toff);
        }
    }
    return 0;
}

static int kxcspacefs_write_end(const struct kiocb* kiocb, struct address_space* mapping, loff_t pos, unsigned len, unsigned copied, struct folio* folio, void* fsdata)
{
    copied = block_write_end(pos, len, copied, folio);
    block_dirty_folio(mapping, folio);
    folio_unlock(folio);
    return copied;
}

ssize_t kxcspacefs_perform_write(struct kiocb* iocb, struct iov_iter* i)
{
	struct file* file = iocb->ki_filp;
	loff_t pos = iocb->ki_pos;
	struct address_space* mapping = file->f_mapping;
	const struct address_space_operations* a_ops = mapping->a_ops;
	size_t chunk = mapping_max_folio_size(mapping);
	long status = 0;
	ssize_t written = 0;

	do {
		struct folio* folio;
		size_t offset;		/* Offset into folio */
		size_t bytes;		/* Bytes to write to folio */
		size_t copied;		/* Bytes copied from user */
		void* fsdata = NULL;

		bytes = iov_iter_count(i);
retry:
		offset = pos & (chunk - 1);
		balance_dirty_pages_ratelimited(mapping);

		if (fatal_signal_pending(current))
        {
			status = -EINTR;
			break;
		}

		status = a_ops->write_begin(iocb, mapping, pos, bytes, &folio, &fsdata);
		if (unlikely(status < 0))
        {
			break;
        }
        bytes = min(chunk - offset, bytes);

		offset = offset_in_folio(folio, pos);
		if (bytes > folio_size(folio) - offset)
        {
			bytes = folio_size(folio) - offset;
        }

		if (mapping_writably_mapped(mapping))
        {
			flush_dcache_folio(folio);
        }

		/*
		 * Faults here on mmap()s can recurse into arbitrary
		 * filesystem code. Lots of locks are held that can
		 * deadlock. Use an atomic copy to avoid deadlocking
		 * in page fault handling.
		 */
		copied = copy_folio_from_iter_atomic(folio, offset, bytes, i);
		flush_dcache_folio(folio);

		status = a_ops->write_end(iocb, mapping, pos, bytes, copied, folio, fsdata);
		if (unlikely(status != copied))
        {
			iov_iter_revert(i, copied - max(status, 0L));
			if (unlikely(status < 0))
            {
				break;
            }
		}
		cond_resched();

		if (unlikely(status == 0))
        {
			/*
			 * A short copy made ->write_end() reject the
			 * thing entirely.  Might be memory poisoning
			 * halfway through, might be a race with munmap,
			 * might be severe memory pressure.
			 */
			if (chunk > PAGE_SIZE)
            {
				chunk /= 2;
            }
			if (copied)
            {
				bytes = copied;
				goto retry;
			}

			/*
			 * 'folio' is now unlocked and faults on it can be
			 * handled. Ensure forward progress by trying to
			 * fault it in now.
			 */
			if (fault_in_iov_iter_readable(i, bytes) == bytes)
            {
				status = -EFAULT;
				break;
			}
		}
        else
        {
			pos += status;
			written += status;
		}
	} while (iov_iter_count(i));

	if (!written)
    {
		return status;
    }
	iocb->ki_pos += written;
	return written;
}

ssize_t __kxcspacefs_file_write_iter(struct kiocb* iocb, struct iov_iter* from)
{
	struct file* file = iocb->ki_filp;
	struct address_space* mapping = file->f_mapping;
	struct inode* inode = mapping->host;
	ssize_t ret;

	ret = file_remove_privs(file);
	if (ret)
    {
		return ret;
    }

	ret = file_update_time(file);
	if (ret)
    {
		return ret;
    }

	if (iocb->ki_flags & IOCB_DIRECT)
    {
		ret = generic_file_direct_write(iocb, from);
		/*
		 * If the write stopped short of completing, fall back to
		 * buffered writes.  Some filesystems do this for writes to
		 * holes, for example.  For DAX files, a buffered write will
		 * not succeed (even if it did, DAX does not handle dirty
		 * page-cache pages correctly).
		 */
		if (ret < 0 || !iov_iter_count(from) || IS_DAX(inode))
        {
			return ret;
        }
		return direct_write_fallback(iocb, from, ret, kxcspacefs_perform_write(iocb, from));
	}

	return kxcspacefs_perform_write(iocb, from);
}

ssize_t kxcspacefs_file_write_iter(struct kiocb* iocb, struct iov_iter* from)
{
	struct file* file = iocb->ki_filp;
	struct inode* inode = file->f_mapping->host;
	ssize_t ret;

	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
	if (ret > 0)
    {
		ret = __kxcspacefs_file_write_iter(iocb, from);
    }
	inode_unlock(inode);

	if (ret > 0)
    {
		ret = generic_write_sync(iocb, ret);
    }
	return ret;
}

long kxcspacefs_fallocate(struct file* file, int mode, loff_t offset, loff_t len)
{
    struct inode* inode = file_inode(file);
    struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    UNICODE_STRING* fn = inode->i_private;

    unsigned long long plen = offset + len;
    if (plen > KMCSFS->size)
    {
        return -EFBIG;
    }
    
    unsigned int nofs_flags = memalloc_nofs_save();
    down_write(KMCSFS->op_lock);
    if (plen > inode->i_size)
    {
        unsigned long long index = get_filename_index(*fn, KMCSFS);
        unsigned long long dindex = FindDictEntry(KMCSFS->dict, KMCSFS->table, KMCSFS->tableend, KMCSFS->DictSize, fn->Buffer, fn->Length);
        if (find_block(sb->s_bdev, KMCSFS, index, plen - inode->i_size, dindex))
        {
            inode->i_size = plen;
            inode->i_blocks = (inode->i_size + 511) / 512;
        }
        else
        {
            up_write(KMCSFS->op_lock);
            memalloc_nofs_restore(nofs_flags);
            return -ENOSPC;
        }
    }
    up_write(KMCSFS->op_lock);
    memalloc_nofs_restore(nofs_flags);

    return inode->i_size;
}

int kxcspacefs_release(struct inode* inode, struct file* file)
{
    filemap_write_and_wait(&inode->i_data);
    return 0;
}

const struct address_space_operations kxcspacefs_aops =
{
	.read_folio = kxcspacefs_read_folio,
    .readahead = kxcspacefs_readahead,
	.writepages = kxcspacefs_writepages,
    .write_begin = kxcspacefs_write_begin,
	.write_end = kxcspacefs_write_end,
    .dirty_folio = filemap_dirty_folio,
    .bmap = kxcspacefs_bmap,
    .invalidate_folio = block_invalidate_folio,
    .migrate_folio = buffer_migrate_folio,
};

const struct file_operations kxcspacefs_file_ops =
{
    .owner = THIS_MODULE,
#if KXCSPACEFS_AT_LEAST(3, 16, 0)
    .read_iter = generic_file_read_iter,
    .write_iter = kxcspacefs_file_write_iter,
#else
    .read = kxcspacefs_read_lock,
    .write = kxcspacefs_write,
#endif
#if KXCSPACEFS_AT_LEAST(6, 17, 0)
    .mmap_prepare = generic_file_mmap_prepare,
#else
    .mmap = generic_file_mmap,
#endif
    .open = kxcspacefs_open,
    .release = kxcspacefs_release,
    .llseek = generic_file_llseek,
    .fsync = generic_file_fsync,
    .fallocate = kxcspacefs_fallocate,
    .unlocked_ioctl = kxcspacefs_ioctl,
};
