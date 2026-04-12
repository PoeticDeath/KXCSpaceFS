// Copyright (c) Anthony Kerr 2026-

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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

static int kxcspacefs_getfrag_block(struct inode* inode, sector_t fragment, struct buffer_head* bh_result, int create)
{
    struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    UNICODE_STRING* fn = inode->i_private;
    unsigned long long phys = 0;
    fragment *= 512;

    down_read(KMCSFS->op_lock);
    unsigned long long index = get_filename_index(*fn, KMCSFS);
    unsigned long long loc = get_strloc(index, KMCSFS);

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

    if ((wronly || rdwr) && trunc && inode->i_size)
    {
        KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(inode->i_sb);
        UNICODE_STRING* fn = inode->i_private;
        down_write(KMCSFS->op_lock);
        dealloc(KMCSFS, get_filename_index(*fn, KMCSFS), inode->i_size, 0);
        up_write(KMCSFS->op_lock);
        /* Update inode metadata */
        inode->i_size = 0;
        inode->i_blocks = 0;
    }
    return 0;
}

static ssize_t kxcspacefs_read(struct file* file, char __user* buf, size_t len, loff_t* ppos)
{
    struct inode* inode = file_inode(file);
    struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    unsigned long long bytes_to_read = 0;
    ssize_t bytes_read = 0;
    loff_t pos = *ppos;

    if (pos > inode->i_size)
    {
        return 0;
    }

    if (pos + len > inode->i_size)
    {
        len = inode->i_size - pos;
    }

    UNICODE_STRING* fn = inode->i_private;
    down_read(KMCSFS->op_lock);
    bytes_read = read_file(sb->s_bdev, KMCSFS, buf, pos, len, get_filename_index(*fn, KMCSFS), &bytes_to_read);
    up_read(KMCSFS->op_lock);
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
    down_write(KMCSFS->op_lock);
    unsigned long long index = get_filename_index(*fn, KMCSFS);
    if (plen > inode->i_size)
    {
        if (find_block(sb->s_bdev, KMCSFS, index, plen - inode->i_size))
        {
            inode->i_size = plen;
            inode->i_blocks = (inode->i_size + 511) / 512;
        }
        else
        {
            up_write(KMCSFS->op_lock);
            return -ENOSPC;
        }
    }

    bytes_write = write_file(sb->s_bdev, KMCSFS, buf, pos, len, index, inode->i_size, &bytes_to_write, false);
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

    return bytes_write;
}

static int kxcspacefs_read_folio(struct file* file, struct folio* folio)
{
    if (!folio_test_uptodate(folio))
    {
        struct address_space* mapping = folio_mapping(folio);
        loff_t pos = folio_pos(folio);
        unsigned long index = 0;

        for (; index < mapping->nrpages; index++)
        {
            struct folio* nfolio = xa_load(&mapping->i_pages, index);
            if (nfolio)
            {
                if (nfolio == folio)
                {
                    break;
                }
            }
        }

        unsigned long pagesrem = 0;
        loff_t lastpos = pos - PAGE_SIZE;

        for (unsigned long i = index; i < mapping->nrpages; i++)
        {
            struct folio* nfolio = xa_load(&mapping->i_pages, i);
            if (nfolio)
            {   
                loff_t nextpos = folio_pos(nfolio);
                if (nextpos == lastpos + PAGE_SIZE)
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

        size_t len = max(pagesrem, 1) * PAGE_SIZE;
        char* buf = vmalloc(len);
        kxcspacefs_read(file, buf, len, &pos);

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
                kunmap_local(nbuf);
            }
        }

        vfree(buf);
    }
    folio_unlock(folio);
    return folio_size(folio);
}

static int kxcspacefs_writepages(struct address_space* mapping, struct writeback_control* wbc)
{
    struct file file;
    struct folio* folio = NULL;
	struct blk_plug plug;
	int error = 0;
	blk_start_plug(&plug);
	while ((folio = writeback_iter(mapping, wbc, folio, &error)))
	{
        if (folio)
        {
            file.f_inode = folio_inode(folio);
            char* nbuf = kmap_local_folio(folio, 0);
            loff_t pos = folio_pos(folio);
            size_t len = folio_size(folio);
            if (pos + len > folio_inode(folio)->i_size)
            {
                len = folio_inode(folio)->i_size - pos;
            }
            kxcspacefs_write(&file, nbuf, len, &pos);
            kunmap_local(nbuf);
            folio_unlock(folio);
        }
    }
	blk_finish_plug(&plug);
	return error;
}


#if KXCSPACEFS_AT_LEAST(6, 17, 0)
static int kxcspacefs_write_begin(const struct kiocb* kiocb, struct address_space* mapping, loff_t pos, unsigned len, struct folio** foliop, void** fsdata)
{
    struct inode* inode = file_inode(kiocb->ki_filp);
#elif KXCSPACEFS_AT_LEAST(6, 12, 0)
static int kxcspacefs_write_begin(struct file* file, struct address_space* mapping, loff_t pos, unsigned len, struct folio** foliop, void** fsdata)
{
    struct inode* inode = file_inode(file);
#endif
    struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    UNICODE_STRING* fn = inode->i_private;

    unsigned long long plen = pos + len;
    if (plen > inode->i_size)
    {
        down_write(KMCSFS->op_lock);
        unsigned long long index = get_filename_index(*fn, KMCSFS);
        if (find_block(sb->s_bdev, KMCSFS, index, plen - inode->i_size))
        {
            inode->i_size = plen;
            inode->i_blocks = (inode->i_size + 511) / 512;
        }
        else
        {
            up_write(KMCSFS->op_lock);
            return -ENOSPC;
        }
        up_write(KMCSFS->op_lock);
    }

	*foliop = __filemap_get_folio(mapping, pos / PAGE_SIZE, FGP_WRITEBEGIN, mapping_gfp_mask(mapping));
    struct buffer_head* bh = folio_buffers(*foliop);
    if (!bh)
    {
        bh = create_empty_buffers(*foliop, PAGE_SIZE, 0);
    }
    return 0;
}

static int kxcspacefs_write_end(const struct kiocb* kiocb, struct address_space* mapping, loff_t pos, unsigned len, unsigned copied, struct folio* folio, void* fsdata)
{
    copied = block_write_end(pos, len, copied, folio);
    folio_mark_dirty(folio);
    folio_unlock(folio);
	folio_put(folio);
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
    if (plen > inode->i_size)
    {
        down_write(KMCSFS->op_lock);
        unsigned long long index = get_filename_index(*fn, KMCSFS);
        if (find_block(sb->s_bdev, KMCSFS, index, plen - inode->i_size))
        {
            inode->i_size = plen;
            inode->i_blocks = (inode->i_size + 511) / 512;
        }
        else
        {
            up_write(KMCSFS->op_lock);
            return -ENOSPC;
        }
        up_write(KMCSFS->op_lock);
    }

    return inode->i_size;
}

const struct address_space_operations kxcspacefs_aops =
{
	.read_folio = kxcspacefs_read_folio,
	.writepages = kxcspacefs_writepages,
    .write_begin = kxcspacefs_write_begin,
	.write_end = kxcspacefs_write_end,
    .dirty_folio = filemap_dirty_folio,
    .bmap = kxcspacefs_bmap,
};

const struct file_operations kxcspacefs_file_ops =
{
    .owner = THIS_MODULE,
#if KXCSPACEFS_AT_LEAST(3, 16, 0)
    .read_iter = generic_file_read_iter,
    .write_iter = kxcspacefs_file_write_iter,
#else
    .read = kxcspacefs_read,
    .write = kxcspacefs_write,
#endif
#if KXCSPACEFS_AT_LEAST(6, 17, 0)
    .mmap_prepare = generic_file_mmap_prepare,
#else
    .mmap = generic_file_mmap,
#endif
    .open = kxcspacefs_open,
    .llseek = generic_file_llseek,
    .fsync = generic_file_fsync,
    .fallocate = kxcspacefs_fallocate,
};
