#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mpage.h>
#include <linux/writeback.h>

#include "super.h"

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
    unsigned long long maxsize = get_file_size(index, *KMCSFS);
    maxsize -= maxsize % KMCSFS->sectorsize;
    unsigned long long loc = 0;
	if (index)
	{
		for (unsigned long long i = 0; i < KMCSFS->tablestrlen; i++)
		{
			if (KMCSFS->tablestr[i] == *".")
			{
				loc++;
				if (loc == index)
				{
					loc = i + 1;
					break;
				}
			}
		}
	}

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
					filesize += int2 - int1;
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

static int kxcspacefs_read_folio(struct file* file, struct folio* folio)
{
	return mpage_read_folio(folio, kxcspacefs_getfrag_block);
}

static void kxcspacefs_readahead(struct readahead_control* rac)
{
    mpage_readahead(rac, kxcspacefs_getfrag_block);
}

static int kxcspacefs_writepages(struct address_space* mapping, struct writeback_control* wbc)
{
	return mpage_writepages(mapping, wbc, kxcspacefs_getfrag_block);
}

#if KXCSPACEFS_AT_LEAST(6, 17, 0)
static int kxcspacefs_write_begin(const struct kiocb* kiocb, struct address_space* mapping, loff_t pos, unsigned len, struct folio** foliop, void** fsdata)
{
    struct inode* inode = file_inode(kiocb->ki_filp);
    struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    UNICODE_STRING* fn = inode->i_private;

    unsigned long long plen = pos + len;
    down_write(KMCSFS->op_lock);
    unsigned long long index = get_filename_index(*fn, KMCSFS);
    if (plen > inode->i_size)
    {
        if (find_block(sb->s_bdev, KMCSFS, index, plen - inode->i_size))
        {
            inode->i_size = plen;
        }
        else
        {
            up_write(KMCSFS->op_lock);
            return -ENOSPC;
        }
    }
    up_write(KMCSFS->op_lock);

	return block_write_begin(mapping, pos, len, foliop, kxcspacefs_getfrag_block);
}
#elif KXCSPACEFS_AT_LEAST(6, 12, 0)
static int kxcspacefs_write_begin(struct file* file, struct address_space* mapping, loff_t pos, unsigned len, struct folio** foliop, void** fsdata)
{
    struct inode* inode = file_inode(file);
    struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    UNICODE_STRING* fn = inode->i_private;

    unsigned long long plen = pos + len;
    down_write(KMCSFS->op_lock);
    unsigned long long index = get_filename_index(*fn, KMCSFS);
    if (plen > inode->i_size)
    {
        if (find_block(sb->s_bdev, KMCSFS, index, plen - inode->i_size))
        {
            inode->i_size = plen;
        }
        else
        {
            up_write(KMCSFS->op_lock);
            return -ENOSPC;
        }
    }
    up_write(KMCSFS->op_lock);

	return block_write_begin(mapping, pos, len, foliop, kxcspacefs_getfrag_block);
}
#else
static int kxcspacefs_write_begin(struct file* file, struct address_space* mapping, loff_t pos, unsigned len, struct page** pagep, void** fsdata)
{
    struct inode* inode = file_inode(file);
    struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    UNICODE_STRING* fn = inode->i_private;

    unsigned long long plen = pos + len;
    down_write(KMCSFS->op_lock);
    unsigned long long index = get_filename_index(*fn, KMCSFS);
    if (plen > inode->i_size)
    {
        if (find_block(sb->s_bdev, KMCSFS, index, plen - inode->i_size))
        {
            inode->i_size = plen;
        }
        else
        {
            up_write(KMCSFS->op_lock);
            return -ENOSPC;
        }
    }
    up_write(KMCSFS->op_lock);

	return block_write_begin(mapping, pos, len, pagep, kxcspacefs_getfrag_block);
}
#endif

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
    bytes_read = read_file(sb->s_bdev, *KMCSFS, buf, pos, len, get_filename_index(*fn, KMCSFS), &bytes_to_read);
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
        }
        else
        {
            up_write(KMCSFS->op_lock);
            return -ENOSPC;
        }
    }

    bytes_write = write_file(sb->s_bdev, *KMCSFS, buf, pos, len, index, inode->i_size, &bytes_to_write, false);
    if (!bytes_write)
    {
        /* successfully wrote data */
        bytes_write += bytes_to_write;
        len -= bytes_to_write;
        pos += bytes_to_write;
    }
    *ppos = pos;

    unsigned long long time = current_time(inode).tv_sec;
    chtime(index, time, 3, *KMCSFS);
    inode->i_mtime_sec = time;
    up_write(KMCSFS->op_lock);

    return bytes_write;
}

const struct address_space_operations kxcspacefs_aops =
{
	.invalidate_folio = block_invalidate_folio,
	.read_folio = kxcspacefs_read_folio,
    .readahead = kxcspacefs_readahead,
	.writepages = kxcspacefs_writepages,
	.write_begin = kxcspacefs_write_begin,
	.write_end = generic_write_end,
	.migrate_folio = buffer_migrate_folio,
    .dirty_folio = filemap_dirty_folio,
    .error_remove_folio = generic_error_remove_folio,
    .bmap = kxcspacefs_bmap,
};

const struct file_operations kxcspacefs_file_ops =
{
    .owner = THIS_MODULE,
    .read_iter = generic_file_read_iter,
    .write_iter = generic_file_write_iter,
#if KXCSPACEFS_AT_LEAST(6, 17, 0)
    .mmap_prepare = generic_file_mmap_prepare,
#endif
    .open = kxcspacefs_open,
    .read = kxcspacefs_read,
    .write = kxcspacefs_write,
    .llseek = generic_file_llseek,
    .fsync = generic_file_fsync,
    .splice_read = filemap_splice_read,
    .splice_write = iter_file_splice_write,
};
