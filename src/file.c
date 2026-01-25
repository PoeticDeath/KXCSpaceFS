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
        loff_t lastpos = pos - 4096;

        for (unsigned long i = index; i < mapping->nrpages; i++)
        {
            struct folio* nfolio = xa_load(&mapping->i_pages, i);
            if (nfolio)
            {   
                loff_t nextpos = folio_pos(nfolio);
                if (nextpos == lastpos + 4096)
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

        size_t len = max(pagesrem, 1) * 4096;
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
                    memmove(nbuf, buf + i * 4096, 4096);
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
                memmove(nbuf, buf, 4096);
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
    struct folio *folio = NULL;
	struct blk_plug plug;
    char* buf = NULL;
    unsigned long long buflen = 0;
    unsigned long long bufstartpos = 0;
    unsigned long long buflastpos = 0;
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
            if (!buf)
            {
                buf = vmalloc(len);
                if (!buf)
                {
                    blk_finish_plug(&plug);
                    return -ENOMEM;
                }
                bufstartpos = pos;
                buflastpos = pos;
            }
            else
            {
                if (buflastpos != pos - folio_size(folio))
                {
                    kxcspacefs_write(&file, buf, buflen, &bufstartpos);
                    vfree(buf);
                    buf = vmalloc(len);
                    if (!buf)
                    {
                        blk_finish_plug(&plug);
                        return -ENOMEM;
                    }
                    bufstartpos = pos;
                    buflastpos = pos;
                    buflen = 0;
                }
                else
                {
                    char* tbuf = vmalloc(buflen + len);
                    if (!tbuf)
                    {
                        break;
                    }
                    memmove(tbuf, buf, buflen);
                    vfree(buf);
                    buf = tbuf;
                    buflastpos = pos;
                }
            }
            memmove(buf + buflen, nbuf, len);
            buflen += len;
            kunmap_local(nbuf);
            folio_unlock(folio);
        }
    }
    if (buf)
    {
        kxcspacefs_write(&file, buf, buflen, &bufstartpos);
        vfree(buf);
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
        }
        else
        {
            up_write(KMCSFS->op_lock);
            return -ENOSPC;
        }
        up_write(KMCSFS->op_lock);
    }

	*foliop = __filemap_get_folio(mapping, pos / 4096, FGP_WRITEBEGIN, mapping_gfp_mask(mapping));
    struct buffer_head* bh = folio_buffers(*foliop);
    if (!bh)
    {
        bh = create_empty_buffers(*foliop, 4096, 0);
        loff_t toff = pos - pos % 4096;
        kxcspacefs_read(kiocb->ki_filp, bh->b_data, 4096, &toff);
    }
    return 0;
}

static int kxcspacefs_write_end(const struct kiocb* kiocb, struct address_space* mapping, loff_t pos, unsigned len, unsigned copied, struct folio* folio, void* fsdata)
{
    copied = block_write_end(pos, len, copied, folio);

    struct file file;
    file.f_inode = folio_inode(folio);
    char* nbuf = kmap_local_folio(folio, 0);
    loff_t bpos = folio_pos(folio);
    size_t blen = folio_size(folio);
    if (bpos + blen > folio_inode(folio)->i_size)
    {
        blen = folio_inode(folio)->i_size - bpos;
    }
    kxcspacefs_write(&file, nbuf, blen, &bpos);
    kunmap_local(nbuf);
    
    folio_unlock(folio);
	folio_put(folio);
    return copied;
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
    .write_iter = generic_file_write_iter,
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
};
