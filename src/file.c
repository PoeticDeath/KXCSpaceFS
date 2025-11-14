#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mpage.h>

#include "super.h"

#include "Dict.h"
#include "cspacefs.h"

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
    bytes_read = read_file(sb->s_bdev, *KMCSFS, buf, pos, len, get_filename_index(*fn, KMCSFS), &bytes_to_read, false);
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

    if (pos > inode->i_size)
    {
        return 0;
    }

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
    up_write(KMCSFS->op_lock);
    if (!bytes_write)
    {
        /* successfully wrote data */
        bytes_write += bytes_to_write;
        len -= bytes_to_write;
        pos += bytes_to_write;
    }
    *ppos = pos;

    return bytes_write;
}

const struct address_space_operations kxcspacefs_aops = {};

const struct file_operations kxcspacefs_file_ops =
{
    .owner = THIS_MODULE,
    .open = kxcspacefs_open,
    .read = kxcspacefs_read,
    .write = kxcspacefs_write,
    .llseek = generic_file_llseek,
    .fsync = generic_file_fsync,
};
