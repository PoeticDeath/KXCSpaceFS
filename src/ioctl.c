// Copyright (c) Anthony Kerr 2026-

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "linuxfs.h"
#include "super.h"
#include "Dict.h"
#include "cspacefs.h"

static int ioctl_getlabel(struct file* file, char* __user user_label)
{
	char label[FSLABEL_MAX] = {0};
    struct inode* inode = file_inode(file);
	struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);

    UNICODE_STRING fn;
    char name = ':';
    fn.Buffer = &name;
    fn.Length = sizeof(WCHAR);
    down_read(KMCSFS->op_lock);
	unsigned long long index = get_filename_index(fn, KMCSFS);
    unsigned long long bytes_read = 0;
    read_file(sb->s_bdev, KMCSFS, label, 0, get_file_size(index, KMCSFS), index, &bytes_read);
    up_read(KMCSFS->op_lock);

	if (copy_to_user(user_label, label, sizeof(label)))
    {
		return -EFAULT;
    }

	return 0;
}

static int ioctl_setlabel(struct file* file, const char* __user user_label)
{
	size_t len;
	char new_label[FSLABEL_MAX] = {0};
	struct inode* inode = file_inode(file);
	struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);

	if (!capable(CAP_SYS_ADMIN))
    {
		return -EPERM;
    }

	/*
	 * Copy the maximum length allowed for any fs label with one more to
	 * find the required terminating null byte in order to test the
	 * label length. The on disk label doesn't need to be null terminated.
	 */
	if (copy_from_user(new_label, user_label, FSLABEL_MAX))
    {
		return -EFAULT;
    }

	len = strnlen(new_label, FSLABEL_MAX);
	if (len >= FSLABEL_MAX)
    {
		return -EINVAL;
    }

    UNICODE_STRING fn;
    char name = ':';
    fn.Buffer = &name;
    fn.Length = sizeof(WCHAR);
    down_write(KMCSFS->op_lock);
	unsigned long long index = get_filename_index(fn, KMCSFS);
    unsigned long long bytes_written = 0;
    unsigned long long size = get_file_size(index, KMCSFS);
	if (size != len)
	{
        if (size < len)
        {
            if (!find_block(sb->s_bdev, KMCSFS, index, len - size))
            {
                up_write(KMCSFS->op_lock);
                return -ENOSPC;
            }
        }
        else
        {
            dealloc(KMCSFS, index, size, len);
            if (len % KMCSFS->sectorsize)
            {
                if (!find_block(sb->s_bdev, KMCSFS, index, len % KMCSFS->sectorsize))
                {
                    up_write(KMCSFS->op_lock);
                    return -ENOSPC;
                }
            }
        }
    }
    write_file(sb->s_bdev, KMCSFS, new_label, 0, len, index, get_file_size(index, KMCSFS), &bytes_written, true);
    up_write(KMCSFS->op_lock);

	return 0;
}

long kxcspacefs_ioctl(struct file* file, unsigned int cmd, unsigned long arg)
{
    struct inode* inode = file_inode(file);
	struct super_block* sb = inode->i_sb;
	struct mnt_idmap* idmap = file_mnt_idmap(file);

    switch (cmd)
    {
	case FS_IOC_GETFSLABEL:
        return ioctl_getlabel(file, (void __user *)arg);
	case FS_IOC_SETFSLABEL:
        return ioctl_setlabel(file, (const void __user *)arg);
	default:
		return -ENOIOCTLCMD;
	}
}