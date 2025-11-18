#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "super.h"
#include "Dict.h"
#include "cspacefs.h"

static const struct inode_operations kxcspacefs_inode_ops;
static const struct inode_operations symlink_inode_ops;

/* Either return the inode that corresponds to a index or filename, if
 * it is already in the cache, or create a new inode object if it is not in the
 * cache.
 *
 * Note that this function is very similar to kxcspacefs_new_inode, except that
 * the requested inode is supposed to be allocated on-disk already. So do not
 * use this to create a completely new inode that has not been allocated on
 * disk.
 */
struct inode* kxcspacefs_iget(struct super_block* sb, unsigned long long index, UNICODE_STRING* fn)
{
    struct inode* inode = NULL;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    unsigned long long dindex = 0;
    int ret;

    if (fn)
    {
        if (fn->Buffer)
        {
            dindex = FindDictEntry(KMCSFS->dict, KMCSFS->table, KMCSFS->tableend, KMCSFS->DictSize, fn->Buffer, fn->Length);
            if (dindex)
            {
                if (KMCSFS->dict[dindex].inode)
                {
                    return KMCSFS->dict[dindex].inode;
                }
            }
            index = get_filename_index(*fn, KMCSFS);
        }
    }

    /* Fail if index is out of range */
    if (index >= KMCSFS->filecount || !index)
    {
        return 0;
    }

    /* Get a locked inode from Linux */
    inode = iget_locked(sb, index);
    if (!inode)
    {
        return -ENOMEM;
    }

    /* If inode is in cache, clean it */
    if (!(inode->i_state & I_NEW))
    {
        UNICODE_STRING* fn = inode->i_private;
        if (fn->Length > sizeof(WCHAR))
        {
            kfree(fn->Buffer);
            kfree(fn);
        }
    }

    inode->i_ino = index;
    inode->i_private = NULL;
    if (fn)
    {
        UNICODE_STRING* ofn = kzalloc(sizeof(UNICODE_STRING), GFP_KERNEL);
        if (!ofn)
        {
            pr_err("out of memory\n");
            ret = -ENOMEM;
            goto failed;
        }
        ofn->Length = fn->Length;
        ofn->Buffer = kzalloc(ofn->Length, GFP_KERNEL);
        if (!ofn->Buffer)
        {
            pr_err("out of memory\n");
            ret = -ENOMEM;
            kfree(ofn);
            goto failed;
        }
        memcpy(ofn->Buffer, fn->Buffer, fn->Length);
        inode->i_private = ofn;
        inode->i_ino = KMCSFS->dict[dindex].hash;
    }

    inode->i_sb = sb;
    inode->i_op = &kxcspacefs_inode_ops;

    inode->i_mode = chmode(index, 0, *KMCSFS);
    i_uid_write(inode, chuid(index, 0, *KMCSFS));
    i_gid_write(inode, chgid(index, 0, *KMCSFS));
    inode->i_size = get_file_size(index, *KMCSFS);

#if KXCSPACEFS_AT_LEAST(6, 6, 0)
    inode_set_ctime(inode, (time64_t) chtime(index, 0, 4, *KMCSFS), 0);
#else
    inode->i_ctime.tv_sec = (time64_t) chtime(index, 0, 4, *KMCSFS);
    inode->i_ctime.tv_nsec = 0;
#endif

#if KXCSPACEFS_AT_LEAST(6, 7, 0)
    inode_set_atime(inode, (time64_t) chtime(index, 0, 0, *KMCSFS), 0);
    inode_set_mtime(inode, (time64_t) chtime(index, 0, 2, *KMCSFS), 0);
#else
    inode->i_atime.tv_sec = (time64_t) chtime(index, 0, 0, *KMCSFS);
    inode->i_atime.tv_nsec = 0;
    inode->i_mtime.tv_sec = (time64_t) chtime(index, 0, 2, *KMCSFS);
    inode->i_mtime.tv_nsec = 0;
#endif

    inode->i_blocks = inode->i_size / KMCSFS->sectorsize;
    set_nlink(inode, 1);

    if (S_ISDIR(inode->i_mode))
    {
        inode->i_fop = &kxcspacefs_dir_ops;
    }
    else if (S_ISREG(inode->i_mode))
    {
        inode->i_fop = &kxcspacefs_file_ops;
        inode->i_mapping->a_ops = &kxcspacefs_aops;
    }
    else if (S_ISLNK(inode->i_mode))
    {
        inode->i_op = &symlink_inode_ops;
    }

    /* Unlock the inode to make it usable, if not found in cache */
    if (inode->i_state & I_NEW)
    {
        unlock_new_inode(inode);
    }

    if (S_ISCHR(inode->i_mode) | S_ISBLK(inode->i_mode) | S_ISFIFO(inode->i_mode))
    {
        unsigned long long bytes_read = 0;
        down_read(KMCSFS->op_lock);
        char buf[sizeof(dev_t)] = {0};
        read_file(sb->s_bdev, *KMCSFS, buf, 0, sizeof(dev_t), index, &bytes_read, true);
        memcpy(&inode->i_rdev, buf, sizeof(dev_t));
        up_read(KMCSFS->op_lock);
        init_special_inode(inode, inode->i_mode, inode->i_rdev);
    }

    if (dindex)
    {
        KMCSFS->dict[dindex].inode = inode;
    }

    return inode;

failed:
    iget_failed(inode);
    return ret;
}

/* Search for a dentry in dir.
 * Fills dentry with NULL if not found in dir, or with the corresponding inode
 * if found.
 * Returns NULL on success, indicating the dentry was successfully filled or
 * confirmed absent.
 */
static struct dentry* kxcspacefs_lookup(struct inode* dir, struct dentry* dentry, unsigned int flags)
{
    struct super_block* sb = dir->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    struct inode* inode = NULL;

    /* Check filename length */
    if (dentry->d_name.len > KXCSPACEFS_FILENAME_LEN)
    {
        return -ENAMETOOLONG;
    }

    /* Search for the file in directory */
    UNICODE_STRING* pfn = dir->i_private;
    UNICODE_STRING fn;
    fn.Length = pfn->Length + (pfn->Length > sizeof(WCHAR) ? sizeof(WCHAR) : 0) + dentry->d_name.len;
    fn.Buffer = kzalloc(fn.Length, GFP_KERNEL);
    if (!fn.Buffer)
    {
        return -ENOMEM;
    }
    memcpy(fn.Buffer, pfn->Buffer, pfn->Length);
    fn.Buffer[pfn->Length > sizeof(WCHAR) ? pfn->Length : 0] = '/';
    memcpy(fn.Buffer + (pfn->Length > sizeof(WCHAR) ? pfn->Length : 0) + 1, dentry->d_name.name, dentry->d_name.len);
    down_read(KMCSFS->op_lock);
    inode = kxcspacefs_iget(sb, 0, &fn);
    up_read(KMCSFS->op_lock);
    if (IS_ERR(inode))
    {
        return ERR_PTR(inode);
    }

    /* Fill the dentry with the inode */
    d_add(dentry, inode);

    return NULL;
}

/* Find and construct a new inode.
 *
 * @dir: the inode of the parent directory where the new inode is supposed to
 *       be attached to.
 * @mode: the mode information of the new inode
 *
 * This is a helper function for the inode operation "create" (implemented in
 * kxcspacefs_create()). It takes care of reserving an inode block on disk,
 * creating a VFS inode object (in memory), and
 * attaching filesystem-specific information to that VFS inode.
 */
static struct inode* kxcspacefs_new_inode(struct inode* dir, struct dentry* dentry, mode_t mode)
{
    struct inode* inode;
    struct super_block* sb = dir->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    UNICODE_STRING* pfn = dir->i_private;
    UNICODE_STRING fn;

    fn.Length = pfn->Length + (pfn->Length > sizeof(WCHAR) ? sizeof(WCHAR) : 0) + dentry->d_name.len;
    fn.Buffer = kzalloc(fn.Length, GFP_KERNEL);
    if (!fn.Buffer)
    {
        return -ENOMEM;
    }
    memcpy(fn.Buffer, pfn->Buffer, pfn->Length);
    fn.Buffer[pfn->Length > sizeof(WCHAR) ? pfn->Length : 0] = '/';
    memcpy(fn.Buffer + (pfn->Length > sizeof(WCHAR) ? pfn->Length : 0) + 1, dentry->d_name.name, dentry->d_name.len);

    down_write(KMCSFS->op_lock);
    int ret = create_file(sb->s_bdev, KMCSFS, fn, dir->i_gid.val, dir->i_uid.val, mode);
    up_write(KMCSFS->op_lock);

    if (IS_ERR(ret))
    {
        kfree(fn.Buffer);
        return ret;
    }

    down_read(KMCSFS->op_lock);
    inode = kxcspacefs_iget(sb, 0, &fn);
    up_read(KMCSFS->op_lock);
    kfree(fn.Buffer);
    if (IS_ERR(inode))
    {
        return inode;
    }

    return inode;
}

/* Create a file or directory in this way:
 *   - check filename length
 *   - create the new inode
 */
#if KXCSPACEFS_AT_LEAST(6, 3, 0)
static int kxcspacefs_create(struct mnt_idmap* id, struct inode* dir, struct dentry* dentry, umode_t mode, bool excl)
#elif KXCSPACEFS_AT_LEAST(5, 12, 0)
static int kxcspacefs_create(struct user_namespace* ns, struct inode* dir, struct dentry* dentry, umode_t mode, bool excl)
#else
static int kxcspacefs_create(struct inode* dir, struct dentry* dentry, umode_t mode, bool excl)
#endif
{
    struct inode* inode;

    /* Check filename length */
    if (strlen(dentry->d_name.name) > KXCSPACEFS_FILENAME_LEN)
    {
        return -ENAMETOOLONG;
    }

    /* Get a new free inode */
    inode = kxcspacefs_new_inode(dir, dentry, mode);
    if (IS_ERR(inode))
    {
        return inode;
    }

    /* setup dentry */
    d_instantiate(dentry, inode);

    return 0;
}

/* Remove the file */
static int kxcspacefs_unlink(struct inode* dir, struct dentry* dentry)
{
    struct super_block* sb = dir->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    UNICODE_STRING* pfn = dir->i_private;
    UNICODE_STRING fn;

    fn.Length = pfn->Length + (pfn->Length > sizeof(WCHAR) ? sizeof(WCHAR) : 0) + dentry->d_name.len;
    fn.Buffer = kzalloc(fn.Length, GFP_KERNEL);
    if (!fn.Buffer)
    {
        return -ENOMEM;
    }
    memcpy(fn.Buffer, pfn->Buffer, pfn->Length);
    fn.Buffer[pfn->Length > sizeof(WCHAR) ? pfn->Length : 0] = '/';
    memcpy(fn.Buffer + (pfn->Length > sizeof(WCHAR) ? pfn->Length : 0) + 1, dentry->d_name.name, dentry->d_name.len);

    down_write(KMCSFS->op_lock);
    int ret = delete_file(sb->s_bdev, KMCSFS, fn, get_filename_index(fn, KMCSFS));
    up_write(KMCSFS->op_lock);

    return ret;
}

#if KXCSPACEFS_AT_LEAST(6, 3, 0)
static int kxcspacefs_rename(struct mnt_idmap* id, struct inode* old_dir, struct dentry* old_dentry, struct inode* new_dir, struct dentry* new_dentry, unsigned int flags)
#elif KXCSPACEFS_AT_LEAST(5, 12, 0)
static int kxcspacefs_rename(struct user_namespace* ns, struct inode* old_dir, struct dentry* old_dentry, struct inode* new_dir, struct dentry* new_dentry, unsigned int flags)
#else
static int kxcspacefs_rename(struct inode* old_dir, struct dentry* old_dentry, struct inode* new_dir, struct dentry* new_dentry, unsigned int flags)
#endif
{
    struct super_block* sb = old_dir->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    int ret = 0;

    /* fail with these unsupported flags */
    if (flags & (RENAME_EXCHANGE | RENAME_WHITEOUT))
    {
        return -EINVAL;
    }

    /* Check if filename is not too long */
    if (strlen(new_dentry->d_name.name) > KXCSPACEFS_FILENAME_LEN)
    {
        return -ENAMETOOLONG;
    }

    /* Get old filename */
    UNICODE_STRING* oldfn;
    oldfn = old_dentry->d_inode->i_private;

    /* Calculate new filename */
    UNICODE_STRING* newdir;
    newdir = new_dir->i_private;
    UNICODE_STRING nfn;

    nfn.Length = newdir->Length + (newdir->Length > sizeof(WCHAR) ? sizeof(WCHAR) : 0) + new_dentry->d_name.len;
    nfn.Buffer = kzalloc(nfn.Length, GFP_KERNEL);
    if (!nfn.Buffer)
    {
        return -ENOMEM;
    }
    memcpy(nfn.Buffer, newdir->Buffer, newdir->Length);
    nfn.Buffer[newdir->Length > sizeof(WCHAR) ? newdir->Length : 0] = '/';
    memcpy(nfn.Buffer + (newdir->Length > sizeof(WCHAR) ? newdir->Length : 0) + 1, new_dentry->d_name.name, new_dentry->d_name.len);

    /* Fail if new_dentry exists */
    down_read(KMCSFS->op_lock);
    ret = kxcspacefs_iget(sb, 0, &nfn);
    up_read(KMCSFS->op_lock);
    if (ret)
    {
        if (flags & RENAME_NOREPLACE)
        {
            kfree(nfn.Buffer);
            return -EEXIST;
        }
        else
        {
            down_write(KMCSFS->op_lock);
            ret = delete_file(sb->s_bdev, KMCSFS, nfn, get_filename_index(nfn, KMCSFS));
            up_write(KMCSFS->op_lock);

            if (IS_ERR(ret))
            {
                kfree(nfn.Buffer);
                return ret;
            }
        }
    }

    down_write(KMCSFS->op_lock);
    ret = rename_file(sb->s_bdev, KMCSFS, *oldfn, nfn);
    up_write(KMCSFS->op_lock);
    if (!IS_ERR(ret))
    {
        unsigned long long dindex = FindDictEntry(KMCSFS->dict, KMCSFS->table, KMCSFS->tableend, KMCSFS->DictSize, nfn.Buffer, nfn.Length);
        KMCSFS->dict[dindex].inode = old_dentry->d_inode;
        kfree(oldfn->Buffer);
        oldfn->Length = nfn.Length;
        oldfn->Buffer = nfn.Buffer;
    }
    else
    {
        kfree(nfn.Buffer);
    }
    return ret;
}

static int kxcspacefs_setattr(struct mnt_idmap* id, struct dentry* dentry, struct iattr* iattr)
{
    struct inode* inode = d_inode(dentry);
    struct super_block* sb = inode->i_sb;
	KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    UNICODE_STRING* fn = inode->i_private;

	int ret = setattr_prepare(id, dentry, iattr);
	if (ret)
    {
		return ret;
    }

    down_write(KMCSFS->op_lock);
    unsigned long long index = get_filename_index(*fn, KMCSFS);

    if (iattr->ia_valid & ATTR_MODE)
    {
        chmode(index, iattr->ia_mode, *KMCSFS);
        inode->i_mode = iattr->ia_mode;
    }

    if (iattr->ia_valid & ATTR_UID)
    {
        chuid(index, iattr->ia_uid.val, *KMCSFS);
        inode->i_uid.val = iattr->ia_uid.val;
    }

    if (iattr->ia_valid & ATTR_GID)
    {
        chgid(index, iattr->ia_gid.val, *KMCSFS);
        inode->i_gid.val = iattr->ia_gid.val;
    }

	if (S_ISREG(inode->i_mode) && (iattr->ia_valid & ATTR_SIZE))
    {
        unsigned long long size = get_file_size(index, *KMCSFS);
		if (size != iattr->ia_size)
		{
            if (size < iattr->ia_size)
            {
                if (!find_block(sb->s_bdev, KMCSFS, index, iattr->ia_size - size))
                {
                    up_write(KMCSFS->op_lock);
                    return -ENOMEM;
                }
            }
            else
            {
                dealloc(KMCSFS, index, size, iattr->ia_size);
            }
            inode->i_size = get_file_size(index, *KMCSFS);
        }
	}
    up_write(KMCSFS->op_lock);

	if (iattr->ia_valid)
    {
		setattr_copy(id, inode, iattr);
	}

	return ret;
}

static int kxcspacefs_mknod(struct mnt_idmap* id, struct inode* dir, struct dentry* dentry, umode_t mode, dev_t dev)
{
    struct super_block* sb = dir->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    int ret = kxcspacefs_create(id, dir, dentry, mode, 0);
    if (IS_ERR(ret))
    {
        return ret;
    }

    struct file file;
    file.f_inode = dentry->d_inode;

    loff_t pos = 0;
    UNICODE_STRING* fn = dentry->d_inode->i_private;
    down_write(KMCSFS->op_lock);
    unsigned long long index = get_filename_index(*fn, KMCSFS);
    ret = find_block(sb->s_bdev, KMCSFS, index, sizeof(dev_t));
    if (!IS_ERR(ret))
    {
        dentry->d_inode->i_size = sizeof(dev_t);
        unsigned long long bytes_written = 0;
        char buf[sizeof(dev_t)] = {0};
        memcpy(buf, &dev, sizeof(dev_t));
        ret = write_file(sb->s_bdev, *KMCSFS, buf, 0, sizeof(dev_t), index, dentry->d_inode->i_size, &bytes_written, true);
    }
    up_write(KMCSFS->op_lock);
    init_special_inode(dentry->d_inode, mode, dev);
    return ret;
}

#if KXCSPACEFS_AT_LEAST(6, 3, 0)
static int kxcspacefs_mkdir(struct mnt_idmap* id, struct inode* dir, struct dentry* dentry, umode_t mode)
{
    return kxcspacefs_create(id, dir, dentry, mode | S_IFDIR, 0);
}
#elif KXCSPACEFS_AT_LEAST(5, 12, 0)
static int kxcspacefs_mkdir(struct user_namespace* ns, struct inode* dir, struct dentry* dentry, umode_t mode)
{
    return kxcspacefs_create(ns, dir, dentry, mode | S_IFDIR, 0);
}
#else
static int kxcspacefs_mkdir(struct inode* dir, struct dentry* dentry, umode_t mode)
{
    return kxcspacefs_create(dir, dentry, mode | S_IFDIR, 0);
}
#endif

static int kxcspacefs_rmdir(struct inode* dir, struct dentry* dentry)
{
    struct super_block* sb = dir->i_sb;

    /* If the directory is not empty, fail */
    int ret = kxcspacefs_iterate((void*)dentry->d_inode, NULL);
    if (IS_ERR(ret))
    {
        return ret;
    }

    /* Remove directory with unlink */
    return kxcspacefs_unlink(dir, dentry);
}

#if KXCSPACEFS_AT_LEAST(6, 3, 0)
static int kxcspacefs_symlink(struct mnt_idmap* id, struct inode* dir, struct dentry* dentry, const char* symname)
#elif KXCSPACEFS_AT_LEAST(5, 12, 0)
static int kxcspacefs_symlink(struct user_namespace* ns, struct inode* dir, struct dentry* dentry, const char* symname)
#else
static int kxcspacefs_symlink(struct inode* dir, struct dentry* dentry, const char* symname)
#endif
{
    struct super_block* sb = dir->i_sb;
    unsigned int l = strlen(symname) + 1;

    struct inode* inode = kxcspacefs_new_inode(dir, dentry, S_IFLNK | S_IRWXUGO);
    if (IS_ERR(inode))
    {
        return inode;
    }

    struct file file;
    file.f_inode = inode;

    loff_t pos = 0;
    return kxcspacefs_write(&file, symname, l, &pos);
}

static const char* kxcspacefs_get_link(struct dentry* dentry, struct inode* inode, struct delayed_call* done)
{
    struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    UNICODE_STRING* fn;
    fn = inode->i_private;

    uint8_t* data = kzalloc(inode->i_size, GFP_KERNEL);
    if (!data)
    {
        return -ENOMEM;
    }

    unsigned long long bytes_read = 0;
    down_read(KMCSFS->op_lock);
    int ret = read_file(sb->s_bdev, *KMCSFS, data, 0, inode->i_size, get_filename_index(*fn, KMCSFS), &bytes_read, false);
    up_read(KMCSFS->op_lock);
    if (IS_ERR(ret))
    {
        return ret;
    }

    return data;
}

static const struct inode_operations kxcspacefs_inode_ops =
{
    .lookup = kxcspacefs_lookup,
    .create = kxcspacefs_create,
    .unlink = kxcspacefs_unlink,
    .mkdir = kxcspacefs_mkdir,
    .rmdir = kxcspacefs_rmdir,
    .rename = kxcspacefs_rename,
    .setattr = kxcspacefs_setattr,
    .mknod = kxcspacefs_mknod,
    .symlink = kxcspacefs_symlink,
};

static const struct inode_operations symlink_inode_ops =
{
    .get_link = kxcspacefs_get_link,
};
