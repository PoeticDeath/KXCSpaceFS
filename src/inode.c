#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fiemap.h>

#include "linuxfs.h"
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
        return ERR_PTR(-ENOMEM);
    }

    /* If inode is in cache, clean it */
    if (!(inode->i_state & I_NEW))
    {
        UNICODE_STRING* fn = inode->i_private;
        if (fn->Length > sizeof(WCHAR))
        {
            vfree(fn->Buffer);
            vfree(fn);
        }
    }

    inode->i_ino = index;
    inode->i_private = NULL;
    if (fn)
    {
        UNICODE_STRING* ofn = vmalloc(sizeof(UNICODE_STRING));
        if (!ofn)
        {
            pr_err("out of memory\n");
            ret = -ENOMEM;
            goto failed;
        }
        ofn->Length = fn->Length;
        ofn->Buffer = vmalloc(ofn->Length);
        if (!ofn->Buffer)
        {
            pr_err("out of memory\n");
            ret = -ENOMEM;
            vfree(ofn);
            goto failed;
        }
        memmove(ofn->Buffer, fn->Buffer, fn->Length);
        inode->i_private = ofn;
        inode->i_ino = KMCSFS->dict[dindex].hash;
    }

    inode->i_sb = sb;
    inode->i_op = &kxcspacefs_inode_ops;

    inode->i_mode = chmode(index, 0, *KMCSFS);
    i_uid_write(inode, chuid(index, 0, *KMCSFS, false));
    i_gid_write(inode, chgid(index, 0, *KMCSFS, false));
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

    inode->i_blocks = inode->i_size / 512;
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
        memmove(&inode->i_rdev, buf, sizeof(dev_t));
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
    return ERR_PTR(ret);
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
        return ERR_PTR(-ENAMETOOLONG);
    }

    /* Search for the file in directory */
    UNICODE_STRING* pfn = dir->i_private;
    UNICODE_STRING fn;
    fn.Length = pfn->Length + (pfn->Length > sizeof(WCHAR) ? sizeof(WCHAR) : 0) + dentry->d_name.len;
    fn.Buffer = vmalloc(fn.Length);
    if (!fn.Buffer)
    {
        return ERR_PTR(-ENOMEM);
    }
    memmove(fn.Buffer, pfn->Buffer, pfn->Length);
    fn.Buffer[pfn->Length > sizeof(WCHAR) ? pfn->Length : 0] = '/';
    memmove(fn.Buffer + (pfn->Length > sizeof(WCHAR) ? pfn->Length : 0) + 1, dentry->d_name.name, dentry->d_name.len);
    down_read(KMCSFS->op_lock);
    inode = kxcspacefs_iget(sb, 0, &fn);
    up_read(KMCSFS->op_lock);
    if (IS_ERR(inode))
    {
        return (void*)inode;
    }

    down_write(KMCSFS->op_lock);
    unsigned long long time = current_time(dir).tv_sec;
    chtime(get_filename_index(*pfn, KMCSFS), time, 1, *KMCSFS);
    dir->i_atime_sec = time;
    up_write(KMCSFS->op_lock);

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
    fn.Buffer = vmalloc(fn.Length);
    if (!fn.Buffer)
    {
        return ERR_PTR(-ENOMEM);
    }
    memmove(fn.Buffer, pfn->Buffer, pfn->Length);
    fn.Buffer[pfn->Length > sizeof(WCHAR) ? pfn->Length : 0] = '/';
    memmove(fn.Buffer + (pfn->Length > sizeof(WCHAR) ? pfn->Length : 0) + 1, dentry->d_name.name, dentry->d_name.len);

    down_write(KMCSFS->op_lock);
    int ret = create_file(sb->s_bdev, KMCSFS, fn, dir->i_gid.val, dir->i_uid.val, mode, current_time(dir).tv_sec);
    up_write(KMCSFS->op_lock);

    if (IS_ERR(ERR_PTR(ret)))
    {
        vfree(fn.Buffer);
        return ERR_PTR(ret);
    }

    down_read(KMCSFS->op_lock);
    inode = kxcspacefs_iget(sb, 0, &fn);
    up_read(KMCSFS->op_lock);
    vfree(fn.Buffer);
    if (IS_ERR(inode))
    {
        return inode;
    }

    down_write(KMCSFS->op_lock);
    unsigned long long time = current_time(dir).tv_sec;
    unsigned long long dir_index = get_filename_index(*pfn, KMCSFS);
    chtime(dir_index, time, 1, *KMCSFS);
    chtime(dir_index, time, 3, *KMCSFS);
    dir->i_atime_sec = time;
    dir->i_mtime_sec = time;
    up_write(KMCSFS->op_lock);

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
        return PTR_ERR(inode);
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
    fn.Buffer = vmalloc(fn.Length);
    if (!fn.Buffer)
    {
        return -ENOMEM;
    }
    memmove(fn.Buffer, pfn->Buffer, pfn->Length);
    fn.Buffer[pfn->Length > sizeof(WCHAR) ? pfn->Length : 0] = '/';
    memmove(fn.Buffer + (pfn->Length > sizeof(WCHAR) ? pfn->Length : 0) + 1, dentry->d_name.name, dentry->d_name.len);

    down_write(KMCSFS->op_lock);
    int ret = delete_file(sb->s_bdev, KMCSFS, fn, get_filename_index(fn, KMCSFS));

    unsigned long long time = current_time(dir).tv_sec;
    unsigned long long dir_index = get_filename_index(*pfn, KMCSFS);
    chtime(dir_index, time, 1, *KMCSFS);
    chtime(dir_index, time, 3, *KMCSFS);
    dir->i_atime_sec = time;
    dir->i_mtime_sec = time;
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
    UNICODE_STRING* olddir;
    olddir = old_dir->i_private;
    UNICODE_STRING* newdir;
    newdir = new_dir->i_private;
    UNICODE_STRING nfn;

    nfn.Length = newdir->Length + (newdir->Length > sizeof(WCHAR) ? sizeof(WCHAR) : 0) + new_dentry->d_name.len;
    nfn.Buffer = vmalloc(nfn.Length);
    if (!nfn.Buffer)
    {
        return -ENOMEM;
    }
    memmove(nfn.Buffer, newdir->Buffer, newdir->Length);
    nfn.Buffer[newdir->Length > sizeof(WCHAR) ? newdir->Length : 0] = '/';
    memmove(nfn.Buffer + (newdir->Length > sizeof(WCHAR) ? newdir->Length : 0) + 1, new_dentry->d_name.name, new_dentry->d_name.len);

    /* Fail if new_dentry exists */
    down_read(KMCSFS->op_lock);
    ret = PTR_ERR(kxcspacefs_iget(sb, 0, &nfn));
    up_read(KMCSFS->op_lock);
    if (ret)
    {
        if (flags & RENAME_NOREPLACE)
        {
            vfree(nfn.Buffer);
            return -EEXIST;
        }
        else
        {
            down_write(KMCSFS->op_lock);
            ret = delete_file(sb->s_bdev, KMCSFS, nfn, get_filename_index(nfn, KMCSFS));
            up_write(KMCSFS->op_lock);

            if (IS_ERR(ERR_PTR(ret)))
            {
                vfree(nfn.Buffer);
                return ret;
            }
        }
    }

    down_write(KMCSFS->op_lock);
    ret = rename_file(sb->s_bdev, KMCSFS, *oldfn, nfn);
    if (!IS_ERR(ERR_PTR(ret)))
    {
        unsigned long long dindex = FindDictEntry(KMCSFS->dict, KMCSFS->table, KMCSFS->tableend, KMCSFS->DictSize, nfn.Buffer, nfn.Length);
        KMCSFS->dict[dindex].inode = old_dentry->d_inode;
        vfree(oldfn->Buffer);
        oldfn->Length = nfn.Length;
        oldfn->Buffer = nfn.Buffer;

        unsigned long long time = current_time(old_dir).tv_sec;
        unsigned long long old_dir_index = get_filename_index(*olddir, KMCSFS);
        unsigned long long new_dir_index = get_filename_index(*newdir, KMCSFS);
        chtime(old_dir_index, time, 1, *KMCSFS);
        chtime(old_dir_index, time, 3, *KMCSFS);
        old_dir->i_atime_sec = time;
        old_dir->i_mtime_sec = time;
        chtime(new_dir_index, time, 1, *KMCSFS);
        chtime(new_dir_index, time, 3, *KMCSFS);
        new_dir->i_atime_sec = time;
        new_dir->i_mtime_sec = time;
        up_write(KMCSFS->op_lock);
    }
    else
    {
        vfree(nfn.Buffer);
        up_write(KMCSFS->op_lock);
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
        chuid(index, iattr->ia_uid.val, *KMCSFS, true);
        inode->i_uid.val = iattr->ia_uid.val;
    }

    if (iattr->ia_valid & ATTR_GID)
    {
        chgid(index, iattr->ia_gid.val, *KMCSFS, true);
        inode->i_gid.val = iattr->ia_gid.val;
    }

    if (iattr->ia_valid & ATTR_ATIME || iattr->ia_valid & ATTR_ATIME_SET)
    {
        chtime(index, iattr->ia_atime.tv_sec, 1, *KMCSFS);
        inode->i_atime_sec = iattr->ia_atime.tv_sec;
    }

    if (iattr->ia_valid & ATTR_MTIME || iattr->ia_valid & ATTR_MTIME_SET)
    {
        chtime(index, iattr->ia_mtime.tv_sec, 3, *KMCSFS);
        inode->i_mtime_sec = iattr->ia_mtime.tv_sec;
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

static int kxcspacefs_fiemap(struct inode* inode, struct fiemap_extent_info* fieinfo, unsigned long long start, unsigned long long len)
{
    struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    UNICODE_STRING* fn = inode->i_private;
    int ret = fiemap_prep(inode, fieinfo, start, &len, 0);
    if (IS_ERR(ERR_PTR(ret)))
    {
        return ret;
    }

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
                        if (filesize > start)
                        {
                            ret = fiemap_fill_next_extent(fieinfo, filesize - KMCSFS->sectorsize, KMCSFS->size - KMCSFS->sectorsize - (int3 + o) * KMCSFS->sectorsize, KMCSFS->sectorsize, maxsize > filesize ? 0 : FIEMAP_EXTENT_LAST);
                        }
					}
				}
				switch (cur)
				{
				case 0:
                    filesize += KMCSFS->sectorsize;
                    if (filesize > start)
                    {
                        ret = fiemap_fill_next_extent(fieinfo, filesize - KMCSFS->sectorsize, KMCSFS->size - KMCSFS->sectorsize - int0 * KMCSFS->sectorsize, KMCSFS->sectorsize, maxsize > filesize ? 0 : FIEMAP_EXTENT_LAST);
                    }
                    break;
				case 1:
					break;
				case 2:
					filesize += int2 - int1;
					break;
				}
                if (IS_ERR(ERR_PTR(ret)))
                {
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

    return ret;
}

static int kxcspacefs_mknod(struct mnt_idmap* id, struct inode* dir, struct dentry* dentry, umode_t mode, dev_t dev)
{
    struct super_block* sb = dir->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    int ret = kxcspacefs_create(id, dir, dentry, mode, 0);
    if (IS_ERR(ERR_PTR(ret)))
    {
        return ret;
    }

    struct file file;
    file.f_inode = dentry->d_inode;

    UNICODE_STRING* fn = dentry->d_inode->i_private;
    down_write(KMCSFS->op_lock);
    unsigned long long index = get_filename_index(*fn, KMCSFS);
    ret = find_block(sb->s_bdev, KMCSFS, index, sizeof(dev_t));
    if (!IS_ERR(ERR_PTR(ret)))
    {
        dentry->d_inode->i_size = sizeof(dev_t);
        unsigned long long bytes_written = 0;
        char buf[sizeof(dev_t)] = {0};
        memmove(buf, &dev, sizeof(dev_t));
        ret = write_file(sb->s_bdev, *KMCSFS, buf, 0, sizeof(dev_t), index, dentry->d_inode->i_size, &bytes_written, true);
    }
    up_write(KMCSFS->op_lock);
    init_special_inode(dentry->d_inode, mode, dev);
    return ret;
}

#if KXCSPACEFS_AT_LEAST(6, 17, 0)
static struct dentry* kxcspacefs_mkdir(struct mnt_idmap* id, struct inode* dir, struct dentry* dentry, umode_t mode)
{
    int ret = kxcspacefs_create(id, dir, dentry, mode | S_IFDIR, 0);
    if (IS_ERR(ERR_PTR(ret)))
    {
        return ERR_PTR(ret);
    }
    return dentry;
}
#elif KXCSPACEFS_AT_LEAST(6, 3, 0)
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
    if (IS_ERR(ERR_PTR(ret)))
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
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    unsigned int l = strlen(symname) + 1;
    UNICODE_STRING* pfn = dir->i_private;
    UNICODE_STRING fn;

    fn.Length = pfn->Length + (pfn->Length > sizeof(WCHAR) ? sizeof(WCHAR) : 0) + dentry->d_name.len;
    fn.Buffer = vmalloc(fn.Length);
    if (!fn.Buffer)
    {
        return -ENOMEM;
    }
    memmove(fn.Buffer, pfn->Buffer, pfn->Length);
    fn.Buffer[pfn->Length > sizeof(WCHAR) ? pfn->Length : 0] = '/';
    memmove(fn.Buffer + (pfn->Length > sizeof(WCHAR) ? pfn->Length : 0) + 1, dentry->d_name.name, dentry->d_name.len);

    struct inode* inode = kxcspacefs_new_inode(dir, dentry, S_IFLNK | S_IRWXUGO);
    if (IS_ERR(inode))
    {
        vfree(fn.Buffer);
        return PTR_ERR(inode);
    }
    d_instantiate(dentry, inode);

    down_write(KMCSFS->op_lock);
    unsigned long long index = get_filename_index(fn, KMCSFS);
    unsigned long long bytes_written = 0;
    write_file(sb->s_bdev, *KMCSFS, symname, 0, l, index, get_file_size(index, *KMCSFS), &bytes_written, true);
    up_write(KMCSFS->op_lock);
    vfree(fn.Buffer);
    return 0;
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
        return ERR_PTR(-ENOMEM);
    }
    
    unsigned long long bytes_read = 0;
    down_read(KMCSFS->op_lock);
    unsigned long long index = get_filename_index(*fn, KMCSFS);
    int ret = read_file(sb->s_bdev, *KMCSFS, data, 0, get_file_size(index, *KMCSFS), index, &bytes_read, true);
    up_read(KMCSFS->op_lock);
    if (IS_ERR(ERR_PTR(ret)))
    {
        kfree(data);
        return ERR_PTR(ret);
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
    .fiemap = kxcspacefs_fiemap,
    .mknod = kxcspacefs_mknod,
    .symlink = kxcspacefs_symlink,
};

static const struct inode_operations symlink_inode_ops =
{
    .get_link = kxcspacefs_get_link,
};
