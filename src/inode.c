#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "bitmap.h"
#include "super.h"
#include "Dict.h"
#include "cspacefs.h"

static const struct inode_operations kxcspacefs_inode_ops;
static const struct inode_operations symlink_inode_ops;

/* Either return the inode that corresponds to a given inode number (ino), if
 * it is already in the cache, or create a new inode object if it is not in the
 * cache.
 *
 * Note that this function is very similar to simplefs_new_inode, except that
 * the requested inode is supposed to be allocated on-disk already. So do not
 * use this to create a completely new inode that has not been allocated on
 * disk.
 */
struct inode* kxcspacefs_iget(struct super_block* sb, unsigned long long index, UNICODE_STRING* fn)
{
    struct inode* inode = NULL;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    int ret;

    if (fn)
    {
        if (fn->Buffer)
        {
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

    /* If inode is in cache, return it */
    if (!(inode->i_state & I_NEW))
    {
        return inode;
    }

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
    }

    inode->i_ino = index;
    inode->i_sb = sb;
    inode->i_op = &kxcspacefs_inode_ops;

    inode->i_mode = chmode(index, 0, *KMCSFS);
    i_uid_write(inode, chuid(index, 0, *KMCSFS));
    i_gid_write(inode, chgid(index, 0, *KMCSFS));
    inode->i_size = get_file_size(index, *KMCSFS);

#if SIMPLEFS_AT_LEAST(6, 6, 0)
    inode_set_ctime(inode, (time64_t) chtime(index, 0, 4, *KMCSFS), 0);
#else
    inode->i_ctime.tv_sec = (time64_t) chtime(index, 0, 4, *KMCSFS);
    inode->i_ctime.tv_nsec = 0;
#endif

#if SIMPLEFS_AT_LEAST(6, 7, 0)
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
        //ci->ei_block = le32_to_cpu(cinode->ei_block);
        inode->i_fop = &kxcspacefs_dir_ops;
    }
    else if (S_ISREG(inode->i_mode))
    {
        //ci->ei_block = le32_to_cpu(cinode->ei_block);
        inode->i_fop = &kxcspacefs_file_ops;
        inode->i_mapping->a_ops = &kxcspacefs_aops;
    }
    else if (S_ISLNK(inode->i_mode))
    {
        //strncpy(ci->i_data, cinode->i_data, sizeof(ci->i_data));
        //inode->i_link = ci->i_data;
        inode->i_op = &symlink_inode_ops;
    }

    /* Unlock the inode to make it usable */
    unlock_new_inode(inode);

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
    if (dentry->d_name.len > SIMPLEFS_FILENAME_LEN)
    {
        return -ENAMETOOLONG;
    }

    /* Search for the file in directory */
    UNICODE_STRING* pfn = dir->i_private;
    UNICODE_STRING fn;
    fn.Length = pfn->Length + sizeof(WCHAR) + dentry->d_name.len;
    fn.Buffer = kzalloc(fn.Length, GFP_KERNEL);
    if (!fn.Buffer)
    {
        return -ENOMEM;
    }
    memcpy(fn.Buffer, pfn->Buffer, pfn->Length);
    fn.Buffer[pfn->Length] = '/';
    memcpy(fn.Buffer + pfn->Length + 1, dentry->d_name.name, dentry->d_name.len);
    down_read(KMCSFS->op_lock);
    inode = kxcspacefs_iget(sb, 0, &fn);
    up_read(KMCSFS->op_lock);
    if (IS_ERR(inode))
    {
        return ERR_PTR(inode);
    }

    /* Update directory access time */
/*#if SIMPLEFS_AT_LEAST(6, 7, 0)
    inode_set_atime_to_ts(dir, current_time(dir));
#else
    dir->i_atime = current_time(dir);
#endif

    mark_inode_dirty(dir);*/

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
 * simplefs_create()). It takes care of reserving an inode block on disk (by
 * modifying the inode bitmap), creating a VFS inode object (in memory), and
 * attaching filesystem-specific information to that VFS inode.
 */
static struct inode* kxcspacefs_new_inode(struct inode* dir, struct dentry* dentry, mode_t mode)
{
    struct inode* inode;
    struct super_block* sb = dir->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    UNICODE_STRING* pfn = dir->i_private;
    UNICODE_STRING fn;

    fn.Length = pfn->Length + sizeof(WCHAR) + dentry->d_name.len;
    fn.Buffer = kzalloc(fn.Length, GFP_KERNEL);
    if (!fn.Buffer)
    {
        return -ENOMEM;
    }
    memcpy(fn.Buffer, pfn->Buffer, pfn->Length);
    fn.Buffer[pfn->Length] = '/';
    memcpy(fn.Buffer + pfn->Length + 1, dentry->d_name.name, dentry->d_name.len);

    /* Check mode before doing anything to avoid undoing everything */
    if (!S_ISDIR(mode) && !S_ISREG(mode) && !S_ISLNK(mode))
    {
        pr_err("File type not supported (only directory, regular file and symlink supported)\n");
        kfree(fn.Buffer);
        return -EINVAL;
    }

    int ret = create_file(sb->s_bdev, KMCSFS, fn, dir->i_gid.val, dir->i_uid.val, mode);
    if (IS_ERR(ret))
    {
        kfree(fn.Buffer);
        return ret;
    }

    inode = kxcspacefs_iget(sb, 0, &fn);
    kfree(fn.Buffer);
    if (IS_ERR(inode))
    {
        return inode;
    }

    return inode;
}

static uint32_t simplefs_get_available_ext_idx(
    int *dir_nr_files,
    struct simplefs_file_ei_block *eblock)
{
    int ei = 0;
    uint32_t first_empty_blk = -1;
    for (ei = 0; ei < SIMPLEFS_MAX_EXTENTS; ei++) {
        if (eblock->extents[ei].ee_start &&
            eblock->extents[ei].nr_files != SIMPLEFS_FILES_PER_EXT) {
            first_empty_blk = ei;
            break;
        } else if (!eblock->extents[ei].ee_start) {
            if (first_empty_blk == -1)
                first_empty_blk = ei;
        } else {
            *dir_nr_files -= eblock->extents[ei].nr_files;
            if (first_empty_blk == -1 && !*dir_nr_files)
                first_empty_blk = ei + 1;
        }
        if (!*dir_nr_files)
            break;
    }
    return first_empty_blk;
}

static int simplefs_put_new_ext(struct super_block *sb,
                                uint32_t ei,
                                struct simplefs_file_ei_block *eblock)
{
    int bno, bi;
    struct buffer_head *bh;
    struct simplefs_dir_block *dblock;
    bno = get_free_blocks(sb, SIMPLEFS_MAX_BLOCKS_PER_EXTENT);
    if (!bno)
        return -ENOSPC;

    eblock->extents[ei].ee_start = bno;
    eblock->extents[ei].ee_len = SIMPLEFS_MAX_BLOCKS_PER_EXTENT;
    eblock->extents[ei].ee_block =
        ei ? eblock->extents[ei - 1].ee_block + eblock->extents[ei - 1].ee_len
           : 0;
    eblock->extents[ei].nr_files = 0;

    /* clear the ext block*/
    /* TODO: fix from 8 to dynamic value */
    for (bi = 0; bi < eblock->extents[ei].ee_len; bi++) {
        bh = sb_bread(sb, eblock->extents[ei].ee_start + bi);
        if (!bh)
            return -EIO;

        dblock = (struct simplefs_dir_block *) bh->b_data;
        memset(dblock, 0, sizeof(struct simplefs_dir_block));
        dblock->files[0].nr_blk = SIMPLEFS_FILES_PER_BLOCK;
        brelse(bh);
    }
    return 0;
}

static void simplefs_set_file_into_dir(struct simplefs_dir_block *dblock,
                                       uint32_t inode_no,
                                       const char *name)
{
    int fi;
    if (dblock->nr_files != 0 && dblock->files[0].inode != 0) {
        for (fi = 0; fi < SIMPLEFS_FILES_PER_BLOCK - 1; fi++) {
            if (dblock->files[fi].nr_blk != 1)
                break;
        }
        dblock->files[fi + 1].inode = inode_no;
        dblock->files[fi + 1].nr_blk = dblock->files[fi].nr_blk - 1;
        strncpy(dblock->files[fi + 1].filename, name, SIMPLEFS_FILENAME_LEN);
        dblock->files[fi].nr_blk = 1;
    } else if (dblock->nr_files == 0) {
        dblock->files[fi].inode = inode_no;
        strncpy(dblock->files[fi].filename, name, SIMPLEFS_FILENAME_LEN);
    } else {
        dblock->files[0].inode = inode_no;
        strncpy(dblock->files[fi].filename, name, SIMPLEFS_FILENAME_LEN);
    }
    dblock->nr_files++;
}

/* Create a file or directory in this way:
 *   - check filename length and if the parent directory is not full
 *   - create the new inode (allocate inode and blocks)
 *   - cleanup index block of the new inode
 *   - add new file/directory in parent index
 */
#if SIMPLEFS_AT_LEAST(6, 3, 0)
static int kxcspacefs_create(struct mnt_idmap* id, struct inode* dir, struct dentry* dentry, umode_t mode, bool excl)
#elif SIMPLEFS_AT_LEAST(5, 12, 0)
static int kxcspacefs_create(struct user_namespace* ns, struct inode* dir, struct dentry* dentry, umode_t mode, bool excl)
#else
static int kxcspacefs_create(struct inode* dir, struct dentry* dentry, umode_t mode, bool excl)
#endif
{
    struct inode* inode;

    /* Check filename length */
    if (strlen(dentry->d_name.name) > SIMPLEFS_FILENAME_LEN)
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

static int simplefs_remove_from_dir(struct inode *dir, struct dentry *dentry)
{
    struct super_block *sb = dir->i_sb;
    struct inode *inode = d_inode(dentry);
    struct buffer_head *bh = NULL, *bh2 = NULL;
    struct simplefs_file_ei_block *eblock = NULL;
    struct simplefs_dir_block *dirblk = NULL;
    int ei = 0, bi = 0, fi = 0;
    int ret = 0, found = false;

    /* Read parent directory index */
    bh = sb_bread(sb, SIMPLEFS_INODE(dir)->ei_block);
    if (!bh)
        return -EIO;

    eblock = (struct simplefs_file_ei_block *) bh->b_data;

    int dir_nr_files = eblock->nr_files;
    for (ei = 0; dir_nr_files; ei++) {
        if (eblock->extents[ei].ee_start) {
            dir_nr_files -= eblock->extents[ei].nr_files;
            for (bi = 0; bi < eblock->extents[ei].ee_len; bi++) {
                bh2 = sb_bread(sb, eblock->extents[ei].ee_start + bi);
                if (!bh2) {
                    ret = -EIO;
                    goto release_bh;
                }
                dirblk = (struct simplefs_dir_block *) bh2->b_data;
                int blk_nr_files = dirblk->nr_files;
                for (fi = 0; blk_nr_files && fi < SIMPLEFS_FILES_PER_BLOCK;) {
                    if (dirblk->files[fi].inode) {
                        if (dirblk->files[fi].inode == inode->i_ino &&
                            !strcmp(dirblk->files[fi].filename,
                                    dentry->d_name.name)) {
                            found = true;
                            dirblk->files[fi].inode = 0;
                            /* merge the empty data */
                            for (int i = fi - 1; i >= 0; i--) {
                                if (dirblk->files[i].inode != 0 || i == 0) {
                                    dirblk->files[i].nr_blk +=
                                        dirblk->files[fi].nr_blk;
                                    break;
                                }
                            }
                            dirblk->nr_files--;
                            eblock->extents[ei].nr_files--;
                            eblock->nr_files--;
                            mark_buffer_dirty(bh2);
                            brelse(bh2);
                            found = true;
                            goto found_data;
                        }
                        blk_nr_files--;
                    }
                    fi += dirblk->files[fi].nr_blk;
                }
                brelse(bh2);
            }
        }
    }
found_data:
    if (found) {
        mark_buffer_dirty(bh);
    }
release_bh:
    brelse(bh);
    return ret;
}

/* Remove a link for a file including the reference in the parent directory.
 * If link count is 0, destroy file in this way:
 *   - remove the file from its parent directory.
 *   - cleanup blocks containing data
 *   - cleanup file index block
 *   - cleanup inode
 */
static int kxcspacefs_unlink(struct inode* dir, struct dentry* dentry)
{
    struct super_block* sb = dir->i_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);
    UNICODE_STRING* pfn = dir->i_private;
    UNICODE_STRING fn;

    fn.Length = pfn->Length + sizeof(WCHAR) + dentry->d_name.len;
    fn.Buffer = kzalloc(fn.Length, GFP_KERNEL);
    if (!fn.Buffer)
    {
        return -ENOMEM;
    }
    memcpy(fn.Buffer, pfn->Buffer, pfn->Length);
    fn.Buffer[pfn->Length] = '/';
    memcpy(fn.Buffer + pfn->Length + 1, dentry->d_name.name, dentry->d_name.len);

    return delete_file(sb->s_bdev, KMCSFS, fn, get_filename_index(fn, KMCSFS));
}

#if SIMPLEFS_AT_LEAST(6, 3, 0)
static int kxcspacefs_rename(struct mnt_idmap* id, struct inode* old_dir, struct dentry* old_dentry, struct inode* new_dir, struct dentry* new_dentry, unsigned int flags)
#elif SIMPLEFS_AT_LEAST(5, 12, 0)
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
    if (strlen(new_dentry->d_name.name) > SIMPLEFS_FILENAME_LEN)
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

    nfn.Length = newdir->Length + sizeof(WCHAR) + new_dentry->d_name.len;
    nfn.Buffer = kzalloc(nfn.Length, GFP_KERNEL);
    if (!nfn.Buffer)
    {
        return -ENOMEM;
    }
    memcpy(nfn.Buffer, newdir->Buffer, newdir->Length);
    nfn.Buffer[newdir->Length] = '/';
    memcpy(nfn.Buffer + newdir->Length + 1, new_dentry->d_name.name, new_dentry->d_name.len);

    /* Fail if new_dentry exists */
    if (kxcspacefs_iget(sb, 0, &nfn))
    {
        if (flags & RENAME_NOREPLACE)
        {
            kfree(nfn.Buffer);
            return -EEXIST;
        }
        else
        {
            ret = delete_file(sb->s_bdev, KMCSFS, nfn, get_filename_index(nfn, KMCSFS));
            if (IS_ERR(ret))
            {
                kfree(nfn.Buffer);
                return ret;
            }
        }
    }

    ret = rename_file(sb->s_bdev, KMCSFS, *oldfn, nfn);
    kfree(nfn.Buffer);
    return ret;
}

#if SIMPLEFS_AT_LEAST(6, 3, 0)
static int kxcspacefs_mkdir(struct mnt_idmap* id, struct inode* dir, struct dentry* dentry, umode_t mode)
{
    return kxcspacefs_create(id, dir, dentry, mode | S_IFDIR, 0);
}
#elif SIMPLEFS_AT_LEAST(5, 12, 0)
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

static int simplefs_link(struct dentry *old_dentry,
                         struct inode *dir,
                         struct dentry *dentry)
{
    struct inode *old_inode = d_inode(old_dentry);
    struct super_block *sb = old_inode->i_sb;
    struct simplefs_inode_info *ci_dir = SIMPLEFS_INODE(dir);
    struct simplefs_file_ei_block *eblock = NULL;
    struct simplefs_dir_block *dblock;
    struct buffer_head *bh = NULL, *bh2 = NULL;
    int ret = 0, alloc = false;
    int ei = 0, bi = 0;
    uint32_t avail;

    bh = sb_bread(sb, ci_dir->ei_block);
    if (!bh)
        return -EIO;

    eblock = (struct simplefs_file_ei_block *) bh->b_data;
    if (eblock->nr_files == SIMPLEFS_MAX_SUBFILES) {
        ret = -EMLINK;
        printk(KERN_INFO "directory is full");
        goto end;
    }

    int dir_nr_files = eblock->nr_files;
    avail = simplefs_get_available_ext_idx(&dir_nr_files, eblock);

    /* if there is not any empty space, alloc new one */
    if (!dir_nr_files && !eblock->extents[avail].ee_start) {
        ret = simplefs_put_new_ext(sb, avail, eblock);
        switch (ret) {
        case -ENOSPC:
            ret = -ENOSPC;
            goto end;
        case -EIO:
            ret = -EIO;
            goto put_block;
        }
        alloc = true;
    }

    /* TODO: fix from 8 to dynamic value */
    /* Find which simplefs_dir_block has free space */
    for (bi = 0; bi < eblock->extents[avail].ee_len; bi++) {
        bh2 = sb_bread(sb, eblock->extents[avail].ee_start + bi);
        if (!bh2) {
            ret = -EIO;
            goto put_block;
        }
        dblock = (struct simplefs_dir_block *) bh2->b_data;
        if (dblock->nr_files != SIMPLEFS_FILES_PER_BLOCK)
            break;
        else
            brelse(bh2);
    }

    /* write the file info into simplefs_dir_block */
    simplefs_set_file_into_dir(dblock, old_inode->i_ino, dentry->d_name.name);

    eblock->nr_files++;
    mark_buffer_dirty(bh2);
    mark_buffer_dirty(bh);
    brelse(bh2);
    brelse(bh);

    inode_inc_link_count(old_inode);
    ihold(old_inode);
    d_instantiate(dentry, old_inode);
    return ret;

put_block:
    if (alloc && eblock->extents[ei].ee_start) {
        put_blocks(KXCSPACEFS_SB(sb), eblock->extents[ei].ee_start,
                   eblock->extents[ei].ee_len);
        memset(&eblock->extents[ei], 0, sizeof(struct simplefs_extent));
    }
end:
    brelse(bh);
    return ret;
}

#if SIMPLEFS_AT_LEAST(6, 3, 0)
static int simplefs_symlink(struct mnt_idmap *id,
                            struct inode *dir,
                            struct dentry *dentry,
                            const char *symname)
#elif SIMPLEFS_AT_LEAST(5, 12, 0)
static int simplefs_symlink(struct user_namespace *ns,
                            struct inode *dir,
                            struct dentry *dentry,
                            const char *symname)
#else
static int simplefs_symlink(struct inode *dir,
                            struct dentry *dentry,
                            const char *symname)
#endif
{
    struct super_block *sb = dir->i_sb;
    unsigned int l = strlen(symname) + 1;
    struct inode *inode = kxcspacefs_new_inode(dir, dentry, S_IFLNK | S_IRWXUGO);
    struct simplefs_inode_info *ci = SIMPLEFS_INODE(inode);
    struct simplefs_inode_info *ci_dir = SIMPLEFS_INODE(dir);
    struct simplefs_file_ei_block *eblock = NULL;
    struct simplefs_dir_block *dblock = NULL;
    struct buffer_head *bh = NULL, *bh2 = NULL;
    int ret = 0, alloc = false;
    int ei = 0, bi = 0;
    uint32_t avail;

    /* Check if symlink content is not too long */
    if (l > sizeof(ci->i_data))
        return -ENAMETOOLONG;

    /* fill directory data block */
    bh = sb_bread(sb, ci_dir->ei_block);
    if (!bh)
        return -EIO;
    eblock = (struct simplefs_file_ei_block *) bh->b_data;

    if (eblock->nr_files == SIMPLEFS_MAX_SUBFILES) {
        ret = -EMLINK;
        printk(KERN_INFO "directory is full");
        goto end;
    }

    int dir_nr_files = eblock->nr_files;
    avail = simplefs_get_available_ext_idx(&dir_nr_files, eblock);

    /* if there is not any empty space, alloc new one */
    if (!dir_nr_files && !eblock->extents[avail].ee_start) {
        ret = simplefs_put_new_ext(sb, avail, eblock);
        switch (ret) {
        case -ENOSPC:
            ret = -ENOSPC;
            goto end;
        case -EIO:
            ret = -EIO;
            goto put_block;
        }
        alloc = true;
    }

    /* TODO: fix from 8 to dynamic value */
    /* Find which simplefs_dir_block has free space */
    for (bi = 0; bi < eblock->extents[avail].ee_len; bi++) {
        bh2 = sb_bread(sb, eblock->extents[avail].ee_start + bi);
        if (!bh2) {
            ret = -EIO;
            goto put_block;
        }
        dblock = (struct simplefs_dir_block *) bh2->b_data;
        if (dblock->nr_files != SIMPLEFS_FILES_PER_BLOCK)
            break;
        else
            brelse(bh2);
    }

    /* write the file info into simplefs_dir_block */
    simplefs_set_file_into_dir(dblock, inode->i_ino, dentry->d_name.name);

    eblock->nr_files++;
    mark_buffer_dirty(bh2);
    mark_buffer_dirty(bh);
    brelse(bh2);
    brelse(bh);

    inode->i_link = (char *) ci->i_data;
    memcpy(inode->i_link, symname, l);
    inode->i_size = l - 1;
    mark_inode_dirty(inode);
    d_instantiate(dentry, inode);
    return 0;

put_block:
    if (alloc && eblock->extents[ei].ee_start) {
        put_blocks(KXCSPACEFS_SB(sb), eblock->extents[ei].ee_start,
                   eblock->extents[ei].ee_len);
        memset(&eblock->extents[ei], 0, sizeof(struct simplefs_extent));
    }

end:
    brelse(bh);
    return ret;
}

static const char *simplefs_get_link(struct dentry *dentry,
                                     struct inode *inode,
                                     struct delayed_call *done)
{
    return inode->i_link;
}

static const struct inode_operations kxcspacefs_inode_ops =
{
    .lookup = kxcspacefs_lookup,
    .create = kxcspacefs_create,
    .unlink = kxcspacefs_unlink,
    .mkdir = kxcspacefs_mkdir,
    .rmdir = kxcspacefs_rmdir,
    .rename = kxcspacefs_rename,
    //.link = simplefs_link,
    //.symlink = simplefs_symlink,
};

static const struct inode_operations symlink_inode_ops = {
    .get_link = simplefs_get_link,
};
