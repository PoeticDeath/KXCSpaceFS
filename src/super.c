#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/statfs.h>

#include <linux/blkdev.h>
#include <linux/jbd2.h>
#include <linux/namei.h>
#include <linux/parser.h>

#include "Dict.h"
#include "cspacefs.h"
#include "super.h"

struct dentry* kxcspacefs_mount(struct file_system_type* fs_type, int flags, const char* dev_name, void* data);
void kxcspacefs_kill_sb(struct super_block *sb);
static struct kmem_cache *simplefs_inode_cache;

/* Needed to initiate the inode cache, to allow us to attach
 * filesystem-specific inode information.
 */
int simplefs_init_inode_cache(void)
{
    simplefs_inode_cache = kmem_cache_create_usercopy(
        "simplefs_cache", sizeof(struct simplefs_inode_info), 0, 0, 0,
        sizeof(struct simplefs_inode_info), NULL);
    if (!simplefs_inode_cache)
        return -ENOMEM;
    return 0;
}

/* De-allocate the inode cache */
void simplefs_destroy_inode_cache(void)
{
    /* wait for call_rcu() and prevent the free cache be used */
    rcu_barrier();

    kmem_cache_destroy(simplefs_inode_cache);
}

static struct inode *simplefs_alloc_inode(struct super_block *sb)
{
    struct simplefs_inode_info *ci =
        kmem_cache_alloc(simplefs_inode_cache, GFP_KERNEL);
    if (!ci)
        return NULL;

    inode_init_once(&ci->vfs_inode);
    return &ci->vfs_inode;
}

static void simplefs_destroy_inode(struct inode *inode)
{
    struct simplefs_inode_info *ci = SIMPLEFS_INODE(inode);
    kmem_cache_free(simplefs_inode_cache, ci);
}

static int simplefs_write_inode(struct inode *inode,
                                struct writeback_control *wbc)
{
    struct simplefs_inode *disk_inode;
    struct simplefs_inode_info *ci = SIMPLEFS_INODE(inode);
    struct super_block *sb = inode->i_sb;
    struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);
    struct buffer_head *bh;
    uint32_t ino = inode->i_ino;
    uint32_t inode_block = (ino / SIMPLEFS_INODES_PER_BLOCK) + 1;
    uint32_t inode_shift = ino % SIMPLEFS_INODES_PER_BLOCK;

    if (ino >= sbi->nr_inodes)
        return 0;

    bh = sb_bread(sb, inode_block);
    if (!bh)
        return -EIO;

    disk_inode = (struct simplefs_inode *) bh->b_data;
    disk_inode += inode_shift;

    /* update the mode using what the generic inode has */
    disk_inode->i_mode = inode->i_mode;
    disk_inode->i_uid = i_uid_read(inode);
    disk_inode->i_gid = i_gid_read(inode);
    disk_inode->i_size = inode->i_size;

#if SIMPLEFS_AT_LEAST(6, 6, 0)
    struct timespec64 ctime = inode_get_ctime(inode);
    disk_inode->i_ctime = ctime.tv_sec;
#else
    disk_inode->i_ctime = inode->i_ctime.tv_sec;
#endif

#if SIMPLEFS_AT_LEAST(6, 7, 0)
    disk_inode->i_atime = inode_get_atime_sec(inode);
    disk_inode->i_atime = inode_get_mtime_sec(inode);
#else
    disk_inode->i_atime = inode->i_atime.tv_sec;
    disk_inode->i_mtime = inode->i_mtime.tv_sec;
#endif
    disk_inode->i_blocks = inode->i_blocks;
    disk_inode->i_nlink = inode->i_nlink;
    disk_inode->ei_block = ci->ei_block;
    strncpy(disk_inode->i_data, ci->i_data, sizeof(ci->i_data));

    mark_buffer_dirty(bh);
    sync_dirty_buffer(bh);
    brelse(bh);

    return 0;
}

static void kxcspacefs_put_super(struct super_block *sb)
{
    KMCSpaceFS* KMCSFS = SIMPLEFS_SB(sb);

    sync_blockdev(sb->s_bdev);
    invalidate_bdev(sb->s_bdev);

    if (KMCSFS)
    {
        kfree(KMCSFS->table);
        kfree(KMCSFS->tablestr);
		kfree(KMCSFS->dict);
		kfree(KMCSFS->readbuf);
		kfree(KMCSFS->writebuf);
        kfree(KMCSFS->readbuflock);
        kfree(KMCSFS->op_lock);
        kfree(KMCSFS);
    }
}

static int kxcspacefs_sync_fs(struct super_block *sb, int wait)
{
    KMCSpaceFS* KMCSFS = SIMPLEFS_SB(sb);

    // Future

    return 0;
}

static int kxcspacefs_statfs(struct dentry* dentry, struct kstatfs* stat)
{
    struct super_block* sb = dentry->d_sb;
    KMCSpaceFS* KMCSFS = SIMPLEFS_SB(sb);

    stat->f_type = 0xCCAACCEF;
    stat->f_bsize = KMCSFS->sectorsize;
    stat->f_blocks = KMCSFS->size / KMCSFS->sectorsize;
    down_read(KMCSFS->op_lock);
    find_block(sb->s_bdev, KMCSFS, 0, 0);
    up_read(KMCSFS->op_lock);
    stat->f_bfree = stat->f_blocks - KMCSFS->used_blocks;
    stat->f_bavail = stat->f_blocks - KMCSFS->used_blocks;
    stat->f_files = KMCSFS->filecount;
    stat->f_ffree = LLONG_MAX;
    stat->f_namelen = SIMPLEFS_FILENAME_LEN;

    return 0;
}

/* Code related to the external journal device settings */

static journal_t *simplefs_get_dev_journal(struct super_block *sb,
                                           dev_t journal_dev)
{
    struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);
    struct buffer_head *bh;
    struct block_device *bdev;
    int hblock, blocksize;
    unsigned long long sb_block, start, len;
    unsigned long offset;
    journal_t *journal;
    int errno = 0;
#if SIMPLEFS_AT_LEAST(6, 9, 0)
    struct file *bdev_file;
    bdev_file = bdev_file_open_by_dev(
        journal_dev, BLK_OPEN_READ | BLK_OPEN_WRITE | BLK_OPEN_RESTRICT_WRITES,
        sb, &fs_holder_ops);
#elif SIMPLEFS_AT_LEAST(6, 8, 0)
    struct bdev_handle *bdev_handle;
    bdev_handle = bdev_open_by_dev(
        journal_dev, BLK_OPEN_READ | BLK_OPEN_WRITE | BLK_OPEN_RESTRICT_WRITES,
        sb, &fs_holder_ops);
#elif SIMPLEFS_AT_LEAST(6, 7, 0)
    struct bdev_handle *bdev_handle;
    up_write(&sb->s_umount);
    bdev_handle = bdev_open_by_dev(journal_dev, BLK_OPEN_READ | BLK_OPEN_WRITE,
                                   sb, &fs_holder_ops);
    down_write(&sb->s_umount);
#elif SIMPLEFS_AT_LEAST(6, 6, 0)
    up_write(&sb->s_umount);
    bdev = blkdev_get_by_dev(journal_dev, BLK_OPEN_READ | BLK_OPEN_WRITE, sb,
                             &fs_holder_ops);
    down_write(&sb->s_umount);
#elif SIMPLEFS_AT_LEAST(6, 5, 0)
    bdev = blkdev_get_by_dev(journal_dev, BLK_OPEN_READ | BLK_OPEN_WRITE, sb,
                             NULL);
#elif SIMPLEFS_AT_LEAST(5, 10, 0)
    bdev = blkdev_get_by_dev(journal_dev, FMODE_READ | FMODE_WRITE | FMODE_EXCL,
                             sb);
#endif

#if SIMPLEFS_AT_LEAST(6, 9, 0)
    if (IS_ERR(bdev_file)) {
        printk(KERN_ERR
               "failed to open journal device unknown-block(%u,%u) %ld\n",
               MAJOR(journal_dev), MINOR(journal_dev), PTR_ERR(bdev_file));
        return ERR_CAST(bdev_file);
    }
    bdev = file_bdev(bdev_file);
#elif SIMPLEFS_AT_LEAST(6, 7, 0)
    if (IS_ERR(bdev_handle)) {
        printk(KERN_ERR
               "failed to open journal device unknown-block(%u,%u) %ld\n",
               MAJOR(journal_dev), MINOR(journal_dev), PTR_ERR(bdev_handle));
        return ERR_CAST(bdev_handle);
    }
    bdev = bdev_handle->bdev;
#elif SIMPLEFS_AT_LEAST(5, 10, 0)
    if (IS_ERR(bdev)) {
        printk(KERN_ERR "failed to open block device (%u:%u), error: %ld\n",
               MAJOR(journal_dev), MINOR(journal_dev), PTR_ERR(bdev));
        return ERR_CAST(bdev);
    }
#endif

    blocksize = sb->s_blocksize;
    hblock = bdev_logical_block_size(bdev);

    if (blocksize < hblock) {
        pr_err("blocksize too small for journal device\n");
        errno = -EINVAL;
        goto out_bdev;
    }

    sb_block = SIMPLEFS_BLOCK_SIZE / blocksize;
    offset = SIMPLEFS_BLOCK_SIZE % blocksize;

#if SIMPLEFS_AT_LEAST(6, 9, 0)
    set_blocksize(bdev_file, blocksize);
#elif SIMPLEFS_AT_LEAST(6, 7, 0)
    set_blocksize(bdev, blocksize);
#endif
    bh = __bread(bdev, sb_block, blocksize);

    if (!bh) {
        pr_err("couldn't read superblock of external journal\n");
        errno = -EINVAL;
        goto out_bdev;
    }
    /*
     * FIXME: Currently, the exact size of the external journal device is not
     * available. Therefore, we use the device size divided by the block size to
     * set `len`. Hint: External device size available now is 8MB.
     *
     * Future implementation might need to change to:
     * len = CapacityOfJournalDevice / SIMPLEFS_BLOCK_SIZE
     */

    len = 2048;
    start = sb_block;
    brelse(bh);

#if SIMPLEFS_AT_LEAST(6, 9, 0)
    journal = jbd2_journal_init_dev(file_bdev(bdev_file), sb->s_bdev, start,
                                    len, sb->s_blocksize);
#elif SIMPLEFS_AT_LEAST(6, 7, 0)
    journal = jbd2_journal_init_dev(bdev_handle->bdev, sb->s_bdev, start, len,
                                    sb->s_blocksize);
#elif SIMPLEFS_AT_LEAST(5, 15, 0)
    journal = jbd2_journal_init_dev(bdev, sb->s_bdev, start, len, blocksize);
#endif

    if (IS_ERR(journal)) {
        pr_err(
            "simplefs_get_dev_journal: failed to initialize journal, error "
            "%ld\n",
            PTR_ERR(journal));
        errno = PTR_ERR(journal);
        goto out_bdev;
    }
#if SIMPLEFS_AT_LEAST(6, 9, 0)
    sbi->s_journal_bdev_file = bdev_file;
#elif SIMPLEFS_AT_LEAST(6, 7, 0)
    sbi->s_journal_bdev_handle = bdev_handle;
#elif SIMPLEFS_AT_LEAST(5, 15, 0)
    sbi->s_journal_bdev = bdev;
#endif

    journal->j_private = sb;
    return journal;

out_bdev:
#if SIMPLEFS_AT_LEAST(6, 9, 0)
    fput(bdev_file);
#elif SIMPLEFS_AT_LEAST(6, 7, 0)
    bdev_release(bdev_handle);
#elif SIMPLEFS_AT_LEAST(6, 5, 0)
    blkdev_put(bdev, sb);
#elif SIMPLEFS_AT_LEAST(5, 10, 0)
    blkdev_put(bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
#endif
    return NULL;
}

static int simplefs_load_journal(struct super_block *sb,
                                 unsigned long journal_devnum)
{
    journal_t *journal;
    struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);
    dev_t journal_dev;
    int err = 0;
    int really_read_only;
    int journal_dev_ro;

    journal_dev = new_decode_dev(journal_devnum);
    journal = simplefs_get_dev_journal(sb, journal_dev);
    if (IS_ERR(journal)) {
        pr_err("Failed to get journal from device, error %ld\n",
               PTR_ERR(journal));
        return PTR_ERR(journal);
    }

    journal_dev_ro = bdev_read_only(journal->j_dev);
    really_read_only = bdev_read_only(sb->s_bdev) | journal_dev_ro;

    if (journal_dev_ro && !sb_rdonly(sb)) {
        pr_err("journal device read-only, try mounting with '-o ro'\n");
        err = -EROFS;
        goto err_out;
    }

    err = jbd2_journal_wipe(journal, !really_read_only);

    if (!err) {
        err = jbd2_journal_load(journal);
        if (err) {
            pr_err("error loading journal, error %d\n", err);
            goto err_out;
        }
    }

    sbi->journal = journal;

    return 0;

err_out:
    jbd2_journal_destroy(journal);
    return err;
}

/* we use SIMPLEFS_OPT_JOURNAL_PATH case to load external journal device now */
#define SIMPLEFS_OPT_JOURNAL_DEV 1
#define SIMPLEFS_OPT_JOURNAL_PATH 2
static const match_table_t tokens = {
    {SIMPLEFS_OPT_JOURNAL_DEV, "journal_dev=%u"},
    {SIMPLEFS_OPT_JOURNAL_PATH, "journal_path=%s"},
};
static int simplefs_parse_options(struct super_block *sb, char *options)
{
    substring_t args[MAX_OPT_ARGS];
    int token, ret = 0, arg;
    char *p;
    char *journal_path;
    struct inode *journal_inode;
    struct path path;

    pr_info("simplefs_parse_options: parsing options '%s'\n", options);

    while ((p = strsep(&options, ","))) {
        if (!*p)
            continue;

        args[0].to = args[0].from = NULL;
        token = match_token(p, tokens, args);

        switch (token) {
        case SIMPLEFS_OPT_JOURNAL_DEV:
            if (args->from && match_int(args, &arg)) {
                pr_err("simplefs_parse_options: match_int failed\n");
                return 1;
            }
            if ((ret = simplefs_load_journal(sb, arg))) {
                pr_err(
                    "simplefs_parse_options: simplefs_load_journal failed with "
                    "%d\n",
                    ret);
                return ret;
            }
            break;

        case SIMPLEFS_OPT_JOURNAL_PATH: {
            journal_path = match_strdup(&args[0]);
            if (!journal_path) {
                pr_err("simplefs_parse_options: match_strdup failed\n");
                return -ENOMEM;
            }
            ret = kern_path(journal_path, LOOKUP_FOLLOW, &path);
            if (ret) {
                pr_err(
                    "simplefs_parse_options: kern_path failed with error %d\n",
                    ret);
                kfree(journal_path);
                return ret;
            }

            journal_inode = path.dentry->d_inode;

            path_put(&path);
            kfree(journal_path);

            if (S_ISBLK(journal_inode->i_mode)) {
                unsigned long journal_devnum =
                    new_encode_dev(journal_inode->i_rdev);
                if ((ret = simplefs_load_journal(sb, journal_devnum))) {
                    pr_err(
                        "simplefs_parse_options: simplefs_load_journal failed "
                        "with %d\n",
                        ret);
                    return ret;
                }
            }
            break;
        }
        }
    }

    return 0;
}

static struct super_operations simplefs_super_ops =
{
    .put_super = kxcspacefs_put_super,
    .alloc_inode = simplefs_alloc_inode,
    .destroy_inode = simplefs_destroy_inode,
    .write_inode = simplefs_write_inode,
    .sync_fs = kxcspacefs_sync_fs,
    .statfs = kxcspacefs_statfs,
};

/* Fill the struct superblock from partition superblock */
int kxcspacefs_fill_super(struct super_block *sb, void *data, int silent)
{
    struct buffer_head* bh = NULL;
    struct inode* root_inode = NULL;
    int ret = 0;

    /* Initialize the superblock */
    sb_set_blocksize(sb, 512);
    sb->s_maxbytes = LLONG_MAX;
    sb->s_op = &simplefs_super_ops;

    /* Read the superblock from disk */
    bh = sb_bread(sb, SIMPLEFS_SB_BLOCK_NR);
    if (!bh)
    {
        return -EIO;
    }

    /* Read table */
    bool found = false;
    KMCSpaceFS* KMCSFS = kzalloc(sizeof(KMCSpaceFS), GFP_KERNEL);
    if (!KMCSFS)
    {
        ret = -ENOMEM;
        goto release;
    }
    KMCSFS->sectorsize = 1 << (9 + (bh->b_data[0] & 0xff));
    KMCSFS->tablesize = 1 + (bh->b_data[4] & 0xff) + ((bh->b_data[3] & 0xff) << 8) + ((bh->b_data[2] & 0xff) << 16) + ((bh->b_data[1] & 0xff) << 24);
    KMCSFS->extratablesize = (unsigned long long)KMCSFS->sectorsize * KMCSFS->tablesize;
    KMCSFS->size = sb->s_bdev->bd_nr_sectors * 512;
    KMCSFS->used_blocks = 0;
    KMCSFS->table = kzalloc(KMCSFS->extratablesize, GFP_KERNEL);
    if (!KMCSFS->table)
    {
        ret = -ENOMEM;
        goto free_kmcsfs;
    }
    sync_read_phys(0, KMCSFS->extratablesize, KMCSFS->table, sb->s_bdev);
    if (!memcmp(bh->b_data, KMCSFS->table, 512))
    {
        KMCSFS->filenamesend = 5;
		KMCSFS->tableend = 0;
		KMCSFS->filecount = 0;
		unsigned long long loc = 0;
		unsigned long long lastslash = 0;

		for (KMCSFS->filenamesend = 5; KMCSFS->filenamesend < KMCSFS->extratablesize; KMCSFS->filenamesend++)
		{
			if ((KMCSFS->table[KMCSFS->filenamesend] & 0xff) == 255)
			{
				if ((KMCSFS->table[min(KMCSFS->filenamesend + 1, KMCSFS->extratablesize)] & 0xff) == 254)
				{
					found = true;
					break;
				}
				else
				{
					if (loc == 0)
    				{
						KMCSFS->tableend = KMCSFS->filenamesend;
					}

					// if following check is not enough to block the driver from loading unnecessarily,
					// then we can add a check to make sure all bytes between loc and i equal a vaild path.
					// if that is not enough, then nothing will be.

					loc = KMCSFS->filenamesend;
				}
				KMCSFS->filecount++;
				lastslash = 0;
			}
			if ((KMCSFS->table[KMCSFS->filenamesend] & 0xff) == 47 || (KMCSFS->table[KMCSFS->filenamesend] & 0xff) == 92)
			{
				lastslash = KMCSFS->filenamesend - loc;
			}
			if (KMCSFS->filenamesend - loc - lastslash > 256 && loc > 0)
			{
				break;
			}
		}

        if (found)
        {
            KMCSFS->tablestr = decode(KMCSFS->table + 5, KMCSFS->tableend - 5);
			if (!KMCSFS->tablestr)
			{
				pr_err("out of memory\n");
				found = false;
				goto free_kmcsfs_table;
			}
			KMCSFS->tablestrlen = KMCSFS->tableend + KMCSFS->tableend - 10;

			unsigned long long i = 0;
			while (KMCSFS->filecount > (unsigned long long)(1) << i)
			{
				i++;
			}
			KMCSFS->DictSize = (unsigned long long)(1) << (i + 1);
			KMCSFS->dict = CreateDict(KMCSFS->DictSize);
			if (!KMCSFS->dict)
			{
				pr_err("out of memory\n");
				kfree(KMCSFS->tablestr);
				found = false;
				goto free_kmcsfs_table;
			}

			KMCSFS->readbuf = kzalloc(KMCSFS->sectorsize, GFP_KERNEL);
			if (!KMCSFS->readbuf)
			{
				pr_err("out of memory\n");
				kfree(KMCSFS->tablestr);
				kfree(KMCSFS->dict);
				found = false;
				goto free_kmcsfs_table;
			}
			KMCSFS->writebuf = kzalloc(KMCSFS->sectorsize, GFP_KERNEL);
			if (!KMCSFS->writebuf)
			{
				pr_err("out of memory\n");
				kfree(KMCSFS->tablestr);
				kfree(KMCSFS->dict);
				kfree(KMCSFS->readbuf);
				found = false;
				goto free_kmcsfs_table;
			}
            KMCSFS->readbuflock = kzalloc(sizeof(struct rw_semaphore), GFP_KERNEL);
			if (!KMCSFS->readbuflock)
			{
				pr_err("out of memory\n");
				kfree(KMCSFS->tablestr);
				kfree(KMCSFS->dict);
				kfree(KMCSFS->readbuf);
				kfree(KMCSFS->writebuf);
				found = false;
				goto free_kmcsfs_table;
			}
            init_rwsem(KMCSFS->readbuflock);
            KMCSFS->op_lock = kzalloc(sizeof(struct rw_semaphore), GFP_KERNEL);
			if (!KMCSFS->op_lock)
			{
				pr_err("out of memory\n");
				kfree(KMCSFS->tablestr);
				kfree(KMCSFS->dict);
				kfree(KMCSFS->readbuf);
				kfree(KMCSFS->writebuf);
                kfree(KMCSFS->readbuflock);
				found = false;
				goto free_kmcsfs_table;
			}
            init_rwsem(KMCSFS->op_lock);
        }
    }

    if (found)
    {
        unsigned long long len = 0;
	    unsigned long long count = 0;
	    unsigned char* filename = kzalloc(65536, GFP_KERNEL);
	    if (filename)
	    {
		    for (unsigned long long i = KMCSFS->tableend + 1; i < KMCSFS->filenamesend; i++)
		    {
			    if ((KMCSFS->table[i] & 0xff) == 255)
			    {
				    AddDictEntry(&KMCSFS->dict, filename, i - len - KMCSFS->tableend, len, &KMCSFS->CurDictSize, &KMCSFS->DictSize, count, false);
				    if (!(count % 1000))
				    {
					    pr_err("%llu / %llu indices computed.\n", count, KMCSFS->filecount);
				    }
				    count++;
				    len = 0;
				    continue;
			    }
			    else if ((KMCSFS->table[i] & 0xff) == 42)
			    {
				    AddDictEntry(&KMCSFS->dict, filename, i - len - KMCSFS->tableend, len, &KMCSFS->CurDictSize, &KMCSFS->DictSize, count, false);
				    if (!(count % 1000))
				    {
					    pr_err("%llu / %llu indices computed.\n", count, KMCSFS->filecount);
				    }
				    len = 0;
				    continue;
			    }
			    else
			    {
				    filename[len] = KMCSFS->table[i] & 0xff;
			    }
			    len++;
		    }
		    kfree(filename);
	    }
        else
        {
            pr_err("out of memory\n");
            kfree(KMCSFS->tablestr);
			kfree(KMCSFS->dict);
			kfree(KMCSFS->readbuf);
			kfree(KMCSFS->writebuf);
            kfree(KMCSFS->readbuflock);
            kfree(KMCSFS->op_lock);
            ret = -ENOMEM;
            goto free_kmcsfs_table;
        }
    }
    else
    {
        pr_err("CSpaceFS Not Found.\n");
        ret = -EINVAL;
        goto free_kmcsfs_table;
    }

    sb->s_fs_info = KMCSFS;

    brelse(bh);

    bh = NULL;
    /* Create root inode */
    UNICODE_STRING root_fn;
    root_fn.Length = 0;
    root_fn.Buffer = NULL;
    root_inode = kxcspacefs_iget(sb, 1, &root_fn);
    if (IS_ERR(root_inode))
    {
        pr_err("out of memory\n");
        kfree(KMCSFS->tablestr);
		kfree(KMCSFS->dict);
		kfree(KMCSFS->readbuf);
		kfree(KMCSFS->writebuf);
        kfree(KMCSFS->readbuflock);
        kfree(KMCSFS->op_lock);
        ret = PTR_ERR(root_inode);
        goto free_kmcsfs_table;
    }

#if SIMPLEFS_AT_LEAST(6, 3, 0)
    inode_init_owner(&nop_mnt_idmap, root_inode, NULL, root_inode->i_mode);
#elif SIMPLEFS_AT_LEAST(5, 12, 0)
    inode_init_owner(&init_user_ns, root_inode, NULL, root_inode->i_mode);
#else
    inode_init_owner(root_inode, NULL, root_inode->i_mode);
#endif

    sb->s_root = d_make_root(root_inode);
    if (!sb->s_root)
    {
        pr_err("out of memory\n");
        kfree(KMCSFS->tablestr);
		kfree(KMCSFS->dict);
		kfree(KMCSFS->readbuf);
		kfree(KMCSFS->writebuf);
        kfree(KMCSFS->readbuflock);
        kfree(KMCSFS->op_lock);
        ret = -ENOMEM;
        goto iput;
    }

    return 0;

iput:
    iput(root_inode);
free_kmcsfs_table:
    kfree(KMCSFS->table);
free_kmcsfs:
    kfree(KMCSFS);
release:
    brelse(bh);

    return ret;
}
