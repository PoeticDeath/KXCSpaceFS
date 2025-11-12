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
