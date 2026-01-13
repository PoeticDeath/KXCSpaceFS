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

#include "linuxfs.h"
#include "Dict.h"
#include "cspacefs.h"
#include "super.h"

struct dentry* kxcspacefs_mount(struct file_system_type* fs_type, int flags, const char* dev_name, void* data);
void kxcspacefs_kill_sb(struct super_block* sb);

static void kxcspacefs_put_super(struct super_block* sb)
{
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);

    sync_blockdev(sb->s_bdev);
    invalidate_bdev(sb->s_bdev);

    if (KMCSFS)
    {
        vfree(KMCSFS->table);
        vfree(KMCSFS->tablestr);
		vfree(KMCSFS->dict);
		vfree(KMCSFS->readbuf);
		vfree(KMCSFS->writebuf);
        vfree(KMCSFS->readbuflock);
        vfree(KMCSFS->op_lock);
        vfree(KMCSFS);
    }
}

static int kxcspacefs_sync_fs(struct super_block* sb, int wait)
{
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);

    // Future

    return 0;
}

static int kxcspacefs_statfs(struct dentry* dentry, struct kstatfs* stat)
{
    struct super_block* sb = dentry->d_sb;
    KMCSpaceFS* KMCSFS = KXCSPACEFS_SB(sb);

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
    stat->f_namelen = KXCSPACEFS_FILENAME_LEN;

    return 0;
}

static struct super_operations kxcspacefs_super_ops =
{
    .put_super = kxcspacefs_put_super,
    .sync_fs = kxcspacefs_sync_fs,
    .statfs = kxcspacefs_statfs,
};

/* Fill the struct superblock from partition superblock */
int kxcspacefs_fill_super(struct super_block* sb, void* data, int silent)
{
    struct buffer_head* bh = NULL;
    struct inode* root_inode = NULL;
    int ret = 0;

    /* Initialize the superblock */
    sb_set_blocksize(sb, 512);
    sb->s_maxbytes = LLONG_MAX;
    sb->s_op = &kxcspacefs_super_ops;

    /* Read the superblock from disk */
    bh = sb_bread(sb, 0);
    if (!bh)
    {
        return -EIO;
    }

    /* Read table */
    bool found = false;
    KMCSpaceFS* KMCSFS = vmalloc(sizeof(KMCSpaceFS));
    if (!KMCSFS)
    {
        ret = -ENOMEM;
        goto release;
    }
    KMCSFS->sectorsize = 1 << (9 + (bh->b_data[0] & 0xff));
    KMCSFS->tablesize = 1 + (bh->b_data[4] & 0xff) + ((bh->b_data[3] & 0xff) << 8) + ((bh->b_data[2] & 0xff) << 16) + ((bh->b_data[1] & 0xff) << 24);
    KMCSFS->extratablesize = (unsigned long long)KMCSFS->sectorsize * KMCSFS->tablesize;
    KMCSFS->size = sb->s_bdev->bd_nr_sectors * 512;
	KMCSFS->size -= KMCSFS->size % KMCSFS->sectorsize;
    KMCSFS->used_blocks = 0;
    KMCSFS->table = vmalloc(KMCSFS->extratablesize);
    if (!KMCSFS->table)
    {
        ret = -ENOMEM;
        goto free_kmcsfs;
    }
	for (unsigned long long i = 0; i < KMCSFS->extratablesize; i += KMCSFS->sectorsize)
	{
    	sync_read_phys(i, KMCSFS->sectorsize, KMCSFS->table + i, sb->s_bdev);
	}
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
				vfree(KMCSFS->tablestr);
				found = false;
				goto free_kmcsfs_table;
			}

			KMCSFS->readbuf = vmalloc(KMCSFS->sectorsize);
			if (!KMCSFS->readbuf)
			{
				pr_err("out of memory\n");
				vfree(KMCSFS->tablestr);
				vfree(KMCSFS->dict);
				found = false;
				goto free_kmcsfs_table;
			}
			KMCSFS->writebuf = vmalloc(KMCSFS->sectorsize);
			if (!KMCSFS->writebuf)
			{
				pr_err("out of memory\n");
				vfree(KMCSFS->tablestr);
				vfree(KMCSFS->dict);
				vfree(KMCSFS->readbuf);
				found = false;
				goto free_kmcsfs_table;
			}
            KMCSFS->readbuflock = vmalloc(sizeof(struct rw_semaphore));
			if (!KMCSFS->readbuflock)
			{
				pr_err("out of memory\n");
				vfree(KMCSFS->tablestr);
				vfree(KMCSFS->dict);
				vfree(KMCSFS->readbuf);
				vfree(KMCSFS->writebuf);
				found = false;
				goto free_kmcsfs_table;
			}
            init_rwsem(KMCSFS->readbuflock);
            KMCSFS->op_lock = vmalloc(sizeof(struct rw_semaphore));
			if (!KMCSFS->op_lock)
			{
				pr_err("out of memory\n");
				vfree(KMCSFS->tablestr);
				vfree(KMCSFS->dict);
				vfree(KMCSFS->readbuf);
				vfree(KMCSFS->writebuf);
                vfree(KMCSFS->readbuflock);
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
	    unsigned char* filename = vmalloc(65536);
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
		    vfree(filename);
	    }
        else
        {
            pr_err("out of memory\n");
            vfree(KMCSFS->tablestr);
			vfree(KMCSFS->dict);
			vfree(KMCSFS->readbuf);
			vfree(KMCSFS->writebuf);
            vfree(KMCSFS->readbuflock);
            vfree(KMCSFS->op_lock);
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
	char name = '/';
    UNICODE_STRING root_fn;
    root_fn.Length = sizeof(WCHAR);
    root_fn.Buffer = &name;
    root_inode = kxcspacefs_iget(sb, 0, &root_fn);
    if (IS_ERR(root_inode))
    {
        pr_err("out of memory\n");
        vfree(KMCSFS->tablestr);
		vfree(KMCSFS->dict);
		vfree(KMCSFS->readbuf);
		vfree(KMCSFS->writebuf);
        vfree(KMCSFS->readbuflock);
        vfree(KMCSFS->op_lock);
        ret = PTR_ERR(root_inode);
        goto free_kmcsfs_table;
    }

#if KXCSPACEFS_AT_LEAST(6, 3, 0)
    inode_init_owner(&nop_mnt_idmap, root_inode, NULL, root_inode->i_mode);
#elif KXCSPACEFS_AT_LEAST(5, 12, 0)
    inode_init_owner(&init_user_ns, root_inode, NULL, root_inode->i_mode);
#else
    inode_init_owner(root_inode, NULL, root_inode->i_mode);
#endif

    sb->s_root = d_make_root(root_inode);
    if (!sb->s_root)
    {
        pr_err("out of memory\n");
        vfree(KMCSFS->tablestr);
		vfree(KMCSFS->dict);
		vfree(KMCSFS->readbuf);
		vfree(KMCSFS->writebuf);
        vfree(KMCSFS->readbuflock);
        vfree(KMCSFS->op_lock);
        ret = -ENOMEM;
        goto iput;
    }

	unsigned long long index = get_filename_index(root_fn, KMCSFS);
	root_inode->i_gid.val = chgid(index, 0, *KMCSFS, false);
	root_inode->i_uid.val = chuid(index, 0, *KMCSFS, false);
	root_inode->i_mode = chmode(index, 0, *KMCSFS);

    return 0;

iput:
    iput(root_inode);
free_kmcsfs_table:
    vfree(KMCSFS->table);
free_kmcsfs:
    vfree(KMCSFS);
release:
    brelse(bh);

    return ret;
}
