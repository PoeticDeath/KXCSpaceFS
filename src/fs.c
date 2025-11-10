#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>

/* Mount a kxcspacefs partition */
struct dentry* kxcspacefs_mount(struct file_system_type* fs_type, int flags, const char* dev_name, void* data)
{
    struct dentry *dentry = NULL;//mount_bdev(fs_type, flags, dev_name, data, simplefs_fill_super);
    if (IS_ERR(dentry))
    {
        pr_err("'%s' mount failure\n", dev_name);
    }
    else
    {
        pr_info("'%s' mount success\n", dev_name);
    }

    return dentry;
}

/* Unmount a kxcspacefs partition */
void kxcspacefs_kill_sb(struct super_block* sb)
{
    kill_block_super(sb);

    pr_info("unmounted disk\n");
}

static struct file_system_type kxcspacefs_file_system_type = {
    .owner = THIS_MODULE,
    .name = "KXCSpaceFS",
    .mount = kxcspacefs_mount,
    .kill_sb = kxcspacefs_kill_sb,
    .fs_flags = FS_REQUIRES_DEV,
    .next = NULL,
};

static int __init kxcspacefs_init(void)
{
    int ret = 0;//simplefs_init_inode_cache();
    if (ret)
    {
        pr_err("Failed to create inode cache\n");
        goto err;
    }

    ret = register_filesystem(&kxcspacefs_file_system_type);
    if (ret)
    {
        pr_err("Failed to register file system\n");
        goto err_inode;
    }

    pr_info("module loaded\n");
    return 0;

err_inode:
    //simplefs_destroy_inode_cache();
    /* Only after rcu_barrier() is the memory guaranteed to be freed. */
    rcu_barrier();
err:
    return ret;
}

static void __exit kxcspacefs_exit(void)
{
    int ret = unregister_filesystem(&kxcspacefs_file_system_type);
    if (ret)
    {
        pr_err("Failed to unregister file system\n");
    }

    //simplefs_destroy_inode_cache();
    /* Only after rcu_barrier() is the memory guaranteed to be freed. */
    rcu_barrier();

    pr_info("module unloaded\n");
}

module_init(kxcspacefs_init);
module_exit(kxcspacefs_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Anthony Kerr");
MODULE_DESCRIPTION("Kernel Mode Driver for CSpaceFS.");
