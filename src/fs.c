// Copyright (c) Anthony Kerr 2026-

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "linuxfs.h"
#include "Dict.h"
#include "cspacefs.h"
#include "super.h"

#if KXCSPACEFS_AT_LEAST(7, 0, 0)
#include <linux/fs_context.h>

static int kxcspacefs_get_tree(struct fs_context* fc)
{
	return get_tree_bdev(fc, kxcspacefs_fill_super);
}

static void kxcspacefs_fc_free(struct fs_context* fc)
{
    return;
}

static const struct fs_context_operations kxcspacefs_context_ops = {
	.parse_param = NULL,
	.get_tree = kxcspacefs_get_tree,
	.reconfigure = NULL,
	.free = kxcspacefs_fc_free,
};

int kxcspacefs_init_context(struct fs_context* fc)
{
	fc->ops = &kxcspacefs_context_ops;

	/* i_version is always enabled now */
	fc->sb_flags |= SB_I_VERSION;

	return 0;
}
#else
/* Mount a kxcspacefs partition */
struct dentry* kxcspacefs_mount(struct file_system_type* fs_type, int flags, const char* dev_name, void* data)
{
    struct dentry *dentry = mount_bdev(fs_type, flags, dev_name, data, kxcspacefs_fill_super);
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
#endif

/* Unmount a kxcspacefs partition */
void kxcspacefs_kill_sb(struct super_block* sb)
{
    kill_block_super(sb);

    pr_info("unmounted disk\n");
}

static struct file_system_type kxcspacefs_file_system_type = {
    .owner = THIS_MODULE,
    .name = "KXCSpaceFS",
#if KXCSPACEFS_AT_LEAST(7, 0, 0)
    .init_fs_context = kxcspacefs_init_context,
#else
    .mount = kxcspacefs_mount,
#endif
    .kill_sb = kxcspacefs_kill_sb,
    .fs_flags = FS_REQUIRES_DEV,
    .next = NULL,
};

static int __init kxcspacefs_init(void)
{
    init_maps();

    int ret = register_filesystem(&kxcspacefs_file_system_type);
    if (ret)
    {
        pr_err("Failed to register file system\n");
        goto err_inode;
    }

    pr_info("module loaded\n");
    return 0;

err_inode:
    /* Only after rcu_barrier() is the memory guaranteed to be freed. */
    vfree(emap);
    vfree(dmap);
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

    /* Only after rcu_barrier() is the memory guaranteed to be freed. */
    vfree(emap);
    vfree(dmap);
    rcu_barrier();

    pr_info("module unloaded\n");
}

module_init(kxcspacefs_init);
module_exit(kxcspacefs_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Anthony Kerr");
MODULE_DESCRIPTION("Kernel Mode Driver for CSpaceFS.");
