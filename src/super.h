#pragma once

#include "Dict.h"
#include "cspacefs.h"

#define KXCSPACEFS_FILENAME_LEN 255

#ifdef __KERNEL__
#include <linux/jbd2.h>
#include <linux/version.h>
/* compatibility macro */
#define KXCSPACEFS_AT_LEAST(major, minor, rev) LINUX_VERSION_CODE >= KERNEL_VERSION(major, minor, rev)

/* superblock functions */
int kxcspacefs_fill_super(struct super_block *sb, void *data, int silent);
void kxcspacefs_kill_sb(struct super_block* sb);

/* inode functions */
struct inode* kxcspacefs_iget(struct super_block* sb, unsigned long long index, UNICODE_STRING* fn);
int kxcspacefs_iterate(struct file* dir, struct dir_context* ctx);
ssize_t kxcspacefs_write(struct file* file, const char __user* buf, size_t len, loff_t* ppos);

/* dentry function */
struct dentry* kxcspacefs_mount(struct file_system_type* fs_type, int flags, const char* dev_name, void* data);

/* file functions */
extern const struct file_operations kxcspacefs_file_ops;
extern const struct file_operations kxcspacefs_dir_ops;
extern const struct address_space_operations kxcspacefs_aops;

/* Getters for superblock and inode */
#define KXCSPACEFS_SB(sb) (sb->s_fs_info)
#endif /* __KERNEL__ */