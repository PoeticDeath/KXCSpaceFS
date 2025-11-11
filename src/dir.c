#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "super.h"

#include "Dict.h"
#include "cspacefs.h"

/* Iterate over the files contained in dir and commit them to @ctx.
 * This function is called by the VFS as ctx->pos changes.
 * Returns 0 on success.
 */
static int kxcspacefs_iterate(struct file* dir, struct dir_context* ctx)
{
    struct inode* inode = file_inode(dir);
    struct super_block* sb = inode->i_sb;
    KMCSpaceFS* KMCSFS = SIMPLEFS_SB(sb);
    int ret = 0;

    /* Check that dir is a directory */
    if (!S_ISDIR(inode->i_mode))
    {
        return -ENOTDIR;
    }

    /* Commit . and .. to ctx */
    if (!dir_emit_dots(dir, ctx))
    {
        return 0;
    }

    /* Read the directory */
    unsigned long long offset = ctx->pos - 2;
    unsigned long long curoffset = 0;
    UNICODE_STRING* fn = inode->i_private;
    UNICODE_STRING rfn;
    rfn.Length = 65536;
    rfn.Buffer = kzalloc(rfn.Length, GFP_KERNEL);
    if (!rfn.Buffer)
    {
        pr_err("out of memory\n");
        return -ENOMEM;
    }

    unsigned long long tableoffset = 0;
    while (tableoffset < KMCSFS->filenamesend - KMCSFS->tableend + 1)
	{
		unsigned long long filenamelen = 0;

		for (; tableoffset < KMCSFS->filenamesend - KMCSFS->tableend + 1; tableoffset++)
		{
			if ((KMCSFS->table[KMCSFS->tableend + tableoffset] & 0xff) == 255 || (KMCSFS->table[KMCSFS->tableend + tableoffset] & 0xff) == 42) // 255 = file, 42 = fuse symlink
			{
				if (fn->Length / sizeof(WCHAR) < filenamelen && filenamelen > 1)
				{
					bool isin = true;
					unsigned long long i = 0;
					for (; i < fn->Length / sizeof(WCHAR); i++)
					{
						if (!incmp(fn->Buffer[i] & 0xff, rfn.Buffer[i] & 0xff) && !(fn->Buffer[i] == '/' && rfn.Buffer[i] == '\\') && !(fn->Buffer[i] == '\\' && rfn.Buffer[i] == '/'))
						{
							isin = false;
							break;
						}
					}
					if (!(rfn.Buffer[i] == '/') && !(rfn.Buffer[i] == '\\') && (fn->Length > 2))
					{
						isin = false;
					}
					i++;
					for (; i < filenamelen; i++)
					{
						if (rfn.Buffer[i] == '/' || rfn.Buffer[i] == '\\')
						{
							isin = false;
							break;
						}
					}
					for (unsigned long long j = 0; j < filenamelen; j++)
					{
						if (rfn.Buffer[j] == ':')
						{
							isin = false;
							break;
						}
					}
					if (isin)
					{
                        curoffset++;
                        if (curoffset > offset)
                        {
						    break;
                        }
					}
				}
				filenamelen = 0;
			}
			else
			{
				rfn.Buffer[filenamelen] = KMCSFS->table[KMCSFS->tableend + tableoffset] & 0xff;
				filenamelen++;
			}
		}

	    if (filenamelen)
	    {
            rfn.Length = filenamelen;
            if (!dir_emit(ctx, rfn.Buffer + fn->Length + 1, rfn.Length - fn->Length - sizeof(WCHAR), kxcspacefs_iget(sb, 0, &rfn)->i_ino, DT_UNKNOWN))
            {
                ret = 1;
                break;
            }
            ctx->pos++;
        }
    }

    kfree(rfn.Buffer);
    return ret;
}

const struct file_operations simplefs_dir_ops =
{
    .owner = THIS_MODULE,
    .iterate_shared = kxcspacefs_iterate,
};
