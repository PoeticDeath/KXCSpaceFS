#include <fcntl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * DIV_ROUND_UP - round up a division
 * @n: dividend
 * @d: divisor
 *
 * Return the result of n / d, rounded up to the nearest integer.
 */
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

struct superblock_data
{
    unsigned char sectorsize;
    unsigned long used_blocks;
};

struct superblock
{
    union
    {
        struct superblock_data sbd;
        char table[512];
    };
};

static struct superblock* write_superblock(int fd, struct stat *fstats, unsigned long long sectorsizewrite, unsigned long long sectorsize)
{
    struct superblock* sb = malloc(sectorsize);
    if (!sb)
    {
        return NULL;
    }
    memset(sb, 0, sectorsize);

    sb->sbd.sectorsize = sectorsizewrite;
    sb->sbd.used_blocks = 0;
    sb->table[5] = 0x0d;
    sb->table[6] = 0x0d;
    sb->table[7] = 0x21;
    sb->table[8] = 0xc0;
    sb->table[9] = 0x0d;
    sb->table[10] = 0x21;
    sb->table[11] = 0xc6;
    sb->table[12] = 0x0c;
    sb->table[13] = 0xff;
    sb->table[14] = 0xff;
    sb->table[15] = '/';
    sb->table[16] = 0xff;
    sb->table[17] = ':';
    sb->table[18] = 0xff;
    sb->table[19] = 0xfe;
    sb->table[92] = 0x00;
    sb->table[93] = 0x02;
    sb->table[94] = 0x21;
    sb->table[95] = 0x02;
    sb->table[96] = 0x21;
    sb->table[97] = 0x01;
    sb->table[98] = 0xc0;
    sb->table[99] = 0x00;
    sb->table[100] = 0x00;
    sb->table[101] = 0x08;
    sb->table[102] = 0x00;
    sb->table[103] = 0x00;
    sb->table[104] = 0x02;
    sb->table[105] = 0x21;
    sb->table[106] = 0x02;
    sb->table[107] = 0x21;
    sb->table[108] = 0x41;
    sb->table[109] = 0xed;
    sb->table[110] = 0x00;
    sb->table[111] = 0x00;
    sb->table[112] = 0x20;
    sb->table[113] = 0x00;
    sb->table[114] = 0x00;
    sb->table[115] = 0x02;
    sb->table[116] = 0x21;
    sb->table[117] = 0x02;
    sb->table[118] = 0x21;
    sb->table[119] = 0x01;
    sb->table[120] = 0xc0;
    sb->table[121] = 0x00;
    sb->table[122] = 0x00;
    sb->table[123] = 0x08;
    sb->table[124] = 0x00;
    sb->table[125] = 0x00;

    int ret = write(fd, sb, sectorsize);
    if (ret != sectorsize)
    {
        free(sb);
        return NULL;
    }

    off_t offset = lseek(fd, -sectorsize, SEEK_END);
    if (!offset)
    {
        free(sb);
        return NULL;
    }

    char perms_and_label[512] = {0};
    perms_and_label[0] = 'O';
    perms_and_label[1] = ':';
    perms_and_label[2] = 'W';
    perms_and_label[3] = 'D';
    perms_and_label[4] = 'G';
    perms_and_label[5] = ':';
    perms_and_label[6] = 'W';
    perms_and_label[7] = 'D';
    perms_and_label[8] = 'D';
    perms_and_label[9] = ':';
    perms_and_label[10] = 'P';
    perms_and_label[11] = '(';
    perms_and_label[12] = 'A';
    perms_and_label[13] = ';';
    perms_and_label[14] = ';';
    perms_and_label[15] = 'F';
    perms_and_label[16] = 'A';
    perms_and_label[17] = ';';
    perms_and_label[18] = ';';
    perms_and_label[19] = ';';
    perms_and_label[20] = 'W';
    perms_and_label[21] = 'D';
    perms_and_label[22] = ')';
    perms_and_label[23] = 'S';
    perms_and_label[24] = 'p';
    perms_and_label[25] = 'a';
    perms_and_label[26] = 'c';
    perms_and_label[27] = 'e';
    perms_and_label[28] = 'F';
    perms_and_label[29] = 'S';

    ret = write(fd, perms_and_label, 512);
    if (ret != 512)
    {
        free(sb);
        return NULL;
    }

    return sb;
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s disk sectorsize\n", argv[0]);
        return EXIT_FAILURE;
    }

    /* Calculate SectorSize */
    char* endptr;
    unsigned long long sectorsize = strtoull(argv[2], &endptr, 10);
    if (*endptr != '\0')
    {
        fprintf(stderr, "Error: Invalid characters in sectorsize.\n");
    }
    else
    {
        fprintf(stdout, "Converted value: %llu\n", sectorsize);
    }
    unsigned long long i = 0;
    while (sectorsize > 512)
    {
        i += 1;
        sectorsize >>= 1;
    }
    sectorsize = 1 << (9 + (i & 0xff));
    fprintf(stdout, "Calculated value: %llu\n", sectorsize);

    /* Open disk image */
    int fd = open(argv[1], O_RDWR);
    if (fd == -1)
    {
        perror("open():");
        return EXIT_FAILURE;
    }

    /* Get image size */
    struct stat stat_buf;
    int ret = fstat(fd, &stat_buf);
    if (ret)
    {
        perror("fstat():");
        ret = EXIT_FAILURE;
        goto fclose;
    }

    /* Get block device size */
    if ((stat_buf.st_mode & S_IFMT) == S_IFBLK)
    {
        long int blk_size = 0;
        ret = ioctl(fd, BLKGETSIZE64, &blk_size);
        if (ret != 0)
        {
            perror("BLKGETSIZE64:");
            ret = EXIT_FAILURE;
            goto fclose;
        }
        stat_buf.st_size = blk_size;
    }

    /* Verify if the file system image has sufficient size. */
    long int min_size = 2 * sectorsize;
    if (stat_buf.st_size < min_size)
    {
        fprintf(stderr, "File is not large enough (size=%ld, min size=%ld)\n", stat_buf.st_size, min_size);
        ret = EXIT_FAILURE;
        goto fclose;
    }

    /* Write superblock (block 0) */
    struct superblock *sb = write_superblock(fd, &stat_buf, i, sectorsize);
    if (!sb)
    {
        perror("write_superblock():");
        ret = EXIT_FAILURE;
        goto fclose;
    }

    free(sb);

fclose:
    close(fd);

    return ret;
}
