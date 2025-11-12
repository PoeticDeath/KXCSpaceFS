// Copyright (c) Anthony Kerr 2025-

#pragma once

typedef char WCHAR;
typedef struct
{
    WCHAR* Buffer;
    unsigned long long Length;
} UNICODE_STRING;

typedef struct
{
	unsigned char uuid[16];
} KMCSpaceFS_UUID;

typedef struct
{
	KMCSpaceFS_UUID uuid;
	unsigned long sectorsize;
	unsigned long long tablesize;
	unsigned long long extratablesize;
	unsigned long long filenamesend;
	unsigned long long tableend;
	unsigned long long size;
	unsigned long long filecount;
	unsigned long long tablestrlen;
	char* table;
	char* tablestr;
	unsigned long long used_blocks;
	unsigned long long CurDictSize;
	unsigned long long DictSize;
	Dict* dict;
	unsigned char* readbuf;
	struct rw_semaphore* readbuflock;
	unsigned char* writebuf;
	struct rw_semaphore* op_lock;
} KMCSpaceFS;

extern unsigned* emap;
extern unsigned* dmap;
void sync_read_phys(unsigned long long offset, unsigned long long length, char* buf, struct block_device* bdev);
void sync_write_phys(unsigned long long offset, unsigned long long length, char* buf, struct block_device* bdev);
void init_maps(void);
char* encode(char* str, unsigned long long len);
char* decode(char* bytes, unsigned long long len);
unsigned long long get_filename_index(UNICODE_STRING FileName, KMCSpaceFS* KMCSFS);
unsigned long long chtime(unsigned long long filenameindex, unsigned long long time, unsigned ch, KMCSpaceFS KMCSFS);
unsigned long chgid(unsigned long long filenameindex, unsigned long gid, KMCSpaceFS KMCSFS);
unsigned long chuid(unsigned long long filenameindex, unsigned long uid, KMCSpaceFS KMCSFS);
unsigned long chmode(unsigned long long filenameindex, unsigned long mode, KMCSpaceFS KMCSFS);
unsigned long chwinattrs(unsigned long long filenameindex, unsigned long winattrs, KMCSpaceFS KMCSFS);
unsigned long long get_file_size(unsigned long long index, KMCSpaceFS KMCSFS);
int read_file(struct block_device* bdev, KMCSpaceFS KMCSFS, uint8_t* data, unsigned long long start, unsigned long long length, unsigned long long index, unsigned long long* bytes_read);
int write_file(struct block_device* bdev, KMCSpaceFS KMCSFS, uint8_t* data, unsigned long long start, unsigned long long length, unsigned long long index, unsigned long long size);
int create_file(struct block_device* bdev, KMCSpaceFS KMCSFS, UNICODE_STRING fn, unsigned long gid, unsigned long uid, unsigned long mode);
void dealloc(KMCSpaceFS* KMCSFS, unsigned long long index, unsigned long long size, unsigned long long newsize);
bool find_block(struct block_device* bdev, KMCSpaceFS* KMCSFS, unsigned long long index, unsigned long long size);
bool delete_file(struct block_device* bdev, KMCSpaceFS* KMCSFS, UNICODE_STRING filename, unsigned long long index);
int rename_file(struct block_device* bdev, KMCSpaceFS* KMCSFS, UNICODE_STRING fn, UNICODE_STRING nfn);