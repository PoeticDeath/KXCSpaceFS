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
	//PERESOURCE readbuflock;
	unsigned char* writebuf;
} KMCSpaceFS;