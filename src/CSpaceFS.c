// Copyright (c) Anthony Kerr 2024-

#include "linuxfs.h"
#include "Dict.h"
#include "cspacefs.h"

unsigned* emap = NULL;
unsigned* dmap = NULL;

static unsigned long long sector_align(unsigned long long n, unsigned long long a)
{
	if (n & (a - 1))
	{
		n = (n + a) & ~(a - 1);
	}

	return n;
}

void sync_read_phys(unsigned long long offset, unsigned long long length, char* buf, struct block_device* bdev)
{
	for (unsigned long long i = 0; i < length; i += 512)
	{
		struct buffer_head* data = __bread(bdev, offset / 512 + i / 512, 512);
		if (data)
		{
			memcpy(buf + i, data->b_data, 512);
			brelse(data);
		}
	}
}

void sync_write_phys(unsigned long long offset, unsigned long long length, char* buf, struct block_device* bdev, bool kern)
{
	for (unsigned long long i = 0; i < length; i += 512)
	{
		struct buffer_head* data = __bread(bdev, offset / 512 + i / 512, 512);
		if (data)
		{
			if (kern)
			{
				memcpy(data->b_data + offset % 512, buf + i, min(512 - offset % 512, length - i));
			}
			else
			{
				copy_from_user(data->b_data + offset % 512, buf + i, min(512 - offset % 512, length - i));
			}
			mark_buffer_dirty(data);
			sync_dirty_buffer(data);
			brelse(data);
		}
		i -= offset % 512;
	}
}

void init_maps(void)
{
	static const char charmap[] = "0123456789-,.; ";
	unsigned p = 0;
	unsigned c;
	emap = kzalloc(65536 * sizeof(unsigned), GFP_KERNEL);
	if (!emap)
	{
		pr_err("out of memory\n");
		return;
	}
	dmap = kzalloc(256 * sizeof(unsigned), GFP_KERNEL);
	if (!dmap)
	{
		pr_err("out of memory\n");
		return;
	}
	for (unsigned i = 0; i < 15; i++)
	{
		for (unsigned o = 0; o < 15; o++)
		{
			c = charmap[i] << 8 | charmap[o];
			emap[c] = p;
			dmap[p] = c;
			p++;
		}
	}
}

char* encode(char* str, unsigned long long len)
{
	char* alc = NULL;
	if (len % 2)
	{
		len++;
		alc = kzalloc(len, GFP_KERNEL);
		if (!alc)
		{
			pr_err("out of memory\n");
			return NULL;
		}
		memcpy(alc, str, len - 1);
		alc[len - 1] = 32;
		alc[len - 2] = 46;
	}
	char* bytes = kzalloc(len / 2 + 1, GFP_KERNEL);
	if (!bytes)
	{
		pr_err("out of memory\n");
		if (alc)
		{
			kfree(alc);
		}
		return NULL;
	}
	if (alc)
	{
		for (unsigned long long i = 0; i < len; i += 2)
		{
			bytes[i / 2] = emap[alc[i] << 8 | alc[i + 1]];
		}
		kfree(alc);
	}
	else
	{
		for (unsigned long long i = 0; i < len; i += 2)
		{
			bytes[i / 2] = emap[str[i] << 8 | str[i + 1]];
		}
	}
	bytes[len / 2] = 0;
	return bytes;
}

char* decode(char* bytes, unsigned long long len)
{
	char* str = kzalloc((len + 1) * 2, GFP_KERNEL);
	if (!str)
	{
		pr_err("out of memory\n");
		return NULL;
	}
	unsigned d;
	for (unsigned long long i = 0; i < len; i++)
	{
		d = dmap[bytes[i] & 0xff];
		str[i * 2] = d >> 8;
		str[i * 2 + 1] = d & 0xff;
	}
	return str;
}

unsigned long long get_filename_index(UNICODE_STRING FileName, KMCSpaceFS* KMCSFS)
{
	unsigned long long loc = 0;
	unsigned long long FileNameLen = FileName.Length / sizeof(WCHAR);
	if (!FileNameLen)
	{
		return 0;
	}

	unsigned long long dindex = FindDictEntry(KMCSFS->dict, KMCSFS->table, KMCSFS->tableend, KMCSFS->DictSize, FileName.Buffer, FileNameLen);
	if (dindex)
	{
		return KMCSFS->dict[dindex].index;
	}

	unsigned j = 0;
	bool found = false;
	bool start = true;
	for (unsigned long long i = 0; i < KMCSFS->filecount + 1; i++)
	{
		for (; loc < KMCSFS->filenamesend - KMCSFS->tableend + 1; loc++)
		{
			if (((KMCSFS->table[KMCSFS->tableend + loc] & 0xff) == 255) || ((KMCSFS->table[KMCSFS->tableend + loc] & 0xff) == 42)) // 255 = file, 42 = fuse symlink
			{
				found = (j == FileNameLen);
				j = 0;
				if (found)
				{
					AddDictEntry(&KMCSFS->dict, FileName.Buffer, loc - FileNameLen, FileNameLen, &KMCSFS->CurDictSize, &KMCSFS->DictSize, i - 1, false);

					return i - 1;
				}
				start = true;
				if ((KMCSFS->table[KMCSFS->tableend + loc] & 0xff) == 255)
				{
					loc++;
					break;
				}
			}
			if (j < FileNameLen)
			{
				if ((incmp((KMCSFS->table[KMCSFS->tableend + loc] & 0xff), (FileName.Buffer[j] & 0xff)) || (((KMCSFS->table[KMCSFS->tableend + loc] & 0xff) == *"/") && ((FileName.Buffer[j] & 0xff) == *"\\"))) && start) // case insensitive, / and \ are the same, make sure it is not just an end or middle of filename
				{
					if ((KMCSFS->table[KMCSFS->tableend + loc] & 0xff) != *"/")
					{
						FileName.Buffer[j] = KMCSFS->table[KMCSFS->tableend + loc] & 0xff;
					}
					j++;
				}
				else
				{
					if ((KMCSFS->table[KMCSFS->tableend + loc] & 0xff) != 42)
					{
						start = false;
					}
					j = 0;
				}
			}
			else
			{
				j++;
			}
		}
	}
	return 0;
}

unsigned long long chtime(unsigned long long filenameindex, unsigned long long time, unsigned ch, KMCSpaceFS KMCSFS)
{ // 24 bytes per file
	unsigned o = 0;
	if (ch == 2 || ch == 3)
	{
		o = 8;
	}
	else if (ch == 4 || ch == 5)
	{
		o = 16;
	}
	if (!(ch % 2))
	{
		char tim[8] = {0};
		memcpy(tim, KMCSFS.table + KMCSFS.filenamesend + 2 + filenameindex * 24 + o, 8);
		char ti[8] = {0};
		for (unsigned i = 0; i < 8; i++)
		{
			ti[i] = tim[7 - i];
		}
		unsigned long long rtime = 0;
		memcpy(&rtime, ti, 8);
		return rtime;
	}
	else
	{
		char ti[8] = {0};
		memcpy(ti, &time, 8);
		char tim[8] = {0};
		for (unsigned i = 0; i < 8; i++)
		{
			tim[i] = ti[7 - i];
		}
		memcpy(KMCSFS.table + KMCSFS.filenamesend + 2 + filenameindex * 24 + o, tim, 8);
		return 0;
	}
}

unsigned long chgid(unsigned long long filenameindex, unsigned long gid, KMCSpaceFS KMCSFS)
{ // First three bytes after times
	if (!gid)
	{
		gid = (KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11] & 0xff) << 16 | (KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 1] & 0xff) << 8 | (KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 2] & 0xff);
		return gid;
	}
	else
	{
		KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11] = (gid >> 16) & 0xff;
		KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 1] = (gid >> 8) & 0xff;
		KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 2] = gid & 0xff;
		return 0;
	}
}

unsigned long chuid(unsigned long long filenameindex, unsigned long uid, KMCSpaceFS KMCSFS)
{ // Next two bytes
	if (!uid)
	{
		uid = (KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 3] & 0xff) << 8 | (KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 4] & 0xff);
		return uid;
	}
	else
	{
		KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 3] = (uid >> 8) & 0xff;
		KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 4] = uid & 0xff;
		return 0;
	}
}

unsigned long chmode(unsigned long long filenameindex, unsigned long mode, KMCSpaceFS KMCSFS)
{ // Next two bytes
	if (!mode)
	{
		mode = (KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 5] & 0xff) << 8 | (KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 6] & 0xff);
		return mode;
	}
	else
	{
		KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 5] = (mode >> 8) & 0xff;
		KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 6] = mode & 0xff;
		return 0;
	}
}

unsigned long chwinattrs(unsigned long long filenameindex, unsigned long winattrs, KMCSpaceFS KMCSFS)
{ // Last four bytes of fileinfo
	if (!winattrs)
	{
		winattrs = (KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 7] & 0xff) << 24 | (KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 8] & 0xff) << 16 | (KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 9] & 0xff) << 8 | (KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 10] & 0xff);
		return winattrs;
	}
	else
	{
		KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 7] = (winattrs >> 24) & 0xff;
		KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 8] = (winattrs >> 16) & 0xff;
		KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 9] = (winattrs >> 8) & 0xff;
		KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 10] = winattrs & 0xff;
		return 0;
	}
}

static unsigned toint(unsigned char c)
{
	switch (c)
	{
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	default:
		return 0;
	}
}

unsigned long long get_file_size(unsigned long long index, KMCSpaceFS KMCSFS)
{
	unsigned long long loc = 0;
	if (index)
	{
		for (unsigned long long i = 0; i < KMCSFS.tablestrlen; i++)
		{
			if (KMCSFS.tablestr[i] == *".")
			{
				loc++;
				if (loc == index)
				{
					loc = i + 1;
					break;
				}
			}
		}
	}

	bool notzero = false;
	bool multisector = false;
	unsigned cur = 0;
	unsigned long long int0 = 0;
	unsigned long long int1 = 0;
	unsigned long long int2 = 0;
	unsigned long long int3 = 0;
	unsigned long long filesize = 0;

	for (unsigned long long i = loc; i < KMCSFS.tablestrlen; i++)
	{
		if (KMCSFS.tablestr[i] == *"," || KMCSFS.tablestr[i] == *".")
		{
			if (notzero)
			{
				if (multisector)
				{
					for (unsigned long long o = 0; o < int0 - int3; o++)
					{
						filesize += KMCSFS.sectorsize;
					}
				}
				switch (cur)
				{
				case 0:
					filesize += KMCSFS.sectorsize;
					break;
				case 1:
					break;
				case 2:
					filesize += int2 - int1;
					break;
				}
			}
			cur = 0;
			int0 = 0;
			int1 = 0;
			int2 = 0;
			int3 = 0;
			multisector = false;
			if (KMCSFS.tablestr[i] == *".")
			{
				break;
			}
		}
		else if (KMCSFS.tablestr[i] == *";")
		{
			cur++;
		}
		else if (KMCSFS.tablestr[i] == *"-")
		{
			int3 = int0;
			multisector = true;
			cur = 0;
			int0 = 0;
			int1 = 0;
			int2 = 0;
		}
		else
		{
			notzero = true;
			switch (cur)
			{
			case 0:
				int0 += toint(KMCSFS.tablestr[i] & 0xff);
				if (KMCSFS.tablestr[i + 1] != *";" && KMCSFS.tablestr[i + 1] != *"," && KMCSFS.tablestr[i + 1] != *"." && KMCSFS.tablestr[i + 1] != *"-")
				{
					int0 *= 10;
				}
				break;
			case 1:
				int1 += toint(KMCSFS.tablestr[i] & 0xff);
				if (KMCSFS.tablestr[i + 1] != *";" && KMCSFS.tablestr[i + 1] != *"," && KMCSFS.tablestr[i + 1] != *"." && KMCSFS.tablestr[i + 1] != *"-")
				{
					int1 *= 10;
				}
				break;
			case 2:
				int2 += toint(KMCSFS.tablestr[i] & 0xff);
				if (KMCSFS.tablestr[i + 1] != *";" && KMCSFS.tablestr[i + 1] != *"," && KMCSFS.tablestr[i + 1] != *"." && KMCSFS.tablestr[i + 1] != *"-")
				{
					int2 *= 10;
				}
				break;
			}
		}
	}

	return filesize;
}

int read_file(struct block_device* bdev, KMCSpaceFS KMCSFS, uint8_t* data, unsigned long long start, unsigned long long length, unsigned long long index, unsigned long long* bytes_read, bool kern)
{
	unsigned long long loc = 0;
	if (index)
	{
		for (unsigned long long i = 0; i < KMCSFS.tablestrlen; i++)
		{
			if (KMCSFS.tablestr[i] == *".")
			{
				loc++;
				if (loc == index)
				{
					loc = i + 1;
					break;
				}
			}
		}
	}

	bool locked = false;
	uint8_t* buf = kzalloc(sector_align(length, KMCSFS.sectorsize), GFP_KERNEL);
	if (!buf)
	{
		if (sector_align(length, KMCSFS.sectorsize) <= KMCSFS.sectorsize)
		{
			locked = true;
			down_write(KMCSFS.readbuflock);
			buf = KMCSFS.readbuf;
		}
		else
		{
			pr_err("out of memory\n");
			return -ENOMEM;
		}
	}

	bool init = true;
	bool notzero = false;
	bool multisector = false;
	unsigned cur = 0;
	unsigned long long int0 = 0;
	unsigned long long int1 = 0;
	unsigned long long int2 = 0;
	unsigned long long int3 = 0;
	unsigned long long filesize = 0;

	for (unsigned long long i = loc; i < KMCSFS.tablestrlen; i++)
	{
		if (KMCSFS.tablestr[i] == *"," || KMCSFS.tablestr[i] == *".")
		{
			if (notzero)
			{
				if (multisector)
				{
					for (unsigned long long o = 0; o < int0 - int3; o++)
					{
						filesize += KMCSFS.sectorsize;
						if (filesize > start)
						{
							if (init)
							{
								sync_read_phys(KMCSFS.size - KMCSFS.sectorsize - (int3 + o) * KMCSFS.sectorsize + (start % KMCSFS.sectorsize) - (start % 512), min(sector_align(KMCSFS.sectorsize - start % KMCSFS.sectorsize, 512), sector_align(length, 512)), buf + (start % KMCSFS.sectorsize) - (start % 512), bdev);
								if (kern)
								{
									memcpy(data, buf + (start % KMCSFS.sectorsize), min(KMCSFS.sectorsize - start % KMCSFS.sectorsize, length));
								}
								else
								{
									copy_to_user(data, buf + (start % KMCSFS.sectorsize), min(KMCSFS.sectorsize - start % KMCSFS.sectorsize, length));
								}
								*bytes_read += min(KMCSFS.sectorsize - start % KMCSFS.sectorsize, length);
								start += min(KMCSFS.sectorsize - start % KMCSFS.sectorsize, length);
								init = false;
							}
							else
							{
								sync_read_phys(KMCSFS.size - KMCSFS.sectorsize - (int3 + o) * KMCSFS.sectorsize, min(KMCSFS.sectorsize, length - *bytes_read), buf, bdev);
								if (kern)
								{
									memcpy(data + *bytes_read, buf, min(KMCSFS.sectorsize, length - *bytes_read));
								}
								else
								{
									copy_to_user(data + *bytes_read, buf, min(KMCSFS.sectorsize, length - *bytes_read));
								}
								start += min(KMCSFS.sectorsize, length - *bytes_read);
								*bytes_read += min(KMCSFS.sectorsize, length - *bytes_read);
							}
						}
					}
				}
				switch (cur)
				{
				case 0:
					filesize += KMCSFS.sectorsize;
					if (filesize > start)
					{
						if (init)
						{
							sync_read_phys(KMCSFS.size - KMCSFS.sectorsize - int0 * KMCSFS.sectorsize + (start % KMCSFS.sectorsize) - (start % 512), min(sector_align(KMCSFS.sectorsize - start % KMCSFS.sectorsize, 512), sector_align(length, 512)), buf + (start % KMCSFS.sectorsize) - (start % 512), bdev);
							if (kern)
							{
								memcpy(data, buf + (start % KMCSFS.sectorsize), min(KMCSFS.sectorsize - start % KMCSFS.sectorsize, length));
							}
							else
							{
								copy_to_user(data, buf + (start % KMCSFS.sectorsize), min(KMCSFS.sectorsize - start % KMCSFS.sectorsize, length));
							}
							*bytes_read += min(KMCSFS.sectorsize - start % KMCSFS.sectorsize, length);
							start += min(KMCSFS.sectorsize - start % KMCSFS.sectorsize, length);
							init = false;
						}
						else
						{
							sync_read_phys(KMCSFS.size - KMCSFS.sectorsize - int0 * KMCSFS.sectorsize, min(KMCSFS.sectorsize, length - *bytes_read), buf, bdev);
							if (kern)
							{
								memcpy(data + *bytes_read, buf, min(KMCSFS.sectorsize, length - *bytes_read));
							}
							else
							{
								copy_to_user(data + *bytes_read, buf, min(KMCSFS.sectorsize, length - *bytes_read));
							}
							start += min(KMCSFS.sectorsize, length - *bytes_read);
							*bytes_read += min(KMCSFS.sectorsize, length - *bytes_read);
						}
					}
					break;
				case 1:
					break;
				case 2:
					filesize += int2 - int1;
					if (filesize > start)
					{
						sync_read_phys(KMCSFS.size - KMCSFS.sectorsize - int0 * KMCSFS.sectorsize + int1 - int1 % 512, sector_align(int2 - int1 + int1 % 512, 512), buf + int1 - int1 % 512, bdev);
						if (init)
						{
							if (kern)
							{
								memcpy(data, buf + int1 + (start % KMCSFS.sectorsize), min(int2 - int1, length));
							}
							else
							{
								copy_to_user(data, buf + int1 + (start % KMCSFS.sectorsize), min(int2 - int1, length));
							}
							start += min(int2 - int1, length);
							*bytes_read += min(int2 - int1, length);
							init = false;
						}
						else
						{
							if (kern)
							{
								memcpy(data + *bytes_read, buf + int1, min(int2 - int1, length - *bytes_read));
							}
							else
							{
								copy_to_user(data + *bytes_read, buf + int1, min(int2 - int1, length - *bytes_read));
							}
							start += min(int2 - int1, length - *bytes_read);
							*bytes_read += min(int2 - int1, length - *bytes_read);
						}
					}
					break;
				}
			}
			if (*bytes_read == length)
			{
				if (locked)
				{
					up_write(KMCSFS.readbuflock);
				}
				else
				{
					kfree(buf);
				}
				return 0;
			}
			cur = 0;
			int0 = 0;
			int1 = 0;
			int2 = 0;
			int3 = 0;
			multisector = false;
			if (KMCSFS.tablestr[i] == *".")
			{
				break;
			}
		}
		else if (KMCSFS.tablestr[i] == *";")
		{
			cur++;
		}
		else if (KMCSFS.tablestr[i] == *"-")
		{
			int3 = int0;
			multisector = true;
			cur = 0;
			int0 = 0;
			int1 = 0;
			int2 = 0;
		}
		else
		{
			notzero = true;
			switch (cur)
			{
			case 0:
				int0 += toint(KMCSFS.tablestr[i] & 0xff);
				if (KMCSFS.tablestr[i + 1] != *";" && KMCSFS.tablestr[i + 1] != *"," && KMCSFS.tablestr[i + 1] != *"." && KMCSFS.tablestr[i + 1] != *"-")
				{
					int0 *= 10;
				}
				break;
			case 1:
				int1 += toint(KMCSFS.tablestr[i] & 0xff);
				if (KMCSFS.tablestr[i + 1] != *";" && KMCSFS.tablestr[i + 1] != *"," && KMCSFS.tablestr[i + 1] != *"." && KMCSFS.tablestr[i + 1] != *"-")
				{
					int1 *= 10;
				}
				break;
			case 2:
				int2 += toint(KMCSFS.tablestr[i] & 0xff);
				if (KMCSFS.tablestr[i + 1] != *";" && KMCSFS.tablestr[i + 1] != *"," && KMCSFS.tablestr[i + 1] != *"." && KMCSFS.tablestr[i + 1] != *"-")
				{
					int2 *= 10;
				}
				break;
			}
		}
	}
	if (locked)
	{
		up_write(KMCSFS.readbuflock);
	}
	else
	{
		kfree(buf);
	}
	return 0;
}

int write_file(struct block_device* bdev, KMCSpaceFS KMCSFS, uint8_t* data, unsigned long long start, unsigned long long length, unsigned long long index, unsigned long long size, unsigned long long* bytes_written, bool kern)
{
	unsigned long long loc = 0;
	if (index)
	{
		for (unsigned long long i = 0; i < KMCSFS.tablestrlen; i++)
		{
			if (KMCSFS.tablestr[i] == *".")
			{
				loc++;
				if (loc == index)
				{
					loc = i + 1;
					break;
				}
			}
		}
	}

	bool init = true;
	bool notzero = false;
	bool multisector = false;
	unsigned cur = 0;
	unsigned long long int0 = 0;
	unsigned long long int1 = 0;
	unsigned long long int2 = 0;
	unsigned long long int3 = 0;
	unsigned long long filesize = 0;

	for (unsigned long long i = loc; i < KMCSFS.tablestrlen; i++)
	{
		if (KMCSFS.tablestr[i] == *"," || KMCSFS.tablestr[i] == *".")
		{
			if (notzero)
			{
				if (multisector)
				{
					for (unsigned long long o = 0; o < int0 - int3; o++)
					{
						filesize += KMCSFS.sectorsize;
						if (filesize > start)
						{
							if (init)
							{
								sync_write_phys(KMCSFS.size - KMCSFS.sectorsize - (int3 + o) * KMCSFS.sectorsize + (start % KMCSFS.sectorsize), min(KMCSFS.sectorsize - start % KMCSFS.sectorsize, length), data, bdev, kern);
								*bytes_written += min(KMCSFS.sectorsize - start % KMCSFS.sectorsize, length);
								start += min(KMCSFS.sectorsize - start % KMCSFS.sectorsize, length);
								init = false;
							}
							else
							{
								sync_write_phys(KMCSFS.size - KMCSFS.sectorsize - (int3 + o) * KMCSFS.sectorsize, min(KMCSFS.sectorsize, length - *bytes_written), data + *bytes_written, bdev, kern);
								start += min(KMCSFS.sectorsize, length - *bytes_written);
								*bytes_written += min(KMCSFS.sectorsize, length - *bytes_written);
							}
						}
					}
				}
				switch (cur)
				{
				case 0:
					filesize += KMCSFS.sectorsize;
					if (filesize > start)
					{
						if (init)
						{
							sync_write_phys(KMCSFS.size - KMCSFS.sectorsize - int0 * KMCSFS.sectorsize + (start % KMCSFS.sectorsize), min(KMCSFS.sectorsize - start % KMCSFS.sectorsize, length), data, bdev, kern);
							*bytes_written += min(KMCSFS.sectorsize - start % KMCSFS.sectorsize, length);
							start += min(KMCSFS.sectorsize - start % KMCSFS.sectorsize, length);
							init = false;
						}
						else
						{
							sync_write_phys(KMCSFS.size - KMCSFS.sectorsize - int0 * KMCSFS.sectorsize, min(KMCSFS.sectorsize, length - *bytes_written), data + *bytes_written, bdev, kern);
							start += min(KMCSFS.sectorsize, length - *bytes_written);
							*bytes_written += min(KMCSFS.sectorsize, length - *bytes_written);
						}
					}
					break;
				case 1:
					break;
				case 2:
					filesize += int2 - int1;
					if (filesize > start)
					{
						if (init)
						{
							sync_write_phys(KMCSFS.size - KMCSFS.sectorsize - int0 * KMCSFS.sectorsize + int1 + (start % KMCSFS.sectorsize), min(int2 - int1 - start % KMCSFS.sectorsize, length), data, bdev, kern);
							*bytes_written += min(int2 - int1 - start % KMCSFS.sectorsize, length);
							start += min(int2 - int1 - start % KMCSFS.sectorsize, length);
							init = false;
						}
						else
						{
							sync_write_phys(KMCSFS.size - KMCSFS.sectorsize - int0 * KMCSFS.sectorsize + int1, min(int2 - int1, length - *bytes_written), data + *bytes_written, bdev, kern);
							start += min(int2 - int1, length - *bytes_written);
							*bytes_written += min(int2 - int1, length - *bytes_written);
						}
					}
					break;
				}
			}
			if (*bytes_written == length)
			{
				return 0;
			}
			cur = 0;
			int0 = 0;
			int1 = 0;
			int2 = 0;
			int3 = 0;
			multisector = false;
			if (KMCSFS.tablestr[i] == *".")
			{
				break;
			}
		}
		else if (KMCSFS.tablestr[i] == *";")
		{
			cur++;
		}
		else if (KMCSFS.tablestr[i] == *"-")
		{
			int3 = int0;
			multisector = true;
			cur = 0;
			int0 = 0;
			int1 = 0;
			int2 = 0;
		}
		else
		{
			notzero = true;
			switch (cur)
			{
			case 0:
				int0 += toint(KMCSFS.tablestr[i] & 0xff);
				if (KMCSFS.tablestr[i + 1] != *";" && KMCSFS.tablestr[i + 1] != *"," && KMCSFS.tablestr[i + 1] != *"." && KMCSFS.tablestr[i + 1] != *"-")
				{
					int0 *= 10;
				}
				break;
			case 1:
				int1 += toint(KMCSFS.tablestr[i] & 0xff);
				if (KMCSFS.tablestr[i + 1] != *";" && KMCSFS.tablestr[i + 1] != *"," && KMCSFS.tablestr[i + 1] != *"." && KMCSFS.tablestr[i + 1] != *"-")
				{
					int1 *= 10;
				}
				break;
			case 2:
				int2 += toint(KMCSFS.tablestr[i] & 0xff);
				if (KMCSFS.tablestr[i + 1] != *";" && KMCSFS.tablestr[i + 1] != *"," && KMCSFS.tablestr[i + 1] != *"." && KMCSFS.tablestr[i + 1] != *"-")
				{
					int2 *= 10;
				}
				break;
			}
		}
	}
	return 0;
}

static bool is_table_expandable(KMCSpaceFS KMCSFS, unsigned long long newsize)
{
	unsigned long long nearestsector = 0;

	bool multisector = false;
	unsigned cur = 0;
	unsigned long long int0 = 0;
	unsigned long long int1 = 0;
	unsigned long long int2 = 0;
	unsigned long long int3 = 0;

	for (unsigned long long i = 0; i < KMCSFS.tablestrlen; i++)
	{
		if (KMCSFS.tablestr[i] == *"," || KMCSFS.tablestr[i] == *".")
		{
			if (multisector)
			{
				for (unsigned long long o = 0; o < int0 - int3; o++)
				{
					nearestsector = max(nearestsector, int3 + o);
				}
			}
			switch (cur)
			{
			case 0:
				nearestsector = max(nearestsector, int0);
				break;
			case 1:
				break;
			case 2:
				nearestsector = max(nearestsector, int0);
				break;
			}
			cur = 0;
			int0 = 0;
			int1 = 0;
			int2 = 0;
			int3 = 0;
			multisector = false;
		}
		else if (KMCSFS.tablestr[i] == *";")
		{
			cur++;
		}
		else if (KMCSFS.tablestr[i] == *"-")
		{
			int3 = int0;
			multisector = true;
			cur = 0;
			int0 = 0;
			int1 = 0;
			int2 = 0;
		}
		else
		{
			switch (cur)
			{
			case 0:
				int0 += toint(KMCSFS.tablestr[i] & 0xff);
				if (KMCSFS.tablestr[i + 1] != *";" && KMCSFS.tablestr[i + 1] != *"," && KMCSFS.tablestr[i + 1] != *"." && KMCSFS.tablestr[i + 1] != *"-")
				{
					int0 *= 10;
				}
				break;
			case 1:
				int1 += toint(KMCSFS.tablestr[i] & 0xff);
				if (KMCSFS.tablestr[i + 1] != *";" && KMCSFS.tablestr[i + 1] != *"," && KMCSFS.tablestr[i + 1] != *"." && KMCSFS.tablestr[i + 1] != *"-")
				{
					int1 *= 10;
				}
				break;
			case 2:
				int2 += toint(KMCSFS.tablestr[i] & 0xff);
				if (KMCSFS.tablestr[i + 1] != *";" && KMCSFS.tablestr[i + 1] != *"," && KMCSFS.tablestr[i + 1] != *"." && KMCSFS.tablestr[i + 1] != *"-")
				{
					int2 *= 10;
				}
				break;
			}
		}
	}

	return KMCSFS.size / KMCSFS.sectorsize - nearestsector > sector_align(newsize, KMCSFS.sectorsize) / KMCSFS.sectorsize;
}

int create_file(struct block_device* bdev, KMCSpaceFS* KMCSFS, UNICODE_STRING fn, unsigned long gid, unsigned long uid, unsigned long mode)
{
	if ((fn.Buffer[fn.Length / sizeof(WCHAR) - 1] & 0xff) == 0)
	{
		fn.Length -= sizeof(WCHAR);
	}

	if (!is_table_expandable(*KMCSFS, KMCSFS->filenamesend + 2 + fn.Length / sizeof(WCHAR) + 1 + 35 * (KMCSFS->filecount + 1)))
	{
		pr_err("table is not expandable\n");
		return -ENOSPC;
	}

	char* newtablestr = kzalloc(KMCSFS->tablestrlen + 2, GFP_KERNEL);
	if (!newtablestr)
	{
		pr_err("out of memory\n");
		return -ENOMEM;
	}

	memcpy(newtablestr, KMCSFS->tablestr, KMCSFS->tablestrlen);
	if (newtablestr[KMCSFS->tablestrlen - 1] == 32)
	{
		newtablestr[KMCSFS->tablestrlen - 1] = 46;
		newtablestr[KMCSFS->tablestrlen] = 32;
		newtablestr[KMCSFS->tablestrlen + 1] = 0;
	}
	else
	{
		newtablestr[KMCSFS->tablestrlen] = 46;
		newtablestr[KMCSFS->tablestrlen + 1] = 0;
		KMCSFS->tablestrlen++;
	}

	char* newtable = kzalloc(5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend + 1 + fn.Length / sizeof(WCHAR) + 2 + 35 * (KMCSFS->filecount + 1), GFP_KERNEL);
	if (!newtable)
	{
		pr_err("out of memory\n");
		kfree(newtablestr);
		return -ENOMEM;
	}
	memset(newtable, 0, 5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend + 1 + fn.Length / sizeof(WCHAR) + 2 + 35 * (KMCSFS->filecount + 1));

	char* newtablestren = encode(newtablestr, KMCSFS->tablestrlen);
	if (!newtablestren)
	{
		pr_err("out of memory\n");
		kfree(newtablestr);
		kfree(newtable);
		return -ENOMEM;
	}

	kfree(KMCSFS->tablestr);
	KMCSFS->tablestr = newtablestr;

	newtable[0] = KMCSFS->table[0];
	unsigned long long extratablesize = 5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend + 2 + fn.Length / sizeof(WCHAR) + 1 + 35 * (KMCSFS->filecount + 1);
	unsigned long long tablesize = (extratablesize + KMCSFS->sectorsize - 1) / KMCSFS->sectorsize - 1;
	newtable[1] = (tablesize >> 24) & 0xff;
	newtable[2] = (tablesize >> 16) & 0xff;
	newtable[3] = (tablesize >> 8) & 0xff;
	newtable[4] = tablesize & 0xff;
	KMCSFS->extratablesize = sector_align(extratablesize, KMCSFS->sectorsize);
	KMCSFS->tablesize = 1 + tablesize;

	memcpy(newtable + 5, newtablestren, (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2);
	kfree(newtablestren);

	memcpy(newtable + 5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2, KMCSFS->table + KMCSFS->tableend, KMCSFS->filenamesend - KMCSFS->tableend);

	newtable[5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend] = 255;
	for (unsigned long long i = 0; i < fn.Length / sizeof(WCHAR); i++)
	{
		newtable[5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend + 1 + i] = ((fn.Buffer[i] & 0xff) == 92) ? 47 : fn.Buffer[i] & 0xff;
	}
	newtable[5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend + 1 + fn.Length / sizeof(WCHAR)] = 255;
	newtable[5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend + 1 + fn.Length / sizeof(WCHAR) + 1] = 254;

	memcpy(newtable + 5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend + 1 + fn.Length / sizeof(WCHAR) + 2, KMCSFS->table + KMCSFS->filenamesend + 2, 24 * KMCSFS->filecount);
	memcpy(newtable + 5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend + 1 + fn.Length / sizeof(WCHAR) + 2 + 24 * (KMCSFS->filecount + 1), KMCSFS->table + KMCSFS->filenamesend + 2 + 24 * KMCSFS->filecount, 11 * KMCSFS->filecount);

	char guidmodes[11] = {0};
	guidmodes[0] = (gid >> 16) & 0xff;
	guidmodes[1] = (gid >> 8) & 0xff;
	guidmodes[2] = gid & 0xff;
	guidmodes[3] = (uid >> 8) & 0xff;
	guidmodes[4] = uid & 0xff;
	guidmodes[5] = (mode >> 8) & 0xff;
	guidmodes[6] = mode & 0xff;
	unsigned long winattrs = 2048 | S_ISDIR(mode) * 8192;
	guidmodes[7] = (winattrs >> 24) & 0xff;
	guidmodes[8] = (winattrs >> 16) & 0xff;
	guidmodes[9] = (winattrs >> 8) & 0xff;
	guidmodes[10] = winattrs & 0xff;
	memcpy(newtable + 5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend + 1 + fn.Length / sizeof(WCHAR) + 2 + 24 * (KMCSFS->filecount + 1) + 11 * KMCSFS->filecount, guidmodes, 11);

	kfree(KMCSFS->table);
	KMCSFS->table = newtable;

	AddDictEntry(&KMCSFS->dict, fn.Buffer, KMCSFS->filenamesend - KMCSFS->tableend + 1, fn.Length / sizeof(WCHAR), &KMCSFS->CurDictSize, &KMCSFS->DictSize, KMCSFS->filecount, false);

	KMCSFS->filenamesend = 5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend + 1 + fn.Length / sizeof(WCHAR);
	KMCSFS->tableend = 5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2;

	ktime_t time = ktime_get();
	chtime(KMCSFS->filecount, time, 5, *KMCSFS);
	chtime(KMCSFS->filecount, time, 1, *KMCSFS);
	chtime(KMCSFS->filecount, time, 3, *KMCSFS);

	KMCSFS->filecount++;
	sync_write_phys(0, KMCSFS->filenamesend + 2 + 35 * KMCSFS->filecount, newtable, bdev, true);

	return 0;
}

void dealloc(KMCSpaceFS* KMCSFS, unsigned long long index, unsigned long long size, unsigned long long newsize)
{
	if (size > newsize)
	{
		unsigned long long loc = 0;
		if (index)
		{
			for (unsigned long long i = 0; i < KMCSFS->tablestrlen; i++)
			{
				if (KMCSFS->tablestr[i] == *".")
				{
					loc++;
					if (loc == index)
					{
						loc = i + 1;
						break;
					}
				}
			}
		}

		bool notzero = false;
		bool multisector = false;
		unsigned cur = 0;
		unsigned long long int0 = 0;
		unsigned long long int1 = 0;
		unsigned long long int2 = 0;
		unsigned long long int3 = 0;
		unsigned long long filesize = 0;
		unsigned long long offset = loc;

		for (unsigned long long i = loc; i < KMCSFS->tablestrlen; i++)
		{
			if (KMCSFS->tablestr[i] == *"," || KMCSFS->tablestr[i] == *".")
			{
				if (notzero)
				{
					if (multisector)
					{
						unsigned long long o = 0;
						for (; o < int0 - int3; o++)
						{
							filesize += KMCSFS->sectorsize;
							if (filesize > newsize)
							{
								break;
							}
						}
						if (filesize > newsize)
						{
							if (o)
							{
								if (o == 1)
								{
									char num0[21] = {0};
									sprintf(num0, "%llu", int3);
									unsigned num0len = strlen(num0);
									memcpy(KMCSFS->tablestr + offset + num0len, KMCSFS->tablestr + i, KMCSFS->tablestrlen - i + num0len);
									memset(KMCSFS->tablestr + KMCSFS->tablestrlen - i + offset + num0len, 0, i - offset - num0len);
									KMCSFS->tablestrlen -= i - offset - num0len;
									i = offset + num0len;
								}
								else
								{
									char num0[21] = {0};
									sprintf(num0, "%llu", int3);
									unsigned num0len = strlen(num0);
									char num1[21] = {0};
									sprintf(num1, "%llu", int3 + o - 1);
									unsigned num1len = strlen(num1);
									memcpy(KMCSFS->tablestr + offset + num0len + 1, num1, num1len);
									memcpy(KMCSFS->tablestr + offset + num0len + 1 + num1len, KMCSFS->tablestr + i, KMCSFS->tablestrlen - i + num0len + 1 + num1len);
									memset(KMCSFS->tablestr + KMCSFS->tablestrlen - i + offset + num0len + 1 + num1len, 0, i - offset - num0len - 1 - num1len);
									KMCSFS->tablestrlen -= i - offset - num0len - 1 - num1len;
									i = offset + num0len + 1 + num1len;
								}
							}
							else
							{
								memcpy(KMCSFS->tablestr + offset, KMCSFS->tablestr + i, KMCSFS->tablestrlen - i);
								memset(KMCSFS->tablestr + KMCSFS->tablestrlen - i + offset, 0, i - offset);
								KMCSFS->tablestrlen -= i - offset;
								i = offset;
							}
						}
						else
						{
							offset = i;
						}
					}
					switch (cur)
					{
					case 0:
						filesize += KMCSFS->sectorsize;
						if (filesize > newsize)
						{
							memcpy(KMCSFS->tablestr + offset, KMCSFS->tablestr + i, KMCSFS->tablestrlen - i);
							memset(KMCSFS->tablestr + KMCSFS->tablestrlen - i + offset, 0, i - offset);
							KMCSFS->tablestrlen -= i - offset;
							i = offset;
						}
						else
						{
							offset = i;
						}
						break;
					case 1:
						break;
					case 2:
						filesize += int2 - int1;
						if (filesize > newsize)
						{
							memcpy(KMCSFS->tablestr + offset, KMCSFS->tablestr + i, KMCSFS->tablestrlen - i);
							memset(KMCSFS->tablestr + KMCSFS->tablestrlen - i + offset, 0, i - offset);
							KMCSFS->tablestrlen -= i - offset;
							i = offset;
						}
						else
						{
							offset = i;
						}
						break;
					}
				}
				cur = 0;
				int0 = 0;
				int1 = 0;
				int2 = 0;
				int3 = 0;
				multisector = false;
				if (KMCSFS->tablestr[i] == *".")
				{
					break;
				}
			}
			else if (KMCSFS->tablestr[i] == *";")
			{
				cur++;
			}
			else if (KMCSFS->tablestr[i] == *"-")
			{
				int3 = int0;
				multisector = true;
				cur = 0;
				int0 = 0;
				int1 = 0;
				int2 = 0;
			}
			else
			{
				notzero = true;
				switch (cur)
				{
				case 0:
					int0 += toint(KMCSFS->tablestr[i] & 0xff);
					if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
					{
						int0 *= 10;
					}
					break;
				case 1:
					int1 += toint(KMCSFS->tablestr[i] & 0xff);
					if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
					{
						int1 *= 10;
					}
					break;
				case 2:
					int2 += toint(KMCSFS->tablestr[i] & 0xff);
					if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
					{
						int2 *= 10;
					}
					break;
				}
			}
		}

		KMCSFS->used_blocks -= size / KMCSFS->sectorsize;
		KMCSFS->used_blocks += newsize / KMCSFS->sectorsize;
	}
}

bool find_block(struct block_device* bdev, KMCSpaceFS* KMCSFS, unsigned long long index, unsigned long long size)
{
	if (size)
	{
		unsigned long* used_bytes = kzalloc((KMCSFS->size / KMCSFS->sectorsize - KMCSFS->tablesize) * sizeof(unsigned long), GFP_KERNEL);
		if (!used_bytes)
		{
			pr_err("out of memory\n");
			return false;
		}
		memset(used_bytes, 0, (KMCSFS->size / KMCSFS->sectorsize - KMCSFS->tablesize) * sizeof(unsigned long));
		unsigned long long endsector = 0;
		unsigned long long endoffset = 0;
		unsigned long long endlength = 0;
		unsigned long long endrlength = 0;
		bool notzero = false;
		bool multisector = false;
		unsigned cur = 0;
		unsigned long long int0 = 0;
		unsigned long long int1 = 0;
		unsigned long long int2 = 0;
		unsigned long long int3 = 0;
		unsigned long long curindex = 0;
		unsigned long long cursize = 0;
		for (unsigned long long i = 0; i < KMCSFS->tablestrlen; i++)
		{
			if (KMCSFS->tablestr[i] == *"," || KMCSFS->tablestr[i] == *".")
			{
				if (notzero)
				{
					if (multisector)
					{
						for (unsigned long long o = 0; o < int0 - int3; o++)
						{
							used_bytes[int3 + o] += KMCSFS->sectorsize;
							if (curindex == index)
							{
								cursize += KMCSFS->sectorsize;
							}
						}
					}
					switch (cur)
					{
					case 0:
						used_bytes[int0] += KMCSFS->sectorsize;
						if (curindex == index)
						{
							cursize += KMCSFS->sectorsize;
						}
						break;
					case 1:
						break;
					case 2:
						used_bytes[int0] += int2 - int1;
						if (curindex == index)
						{
							cursize += int2 - int1;
							endsector = int0;
							endoffset = int1;
							endlength = int2 - int1;
							endrlength = endlength + endoffset % 512;
							endrlength += (512 - endrlength % 512) % 512;
						}
						break;
					}
				}
				cur = 0;
				int0 = 0;
				int1 = 0;
				int2 = 0;
				int3 = 0;
				notzero = false;
				multisector = false;
				if (KMCSFS->tablestr[i] == *".")
				{
					curindex++;
				}
			}
			else if (KMCSFS->tablestr[i] == *";")
			{
				cur++;
			}
			else if (KMCSFS->tablestr[i] == *"-")
			{
				int3 = int0;
				multisector = true;
				cur = 0;
				int0 = 0;
				int1 = 0;
				int2 = 0;
			}
			else
			{
				notzero = true;
				switch (cur)
				{
				case 0:
					int0 += toint(KMCSFS->tablestr[i] & 0xff);
					if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
					{
						int0 *= 10;
					}
					break;
				case 1:
					int1 += toint(KMCSFS->tablestr[i] & 0xff);
					if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
					{
						int1 *= 10;
					}
					break;
				case 2:
					int2 += toint(KMCSFS->tablestr[i] & 0xff);
					if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
					{
						int2 *= 10;
					}
					break;
				}
			}
		}

		unsigned long long loc = 0;
		if (!(cursize % KMCSFS->sectorsize))
		{
			for (unsigned long long i = 0; i < KMCSFS->tablestrlen; i++)
			{
				if (KMCSFS->tablestr[i] == *".")
				{
					loc++;
					if (loc == index + 1)
					{
						loc = i;
						break;
					}
				}
			}
		}

		unsigned char* tempdata = NULL;
		unsigned long long newoffset = 0;
		unsigned long long cursector = 0;
		unsigned long long blocksneeded = (size + KMCSFS->sectorsize - 1) / KMCSFS->sectorsize;
		for (unsigned long long i = 0; i < blocksneeded; i++)
		{
			if (cursize % KMCSFS->sectorsize)
			{ // Last block was part sector
				tempdata = kzalloc(endrlength, GFP_KERNEL);
				if (!tempdata)
				{
					pr_err("out of memory\n");
					kfree(used_bytes);
					return false;
				}
				sync_read_phys(KMCSFS->size - endsector * KMCSFS->sectorsize - KMCSFS->sectorsize + endoffset - endoffset % 512, endrlength, tempdata, bdev);
				dealloc(KMCSFS, index, cursize, cursize - cursize % KMCSFS->sectorsize);
				used_bytes[endsector] -= cursize % KMCSFS->sectorsize;
				size += cursize % KMCSFS->sectorsize;
				blocksneeded = (size + KMCSFS->sectorsize - 1) / KMCSFS->sectorsize;
				cursize -= cursize % KMCSFS->sectorsize;
				for (unsigned long long o = 0; o < KMCSFS->tablestrlen; o++)
				{
					if (KMCSFS->tablestr[o] == *".")
					{
						loc++;
						if (loc == index + 1)
						{
							loc = o;
							break;
						}
					}
				}
			}
			if (!(size % KMCSFS->sectorsize) || i < blocksneeded - 1)
			{ // Full sector allocation
				for (; cursector < (KMCSFS->size / KMCSFS->sectorsize - KMCSFS->tablesize); cursector++)
				{
					if (!used_bytes[cursector])
					{
						if (cursize)
						{
							char* newtable = kzalloc(KMCSFS->tablestrlen + 22, GFP_KERNEL);
							if (!newtable)
							{
								pr_err("out of memory\n");
								kfree(used_bytes);
								return false;
							}
							memcpy(newtable, KMCSFS->tablestr, loc);
							newtable[loc] = *",";
							char num[21] = {0};
							sprintf(num, "%llu", cursector);
							unsigned numlen = strlen(num);
							memcpy(newtable + loc + 1, num, numlen);
							memcpy(newtable + loc + numlen + 1, KMCSFS->tablestr + loc, KMCSFS->tablestrlen - loc);
							kfree(KMCSFS->tablestr);
							KMCSFS->tablestr = newtable;
							KMCSFS->tablestrlen += numlen + 1;
							loc += numlen + 1;
							cursize += KMCSFS->sectorsize;
							used_bytes[cursector] += KMCSFS->sectorsize;
							size -= KMCSFS->sectorsize;
							KMCSFS->used_blocks++;
						}
						else
						{
							char* newtable = kzalloc(KMCSFS->tablestrlen + 21, GFP_KERNEL);
							if (!newtable)
							{
								pr_err("out of memory\n");
								kfree(used_bytes);
								return false;
							}
							memcpy(newtable, KMCSFS->tablestr, loc);
							char num[21] = {0};
							sprintf(num, "%llu", cursector);
							unsigned numlen = strlen(num);
							memcpy(newtable + loc, num, numlen);
							memcpy(newtable + loc + numlen, KMCSFS->tablestr + loc, KMCSFS->tablestrlen - loc);
							kfree(KMCSFS->tablestr);
							KMCSFS->tablestr = newtable;
							KMCSFS->tablestrlen += numlen;
							loc += numlen;
							cursize += KMCSFS->sectorsize;
							used_bytes[cursector] += KMCSFS->sectorsize;
							size -= KMCSFS->sectorsize;
							KMCSFS->used_blocks++;
						}
						break;
					}
				}
			}
			else
			{ // Part sector allocation
				char* tablestr = NULL;
				unsigned long long* used_sector_bytes = NULL;
				unsigned long long temptablestrlen = KMCSFS->tablestrlen;
				for (cursector = 0; cursector < (KMCSFS->size / KMCSFS->sectorsize - KMCSFS->tablesize); cursector++)
				{
					if (!used_bytes[cursector])
					{
						if (cursize)
						{
							char* newtable = kzalloc(KMCSFS->tablestrlen + 64, GFP_KERNEL);
							if (!newtable)
							{
								pr_err("out of memory\n");
								kfree(used_bytes);
								return false;
							}
							memcpy(newtable, KMCSFS->tablestr, loc);
							newtable[loc] = *",";
							char num1[21] = {0};
							sprintf(num1, "%llu", cursector);
							unsigned num1len = strlen(num1);
							memcpy(newtable + loc + 1, num1, num1len);
							newtable[loc + 1 + num1len] = *";";
							newtable[loc + 1 + num1len + 1] = *"0";
							newtable[loc + 1 + num1len + 2] = *";";
							char num3[21] = {0};
							sprintf(num3, "%llu", size % KMCSFS->sectorsize);
							unsigned num3len = strlen(num3);
							memcpy(newtable + loc + 1 + num1len + 3, num3, num3len);
							memcpy(newtable + loc + 1 + num1len + 3 + num3len, KMCSFS->tablestr + loc, KMCSFS->tablestrlen - loc);
							kfree(KMCSFS->tablestr);
							KMCSFS->tablestr = newtable;
							KMCSFS->tablestrlen += num1len + num3len + 4;
							loc += num1len + num3len + 4;
							cursize += size % KMCSFS->sectorsize;
							used_bytes[cursector] += size % KMCSFS->sectorsize;
							size -= size % KMCSFS->sectorsize;
							if (used_bytes[cursector] == KMCSFS->sectorsize)
							{
								KMCSFS->used_blocks++;
							}
						}
						else
						{
							char* newtable = kzalloc(KMCSFS->tablestrlen + 63, GFP_KERNEL);
							if (!newtable)
							{
								pr_err("out of memory\n");
								kfree(used_bytes);
								return false;
							}
							memcpy(newtable, KMCSFS->tablestr, loc);
							char num1[21] = {0};
							sprintf(num1, "%llu", cursector);
							unsigned num1len = strlen(num1);
							memcpy(newtable + loc, num1, num1len);
							newtable[loc + num1len] = *";";
							newtable[loc + num1len + 1] = *"0";
							newtable[loc + num1len + 2] = *";";
							char num3[21] = {0};
							sprintf(num3, "%llu", size % KMCSFS->sectorsize);
							unsigned num3len = strlen(num3);
							memcpy(newtable + loc + num1len + 3, num3, num3len);
							memcpy(newtable + loc + num1len + 3 + num3len, KMCSFS->tablestr + loc, KMCSFS->tablestrlen - loc);
							kfree(KMCSFS->tablestr);
							KMCSFS->tablestr = newtable;
							KMCSFS->tablestrlen += num1len + num3len + 3;
							loc += num1len + num3len + 3;
							cursize += size % KMCSFS->sectorsize;
							used_bytes[cursector] += size % KMCSFS->sectorsize;
							size -= size % KMCSFS->sectorsize;
							if (used_bytes[cursector] == KMCSFS->sectorsize)
							{
								KMCSFS->used_blocks++;
							}
						}
						break;
					}
					else if (KMCSFS->sectorsize - used_bytes[cursector] >= size % KMCSFS->sectorsize)
					{
						if (!tablestr)
						{
							tablestr = kzalloc(KMCSFS->tablestrlen, GFP_KERNEL);
							if (!tablestr)
							{
								pr_err("out of memory\n");
								kfree(used_bytes);
								return false;
							}
							memcpy(tablestr, KMCSFS->tablestr, KMCSFS->tablestrlen);
						}

						if (!used_sector_bytes)
						{
							used_sector_bytes = kzalloc(KMCSFS->sectorsize / 8, GFP_KERNEL);
							if (!used_sector_bytes)
							{
								pr_err("out of memory\n");
								kfree(used_bytes);
								kfree(tablestr);
								return false;
							}
						}
						memset(used_sector_bytes, 0, KMCSFS->sectorsize / 8);

						cur = 0;
						int0 = 0;
						int1 = 0;
						int2 = 0;
						unsigned long long strsize = 0;

						for (unsigned long long o = 0; o < temptablestrlen; o++)
						{
							strsize++;
							if (tablestr[o] == *"," || tablestr[o] == *".")
							{
								if (int0 == cursector)
								{
									o++;
									switch (cur)
									{
									case 0:
										memcpy(tablestr + o - strsize, tablestr + o, temptablestrlen - o);
										temptablestrlen -= strsize;
										o -= strsize;
										break;
									case 1:
										break;
									case 2:
										for (unsigned long long p = int1; p < int2; p++)
										{
											used_sector_bytes[p / sizeof(unsigned long long) / 8] |= ((unsigned long long)1 << (p % (sizeof(unsigned long long) * 8)));
										}
										memcpy(tablestr + o - strsize, tablestr + o, temptablestrlen - o);
										temptablestrlen -= strsize;
										o -= strsize;
										break;
									}
									o--;
								}
								cur = 0;
								int0 = 0;
								int1 = 0;
								int2 = 0;
								strsize = 0;
							}
							else if (tablestr[o] == *";")
							{
								cur++;
							}
							else if (tablestr[o] == *"-")
							{
								cur = 0;
								int0 = 0;
								int1 = 0;
								int2 = 0;
							}
							else
							{
								switch (cur)
								{
								case 0:
									int0 += toint(tablestr[o] & 0xff);
									if (tablestr[o + 1] != *";" && tablestr[o + 1] != *"," && tablestr[o + 1] != *"." && tablestr[o + 1] != *"-")
									{
										int0 *= 10;
									}
									break;
								case 1:
									int1 += toint(tablestr[o] & 0xff);
									if (tablestr[o + 1] != *";" && tablestr[o + 1] != *"," && tablestr[o + 1] != *"." && tablestr[o + 1] != *"-")
									{
										int1 *= 10;
									}
									break;
								case 2:
									int2 += toint(tablestr[o] & 0xff);
									if (tablestr[o + 1] != *";" && tablestr[o + 1] != *"," && tablestr[o + 1] != *"." && tablestr[o + 1] != *"-")
									{
										int2 *= 10;
									}
									break;
								}
							}
						}

						unsigned long long freecount = 0;
						unsigned long long offset = 0;
						for (; offset < KMCSFS->sectorsize; offset++)
						{
							if (used_sector_bytes[offset / sizeof(unsigned long long) / 8] & ((unsigned long long)1 << (offset % (sizeof(unsigned long long) * 8))))
							{
								freecount = 0;
								if (KMCSFS->sectorsize - offset < size % KMCSFS->sectorsize)
								{
									break;
								}
							}
							else
							{
								freecount++;
								if (freecount == size % KMCSFS->sectorsize)
								{
									offset++;
									break;
								}
							}
						}

						if (freecount == size % KMCSFS->sectorsize)
						{
							if (cursize)
							{
								char* newtable = kzalloc(KMCSFS->tablestrlen + 64, GFP_KERNEL);
								if (!newtable)
								{
									pr_err("out of memory\n");
									kfree(used_bytes);
									kfree(tablestr);
									kfree(used_sector_bytes);
									return false;
								}
								memcpy(newtable, KMCSFS->tablestr, loc);
								newtable[loc] = *",";
								char num1[21] = {0};
								sprintf(num1, "%llu", cursector);
								unsigned num1len = strlen(num1);
								memcpy(newtable + loc + 1, num1, num1len);
								newtable[loc + 1 + num1len] = *";";
								char num2[21] = {0};
								sprintf(num2, "%llu", offset - size);
								newoffset = offset - size;
								unsigned num2len = strlen(num2);
								memcpy(newtable + loc + 1 + num1len + 1, num2, num2len);
								newtable[loc + 1 + num1len + 1 + num2len] = *";";
								char num3[21] = {0};
								sprintf(num3, "%llu", offset);
								unsigned num3len = strlen(num3);
								memcpy(newtable + loc + 1 + num1len + 1 + num2len + 1, num3, num3len);
								memcpy(newtable + loc + 1 + num1len + 1 + num2len + 1 + num3len, KMCSFS->tablestr + loc, KMCSFS->tablestrlen - loc);
								kfree(KMCSFS->tablestr);
								KMCSFS->tablestr = newtable;
								KMCSFS->tablestrlen += num1len + 1 + num2len + 1 + num3len + 1;
								loc += num1len + 1 + num2len + 1 + num3len + 1;
								cursize += size % KMCSFS->sectorsize;
								used_bytes[cursector] += size % KMCSFS->sectorsize;
								size -= size % KMCSFS->sectorsize;
								if (used_bytes[cursector] == KMCSFS->sectorsize)
								{
									KMCSFS->used_blocks++;
								}
							}
							else
							{
								char* newtable = kzalloc(KMCSFS->tablestrlen + 63, GFP_KERNEL);
								if (!newtable)
								{
									pr_err("out of memory\n");
									kfree(used_bytes);
									kfree(tablestr);
									kfree(used_sector_bytes);
									return false;
								}
								memcpy(newtable, KMCSFS->tablestr, loc);
								char num1[21] = {0};
								sprintf(num1, "%llu", cursector);
								unsigned num1len = strlen(num1);
								memcpy(newtable + loc, num1, num1len);
								newtable[loc + num1len] = *";";
								char num2[21] = {0};
								sprintf(num2, "%llu", offset - size);
								newoffset = offset - size;
								unsigned num2len = strlen(num2);
								memcpy(newtable + loc + num1len + 1, num2, num2len);
								newtable[loc + num1len + 1 + num2len] = *";";
								char num3[21] = {0};
								sprintf(num3, "%llu", offset);
								unsigned num3len = strlen(num3);
								memcpy(newtable + loc + num1len + 1 + num2len + 1, num3, num3len);
								memcpy(newtable + loc + num1len + 1 + num2len + 1 + num3len, KMCSFS->tablestr + loc, KMCSFS->tablestrlen - loc);
								kfree(KMCSFS->tablestr);
								KMCSFS->tablestr = newtable;
								KMCSFS->tablestrlen += num1len + 1 + num2len + 1 + num3len;
								loc += num1len + 1 + num2len + 1 + num3len;
								cursize += size % KMCSFS->sectorsize;
								used_bytes[cursector] += size % KMCSFS->sectorsize;
								size -= size % KMCSFS->sectorsize;
								if (used_bytes[cursector] == KMCSFS->sectorsize)
								{
									KMCSFS->used_blocks++;
								}
							}
							break;
						}
					}
				}
				if (tablestr)
				{
					kfree(tablestr);
				}
				if (used_sector_bytes)
				{
					kfree(used_sector_bytes);
				}
			}
			if (tempdata)
			{
				sync_write_phys(KMCSFS->size - cursector * KMCSFS->sectorsize - KMCSFS->sectorsize + newoffset, endlength, tempdata + endoffset % 512, bdev, true);
				kfree(tempdata);
				tempdata = NULL;
			}
		}

		kfree(used_bytes);
		if (!size)
		{
			unsigned long long extratablesize = 5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend + 2 + 35 * KMCSFS->filecount;
			if (!is_table_expandable(*KMCSFS, extratablesize))
			{
				pr_err("out of memory - could not write to disk 1\n");
				return false;
			}
			unsigned long long tablesize = (extratablesize + KMCSFS->sectorsize - 1) / KMCSFS->sectorsize - 1;
			char* newtable = kzalloc(extratablesize, GFP_KERNEL);
			if (!newtable)
			{
				pr_err("out of memory - could not write to disk 2\n");
				return false;
			}
			char* newtablestren = encode(KMCSFS->tablestr, KMCSFS->tablestrlen);
			if (!newtablestren)
			{
				pr_err("out of memory - could not write to disk 3\n");
				kfree(newtable);
				return false;
			}
			newtable[0] = KMCSFS->table[0];
			newtable[1] = (tablesize >> 24) & 0xff;
			newtable[2] = (tablesize >> 16) & 0xff;
			newtable[3] = (tablesize >> 8) & 0xff;
			newtable[4] = tablesize & 0xff;
			memcpy(newtable + 5, newtablestren, (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2);
			kfree(newtablestren);
			memcpy(newtable + 5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2, KMCSFS->table + KMCSFS->tableend, extratablesize - 5 - (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2);
			KMCSFS->extratablesize = extratablesize;
			KMCSFS->tablesize = 1 + tablesize;
			KMCSFS->filenamesend = 5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend;
			KMCSFS->tableend = 5 + (KMCSFS->tablestrlen + KMCSFS->tablestrlen % 2) / 2;
			kfree(KMCSFS->table);
			KMCSFS->table = newtable;
			sync_write_phys(0, extratablesize, newtable, bdev, true);
		}
		return true;
	}
	else
	{
		if (!KMCSFS->used_blocks)
		{
			unsigned long* used_bytes = kzalloc((KMCSFS->size / KMCSFS->sectorsize - KMCSFS->tablesize) * sizeof(unsigned long), GFP_KERNEL);
			if (!used_bytes)
			{
				pr_err("out of memory\n");
				return false;
			}
			memset(used_bytes, 0, (KMCSFS->size / KMCSFS->sectorsize - KMCSFS->tablesize) * sizeof(unsigned long));
			bool notzero = false;
			bool multisector = false;
			unsigned cur = 0;
			unsigned long long int0 = 0;
			unsigned long long int1 = 0;
			unsigned long long int2 = 0;
			unsigned long long int3 = 0;
			for (unsigned long long i = 0; i < KMCSFS->tablestrlen; i++)
			{
				if (KMCSFS->tablestr[i] == *"," || KMCSFS->tablestr[i] == *".")
				{
					if (notzero)
					{
						if (multisector)
						{
							for (unsigned long long o = 0; o < int0 - int3; o++)
							{
								used_bytes[int3 + o] += KMCSFS->sectorsize;
								KMCSFS->used_blocks++;
							}
						}
						switch (cur)
						{
						case 0:
							used_bytes[int0] += KMCSFS->sectorsize;
							KMCSFS->used_blocks++;
							break;
						case 1:
							break;
						case 2:
							used_bytes[int0] += int2 - int1;
							if (used_bytes[int0] == KMCSFS->sectorsize)
							{
								KMCSFS->used_blocks++;
							}
							break;
						}
					}
					cur = 0;
					int0 = 0;
					int1 = 0;
					int2 = 0;
					int3 = 0;
					notzero = false;
					multisector = false;
				}
				else if (KMCSFS->tablestr[i] == *";")
				{
					cur++;
				}
				else if (KMCSFS->tablestr[i] == *"-")
				{
					int3 = int0;
					multisector = true;
					cur = 0;
					int0 = 0;
					int1 = 0;
					int2 = 0;
				}
				else
				{
					notzero = true;
					switch (cur)
					{
					case 0:
						int0 += toint(KMCSFS->tablestr[i] & 0xff);
						if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
						{
							int0 *= 10;
						}
						break;
					case 1:
						int1 += toint(KMCSFS->tablestr[i] & 0xff);
						if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
						{
							int1 *= 10;
						}
						break;
					case 2:
						int2 += toint(KMCSFS->tablestr[i] & 0xff);
						if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
						{
							int2 *= 10;
						}
						break;
					}
				}
			}
			kfree(used_bytes);
		}
		return true;
	}
}

int delete_file(struct block_device* bdev, KMCSpaceFS* KMCSFS, UNICODE_STRING filename, unsigned long long index)
{
	char* newtable = kzalloc(KMCSFS->filenamesend + 2 + 35 * (KMCSFS->filecount - 1), GFP_KERNEL);
	if (!newtable)
	{
		pr_err("out of memory\n");
		return -ENOMEM;
	}
	memset(newtable, 0, KMCSFS->filenamesend + 2 + 35 * (KMCSFS->filecount - 1));
	char* newtablestr = kzalloc(KMCSFS->tablestrlen, GFP_KERNEL);
	if (!newtablestr)
	{
		pr_err("out of memory\n");
		kfree(newtable);
		return -ENOMEM;
	}
	memset(newtablestr, 0, KMCSFS->tablestrlen);
	unsigned long long tableloc = 0;
	if (index)
	{
		for (unsigned long long i = 0; i < KMCSFS->tablestrlen; i++)
		{
			if (KMCSFS->tablestr[i] == *".")
			{
				tableloc++;
				if (tableloc == index)
				{
					tableloc = i + 1;
					break;
				}
			}
		}
	}
	unsigned long long tablelen = 0;
	for (unsigned long long i = tableloc; i < KMCSFS->tablestrlen; i++)
	{
		if (KMCSFS->tablestr[i] == *".")
		{
			tablelen = i - tableloc + 1;
			break;
		}
	}
	unsigned long long loc = KMCSFS->tableend;
	if (index)
	{
		loc = 0;
		for (unsigned long long i = KMCSFS->tableend; i < KMCSFS->filenamesend + 1; i++)
		{
			if (KMCSFS->table[i] == *"\xff")
			{
				loc++;
				if (loc == index + 1)
				{
					loc = i;
					break;
				}
			}
		}
	}
	unsigned long long len = 0;
	for (unsigned long long i = loc + 1; i < KMCSFS->filenamesend + 1; i++)
	{
		if (KMCSFS->table[i] == *"\xff")
		{
			len = i - loc;
			break;
		}
	}
	unsigned long long tablestrlen = KMCSFS->tablestrlen - tablelen;
	memcpy(newtablestr, KMCSFS->tablestr, tableloc);
	memcpy(newtablestr + tableloc, KMCSFS->tablestr + tableloc + tablelen, KMCSFS->tablestrlen - tableloc - tablelen);
	char* newtablestren = encode(newtablestr, tablestrlen);
	if (!newtablestren)
	{
		pr_err("out of memory\n");
		kfree(newtable);
		kfree(newtablestr);
		return -ENOMEM;
	}
	unsigned long long extratablesize = 5 + (tablestrlen + tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend - len + 35 * (KMCSFS->filecount - 1);
	unsigned long long tablesize = (extratablesize + KMCSFS->sectorsize - 1) / KMCSFS->sectorsize - 1;
	newtable[0] = KMCSFS->table[0];
	newtable[1] = (tablesize >> 24) & 0xff;
	newtable[2] = (tablesize >> 16) & 0xff;
	newtable[3] = (tablesize >> 8) & 0xff;
	newtable[4] = tablesize & 0xff;
	memcpy(newtable + 5, newtablestren, (tablestrlen + tablestrlen % 2) / 2);
	kfree(newtablestren);
	memcpy(newtable + 5 + (tablestrlen + tablestrlen % 2) / 2, KMCSFS->table + KMCSFS->tableend, loc - KMCSFS->tableend);
	memcpy(newtable + 5 + (tablestrlen + tablestrlen % 2) / 2 + loc - KMCSFS->tableend, KMCSFS->table + loc + len, KMCSFS->filenamesend - loc - len + 2);
	memcpy(newtable + 5 + (tablestrlen + tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend - len + 2, KMCSFS->table + KMCSFS->filenamesend + 2, 24 * index);
	memcpy(newtable + 5 + (tablestrlen + tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend - len + 2 + 24 * index, KMCSFS->table + KMCSFS->filenamesend + 2 + 24 * (index + 1), 24 * (KMCSFS->filecount - index - 1));
	memcpy(newtable + 5 + (tablestrlen + tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend - len + 2 + 24 * (KMCSFS->filecount - 1), KMCSFS->table + KMCSFS->filenamesend + 2 + 24 * KMCSFS->filecount, 11 * index);
	memcpy(newtable + 5 + (tablestrlen + tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend - len + 2 + 24 * (KMCSFS->filecount - 1) + 11 * index, KMCSFS->table + KMCSFS->filenamesend + 2 + 24 * KMCSFS->filecount + 11 * (index + 1), 11 * (KMCSFS->filecount - index - 1));
	sync_write_phys(0, 5 + (tablestrlen + tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend - len + 2 + 35 * (KMCSFS->filecount - 1), newtable, bdev, true);

	unsigned long long dindex = FindDictEntry(KMCSFS->dict, KMCSFS->table, KMCSFS->tableend, KMCSFS->DictSize, filename.Buffer, filename.Length / sizeof(WCHAR));
	if (dindex)
	{
		RemoveDictEntry(KMCSFS->dict, KMCSFS->DictSize, dindex, filename.Length / sizeof(WCHAR), &KMCSFS->CurDictSize);
	}

	KMCSFS->used_blocks -= get_file_size(index, *KMCSFS) / KMCSFS->sectorsize;
	kfree(KMCSFS->table);
	KMCSFS->table = newtable;
	KMCSFS->tablesize = 1 + tablesize;
	KMCSFS->extratablesize = extratablesize;
	KMCSFS->filenamesend = 5 + (tablestrlen + tablestrlen % 2) / 2 + KMCSFS->filenamesend - KMCSFS->tableend - len;
	KMCSFS->tableend = 5 + (tablestrlen + tablestrlen % 2) / 2;
	kfree(KMCSFS->tablestr);
	KMCSFS->tablestr = newtablestr;
	KMCSFS->tablestrlen = tablestrlen;
	KMCSFS->filecount--;
	return 0;
}

int rename_file(struct block_device* bdev, KMCSpaceFS* KMCSFS, UNICODE_STRING fn, UNICODE_STRING nfn)
{
	unsigned long long extratablesize = KMCSFS->filenamesend + 2 + 35 * KMCSFS->filecount - fn.Length / sizeof(WCHAR) + nfn.Length / sizeof(WCHAR);
	unsigned long long tablesize = (extratablesize + KMCSFS->sectorsize - 1) / KMCSFS->sectorsize - 1;

	char* newtable = kzalloc(extratablesize, GFP_KERNEL);
	if (!newtable)
	{
		pr_err("out of memory\n");
		return -ENOMEM;
	}
	memset(newtable, 0, extratablesize);

	if (!is_table_expandable(*KMCSFS, extratablesize))
	{
		pr_err("table is not expandable\n");
		kfree(newtable);
		return -ENOSPC;
	}

	unsigned long long index = get_filename_index(fn, KMCSFS);
	if (!index)
	{
		kfree(newtable);
		return -ENOENT;
	}

	unsigned long long loc = KMCSFS->tableend;
	if (index)
	{
		loc = 0;
		for (unsigned long long i = KMCSFS->tableend; i < KMCSFS->filenamesend + 1; i++)
		{
			if (KMCSFS->table[i] == *"\xff")
			{
				loc++;
				if (loc == index + 1)
				{
					loc = i;
					break;
				}
			}
		}
	}

	newtable[0] = KMCSFS->table[0];
	newtable[1] = (tablesize >> 24) & 0xff;
	newtable[2] = (tablesize >> 16) & 0xff;
	newtable[3] = (tablesize >> 8) & 0xff;
	newtable[4] = tablesize & 0xff;
	memcpy(newtable + 5, KMCSFS->table + 5, loc - 5);
	newtable[loc] = *"\xff";
	for (unsigned long long i = 0; i < nfn.Length / sizeof(WCHAR); i++)
	{
		newtable[loc + i + 1] = nfn.Buffer[i] & 0xff;
		if (newtable[loc + i + 1] == 92)
		{
			newtable[loc + i + 1] = 47;
		}
	}
	memcpy(newtable + loc + 1 + nfn.Length / sizeof(WCHAR), KMCSFS->table + loc + 1 + fn.Length / sizeof(WCHAR), KMCSFS->filenamesend - loc - 1 - fn.Length / sizeof(WCHAR) + 2 + 35 * KMCSFS->filecount);

	unsigned long long dindex = FindDictEntry(KMCSFS->dict, KMCSFS->table, KMCSFS->tableend, KMCSFS->DictSize, fn.Buffer, fn.Length / sizeof(WCHAR));
	if (dindex)
	{
		unsigned long long filenameloc = KMCSFS->dict[dindex].filenameloc;
		unsigned long long opencount = KMCSFS->dict[dindex].opencount;
		unsigned long long flags = KMCSFS->dict[dindex].flags;
		unsigned long long streamdeletecount = KMCSFS->dict[dindex].streamdeletecount;
		struct _fcb* fcb = KMCSFS->dict[dindex].fcb;
		char* filename = KMCSFS->dict[dindex].filename;
		RemoveDictEntry(KMCSFS->dict, KMCSFS->DictSize, dindex, fn.Length / sizeof(WCHAR), &KMCSFS->CurDictSize);
		AddDictEntry(&KMCSFS->dict, nfn.Buffer, filenameloc, nfn.Length / sizeof(WCHAR), &KMCSFS->CurDictSize, &KMCSFS->DictSize, index, true);
		dindex = FindDictEntry(KMCSFS->dict, newtable, KMCSFS->tableend, KMCSFS->DictSize, nfn.Buffer, nfn.Length / sizeof(WCHAR));
		if (dindex)
		{
			KMCSFS->dict[dindex].opencount = opencount;
			KMCSFS->dict[dindex].flags = flags;
			KMCSFS->dict[dindex].streamdeletecount = streamdeletecount;
			KMCSFS->dict[dindex].fcb = fcb;
			KMCSFS->dict[dindex].filename = filename;
		}
	}

	KMCSFS->filenamesend = KMCSFS->filenamesend - fn.Length / sizeof(WCHAR) + nfn.Length / sizeof(WCHAR);
	KMCSFS->extratablesize = extratablesize;
	KMCSFS->tablesize = 1 + tablesize;
	kfree(KMCSFS->table);
	KMCSFS->table = newtable;

	sync_write_phys(0, extratablesize, newtable, bdev, true);

	return 0;
}