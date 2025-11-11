// Copyright (c) Anthony Kerr 2024-

#include "linuxfs.h"
#include "Dict.h"
#include "cspacefs.h"
#include "Sha3.h"

bool incmp(unsigned char a, unsigned char b)
{
	if (a >= 'A' && a <= 'Z')
	{
		a += 32;
	}
	if (b >= 'A' && b <= 'Z')
	{
		b += 32;
	}
	return a == b;
}

Dict* CreateDict(unsigned long long size)
{
	Dict* dict = kzalloc(sizeof(Dict) * size, GFP_KERNEL);
	if (dict == NULL)
	{
		return NULL;
	}
	memset(dict, 0, sizeof(Dict) * size);
	return dict;
}

Dict* ResizeDict(Dict* dict, unsigned long long oldsize, unsigned long long* newsize)
{
	Dict* ndict = NULL;
startover:
	*newsize *= 2;
	ndict = kzalloc(sizeof(Dict) * *newsize, GFP_KERNEL);
	if (ndict == NULL)
	{
		*newsize = oldsize;
		return NULL;
	}
	memset(ndict, 0, sizeof(Dict) * *newsize);
	for (unsigned long long i = 0; i < oldsize; i++)
	{
		if (dict[i].filenameloc)
		{
			unsigned long long hash = dict[i].hash;
			unsigned long long j = hash % *newsize;
			if (!j)
			{
				j++;
			}
			while (ndict[j].filenameloc && j < *newsize - 1)
			{
				j++;
			}
			if (j > *newsize - 1)
			{
				kfree(ndict);
				goto startover;
			}
			ndict[j].filenameloc = dict[i].filenameloc;
			ndict[j].hash = hash;
			ndict[j].index = dict[i].index;
			ndict[j].opencount = dict[i].opencount;
			ndict[j].flags = dict[i].flags;
			ndict[j].streamdeletecount = dict[i].streamdeletecount;
			ndict[j].fcb = dict[i].fcb;
			ndict[j].filename = dict[i].filename;
		}
	}
	return ndict;
}

bool AddDictEntry(Dict** dict, char* filename, unsigned long long filenameloc, unsigned long long filenamelen, unsigned long long* cursize, unsigned long long* size, unsigned long long index, bool scan)
{
	unsigned long long hash = 0;
	char* Filename = kzalloc(filenamelen + 1, GFP_KERNEL);
	if (Filename == NULL)
	{
		return false;
	}
	for (unsigned long long i = 0; i < filenamelen; i++)
	{
		Filename[i] = filename[i] & 0xff;
		if (Filename[i] == 92)
		{
			Filename[i] = 47;
		}
		if (Filename[i] >= 'A' && Filename[i] <= 'Z')
		{
			Filename[i] += 32;
		}
	}
	sha3_HashBuffer(256, 0, Filename, filenamelen, &hash, 8);
	kfree(Filename);
	unsigned long long i = hash % *size;
	if (!i)
	{
		i++;
	}
	while ((*dict)[i].filenameloc && i < *size - 1)
	{
		if ((*dict)[i].hash == hash)
		{
			memset(*dict + i, 0, sizeof(Dict));
			(*dict)[i].hash = hash;
			(*dict)[i].filenameloc = filenameloc;
			(*dict)[i].index = index;
			return true;
		}
		i++;
	}
	while (i > *size - 1)
	{
		Dict* tdict = ResizeDict(*dict, *size, size);
		if (tdict == NULL)
		{
			return false;
		}
		i = hash % *size;
		if (!i)
		{
			i++;
		}
		while (tdict[i].filenameloc && i < *size - 1)
		{
			i++;
		}
		kfree(*dict);
		*dict = tdict;
	}
	(*cursize)++;
	if (scan)
	{
		for (unsigned long long j = 0; j < *size; j++)
		{
			if (!(*dict)[j].filenameloc)
			{
				continue;
			}
			if ((*dict)[j].index >= index)
			{
				(*dict)[j].index++;
			}
			if ((*dict)[j].filenameloc >= filenameloc)
			{
				(*dict)[j].filenameloc += filenamelen + 1;
			}
		}
	}
	memset(*dict + i, 0, sizeof(Dict));
	(*dict)[i].hash = hash;
	(*dict)[i].filenameloc = filenameloc;
	(*dict)[i].index = index;
	if (*cursize * 3 / 4 > *size)
	{
		Dict* tdict = ResizeDict(*dict, *size, size);
		if (tdict == NULL)
		{
			return true;
		}
		kfree(*dict);
		*dict = tdict;
	}
	return true;
}

unsigned long long FindDictEntry(Dict* dict, char* table, unsigned long long tableend, unsigned long long size, char* filename, unsigned long long filenamelen)
{
	char* Filename = kzalloc(filenamelen + 1, GFP_KERNEL);
	if (Filename == NULL)
	{
		return 0;
	}
	for (unsigned long long i = 0; i < filenamelen; i++)
	{
		Filename[i] = filename[i] & 0xff;
		if (Filename[i] == 92)
		{
			Filename[i] = 47;
		}
		if (Filename[i] >= 'A' && Filename[i] <= 'Z')
		{
			Filename[i] += 32;
		}
	}
	unsigned long long hash = 0;
	sha3_HashBuffer(256, 0, Filename, filenamelen, &hash, 8);
	unsigned long long o = hash % size;
	if (!o)
	{
		o++;
	}
	while (true)
	{
		if (o > size - 1)
		{
			kfree(Filename);
			return 0;
		}
		if (!dict[o].filenameloc)
		{
			kfree(Filename);
			return 0;
		}
		for (unsigned long long j = 0; j < filenamelen; j++)
		{
			if (!((incmp((table[tableend + dict[o].filenameloc + j] & 0xff), (Filename[j] & 0xff)) || (((table[tableend + dict[o].filenameloc + j] & 0xff) == *"/") && ((Filename[j] & 0xff) == *"\\")))))
			{
				break;
			}
			else
			{
				if ((table[tableend + dict[o].filenameloc + j] & 0xff) != *"/")
				{
					filename[j] = table[tableend + dict[o].filenameloc + j] & 0xff;
				}
			}
			if (j == filenamelen - 1 && ((table[tableend + dict[o].filenameloc + j + 1] & 0xff) == 255 || (table[tableend + dict[o].filenameloc + j + 1] & 0xff) == 42) && dict[o].hash == hash)
			{
				kfree(Filename);
				return o;
			}
		}
		o++;
	}
}

void RemoveDictEntry(Dict* dict, unsigned long long size, unsigned long long dindex, unsigned long long filenamelen, unsigned long long* cursize)
{
	unsigned long long index = dict[dindex].index;
	unsigned long long filenameloc = dict[dindex].filenameloc;
	memset(dict + dindex, 0, sizeof(Dict));
	(*cursize)--;
	for (unsigned long long i = 0; i < size; i++)
	{
		if (!dict[i].filenameloc)
		{
			continue;
		}
		if (dict[i].index > index)
		{
			dict[i].index--;
		}
		if (dict[i].filenameloc > filenameloc)
		{
			dict[i].filenameloc -= filenamelen + 1;
		}
	}
	return;
}