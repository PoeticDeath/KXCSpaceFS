// Copyright (c) Anthony Kerr 2024-

#define pr_fmt(fmt) KBUILD_MODNAME ":%s:%s:%d: " fmt, __FILE__, __func__, __LINE__

#include "linuxfs.h"
#include "Dict.h"
#include "cspacefs.h"
#include "Sha3.h"

bool incmp(unsigned char a, unsigned char b)
{
	/*if (a >= 'A' && a <= 'Z')
	{
		a += 32;
	}
	if (b >= 'A' && b <= 'Z')
	{
		b += 32;
	}*/
	return a == b;
}

Dict* CreateDict(unsigned long long size)
{
	Dict* dict = vmalloc(sizeof(Dict) * size);
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
	ndict = CreateDict(*newsize);
	if (ndict == NULL)
	{
		*newsize = oldsize;
		return NULL;
	}
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
			Dict* tdict = ndict + j;
			bool taken = ndict[j].filenameloc;
			while (tdict->ndict)
			{
				tdict = tdict->ndict;
			}
			while (ndict[j].filenameloc && j < *newsize - 1)
			{
				j++;
			}
			if (ndict[j].filenameloc || j > *newsize - 1)
			{
				vfree(ndict);
				goto startover;
			}
			ndict[j].filenameloc = dict[i].filenameloc;
			ndict[j].hash = hash;
			ndict[j].index = dict[i].index;
			ndict[j].inode = dict[i].inode;
			if (taken)
			{
				ndict[j].pdict = tdict;
				tdict->ndict = ndict + j;
			}
		}
	}
	return ndict;
}

bool AddDictEntry(Dict** dict, char* filename, unsigned long long filenameloc, unsigned long long filenamelen, unsigned long long* cursize, unsigned long long* size, unsigned long long index, bool createscan, bool linkscan)
{
	unsigned long long hash = 0;
	char* Filename = vmalloc(filenamelen + 1);
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
		/*if (Filename[i] >= 'A' && Filename[i] <= 'Z')
		{
			Filename[i] += 32;
		}*/
	}
	sha3_HashBuffer(256, 0, Filename, filenamelen, &hash, 8);
	vfree(Filename);
	unsigned long long i = hash % *size;
	if (!i)
	{
		i++;
	}
	Dict* tdict = *dict + i;
	bool taken = (*dict)[i].filenameloc;
	while (tdict->ndict)
	{
		tdict = tdict->ndict;
	}
	while ((*dict)[i].filenameloc && i < *size - 1)
	{
		i++;
	}
	while ((*dict)[i].filenameloc || i > *size - 1)
	{
		Dict* ndict = ResizeDict(*dict, *size, size);
		if (ndict == NULL)
		{
			return false;
		}
		i = hash % *size;
		if (!i)
		{
			i++;
		}
		tdict = ndict + i;
		taken = ndict[i].filenameloc;
		while (tdict->ndict)
		{
			tdict = tdict->ndict;
		}
		while (ndict[i].filenameloc && i < *size - 1)
		{
			i++;
		}
		vfree(*dict);
		*dict = ndict;
	}
	(*cursize)++;
	if (createscan)
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
	if (linkscan)
	{
		for (unsigned long long j = 0; j < *size; j++)
		{
			if (!(*dict)[j].filenameloc)
			{
				continue;
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
	if (taken)
	{
		(*dict)[i].pdict = tdict;
		tdict->ndict = *dict + i;
	}
	if (*cursize > *size * 3 / 4)
	{
		Dict* tdict = ResizeDict(*dict, *size, size);
		if (tdict == NULL)
		{
			return true;
		}
		vfree(*dict);
		*dict = tdict;
	}
	return true;
}

unsigned long long FindDictEntry(Dict* dict, char* table, unsigned long long tableend, unsigned long long size, char* filename, unsigned long long filenamelen)
{
	char* Filename = vmalloc(filenamelen + 1);
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
		/*if (Filename[i] >= 'A' && Filename[i] <= 'Z')
		{
			Filename[i] += 32;
		}*/
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
			vfree(Filename);
			return 0;
		}
		if (!dict[o].filenameloc)
		{
			vfree(Filename);
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
				vfree(Filename);
				return o;
			}
		}
		if (dict[o].ndict)
		{
			o = dict[o].ndict - dict;
		}
		else
		{
			vfree(Filename);
			return 0;
		}
	}
}

void RemoveDictEntry(Dict* dict, unsigned long long size, unsigned long long dindex, unsigned long long filenamelen, unsigned long long* cursize)
{
	unsigned long long index = dict[dindex].index;
	unsigned long long filenameloc = dict[dindex].filenameloc;
	if (dict[dindex].ndict)
	{
		Dict* tdict = dict + dindex;
		Dict* ndict = tdict->ndict;
		Dict* pdict = tdict->pdict;
		memmove(tdict, ndict, sizeof(Dict));
		memset(ndict, 0, sizeof(Dict));
		if (tdict->ndict)
		{
			tdict->ndict->pdict = tdict;
		}
		tdict->pdict = pdict;
	}
	else if (dict[dindex].pdict)
	{
		dict[dindex].pdict->ndict = NULL;
		memset(dict + dindex, 0, sizeof(Dict));
	}
	else
	{
		memset(dict + dindex, 0, sizeof(Dict));
	}
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

void RemoveLinkDictEntry(Dict* dict, unsigned long long size, unsigned long long dindex, unsigned long long filenamelen, unsigned long long* cursize)
{
	unsigned long long index = dict[dindex].index;
	unsigned long long filenameloc = dict[dindex].filenameloc;
	if (dict[dindex].ndict)
	{
		Dict* tdict = dict + dindex;
		Dict* ndict = tdict->ndict;
		Dict* pdict = tdict->pdict;
		memmove(tdict, ndict, sizeof(Dict));
		memset(ndict, 0, sizeof(Dict));
		if (tdict->ndict)
		{
			tdict->ndict->pdict = tdict;
		}
		tdict->pdict = pdict;
	}
	else if (dict[dindex].pdict)
	{
		dict[dindex].pdict->ndict = NULL;
		memset(dict + dindex, 0, sizeof(Dict));
	}
	else
	{
		memset(dict + dindex, 0, sizeof(Dict));
	}
	(*cursize)--;
	for (unsigned long long i = 0; i < size; i++)
	{
		if (!dict[i].filenameloc)
		{
			continue;
		}
		if (dict[i].filenameloc > filenameloc)
		{
			dict[i].filenameloc -= filenamelen + 1;
		}
	}
	return;
}