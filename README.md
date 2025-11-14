# kxcspacefs - cspacefs as a kernel module for Linux

Super block operations are established at the time of mounting. The operation
tables for inodes and files are set when the inode is accessed. The initial step
before accessing an inode involves a lookup process. The inode for a file is
identified by invoking the lookup handler of the parent inode.

## Features

* Directories: create, remove, list, rename;
* Regular files: create, remove, read/write (through page cache), rename;
* Symbolic links (also symlink or soft link): create, remove, rename;
* Mknod files;
* No extended attribute support;

## Prerequisites

Install linux kernel header in advance.
```shell
$ sudo apt install linux-headers-$(uname -r)
```

## Build and Run

You can build the kernel module and tool with `make`.
Generate test image via `make test.img`, which creates a zeroed file of 50 MiB.

You can then mount this image on a system with the kxcspacefs kernel module installed.
Let's test kernel module:
```shell
$ sudo insmod kxcspacefs.ko
```

Corresponding kernel message:
```
kxcspacefs: module loaded
```

Generate test image by creating a zeroed file of 50 MiB. We can then mount
this image on a system with the kxcspacefs kernel module installed.
```shell
$ mkdir -p test
$ dd if=/dev/zero of=test.img bs=1M count=50
$ ./mkfs.kxcspacefs test.img $(sectorsize)
$ sudo mount -o loop -t KXCSpaceFS test.img test
```

You shall get the following kernel messages:
```
kxcspacefs: '/dev/loop?' mount success
```
Here `/dev/loop?` might be `loop1`, `loop2`, `loop3`, etc.

Perform regular file system operations: (as root)
```shell
$ echo "Hello World" > test/hello
$ cat test/hello
$ ls -lR
```

Remove kernel mount point and module:
```shell
$ sudo umount test
$ sudo rmmod kxcspacefs
```

## New License
`kxcspacefs` is released under the GPL v3 clause licence. Use of this source code
is governed by a GPL-style license that can be found in the LICENSE file.

## Old License

`simplefs` is released under the BSD 2 clause license. Use of this source code
is governed by a BSD-style license that can be found in the LICENSE.old file.
