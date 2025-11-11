obj-m += kxcspacefs.o
kxcspacefs-objs := fs.o super.o inode.o file.o dir.o extent.o Sha3.o

KDIR ?= /lib/modules/$(shell uname -r)/build

MKFS = build/mkfs.kxcspacefs

all: $(MKFS)
	make -C $(KDIR) M=$(PWD)/src MO=$(PWD)/build modules

IMAGE ?= test/test.img
IMAGESIZE ?= 200

# To test max files(40920) in directory, the image size should be at least 159.85 MiB
# 40920 * 4096(block size) ~= 159.85 MiB

$(MKFS): src/mkfs.c
	$(CC) -std=gnu99 -Wall -o $@ $<

$(IMAGE): $(MKFS)
	dd if=/dev/zero of=${IMAGE} bs=1M count=${IMAGESIZE}
	./$< $(IMAGE)

check: all
	script/test.sh $(IMAGE) $(IMAGESIZE) $(MKFS)

bear:
	make -C $(KDIR) M=$(PWD)/src MO=$(PWD)/build clean
	bear --append --output $(PWD)/.vscode/compile_commands.json -- $(MAKE) -C $(KDIR) M=$(PWD)/src MO=$(PWD)/build modules

clean:
	make -C $(KDIR) M=$(PWD)/src MO=$(PWD)/build clean
	rm -f $(MKFS) $(IMAGE)

.PHONY: all clean
