obj-m += kxcspacefs.o
kxcspacefs-objs := fs.o super.o inode.o file.o dir.o Sha3.o Dict.o CSpaceFS.o

EXTRA_CFLAGS := -O3 -msoft-float -msse -msse2 -msse3 -msse4

KBUILD_CFLAGS = -std=gnu11 -fshort-wchar -funsigned-char -fno-common -fno-PIE -fno-strict-aliasing -mno-mmx -mno-3dnow -mno-avx -fcf-protection=none -m64 -falign-jumps=1 -falign-loops=1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3 -mskip-rax-setup -march=x86-64 -mtune=generic -mno-red-zone -mcmodel=kernel -mstack-protector-guard-reg=gs -mstack-protector-guard-symbol=__ref_stack_chk_guard -Wno-sign-compare -fno-asynchronous-unwind-tables -mindirect-branch=thunk-extern -mindirect-branch-register -mindirect-branch-cs-prefix -mfunction-return=thunk-extern -fno-jump-tables -mharden-sls=all -fpatchable-function-entry=16,16 -fno-delete-null-pointer-checks -O2 -fno-allow-store-data-races -fstack-protector-strong -fno-omit-frame-pointer -fno-optimize-sibling-calls -ftrivial-auto-var-init=zero -fzero-init-padding-bits=all  -fno-stack-clash-protection -fzero-call-used-regs=used-gpr -pg -mrecord-mcount -mfentry -DCC_USING_FENTRY -fmin-function-alignment=16  -fstrict-flex-arrays=3 -fno-strict-overflow -fno-stack-check -fconserve-stack -fno-builtin-wcslen -Wall -Wextra -Wundef -Werror=implicit-function-declaration -Werror=implicit-int -Werror=return-type -Werror=strict-prototypes -Wno-format-security -Wno-trigraphs  -Wno-frame-address  -Wno-address-of-packed-member -Wmissing-declarations -Wmissing-prototypes -Wframe-larger-than=1024 -Wno-main  -Wno-dangling-pointer -Wvla-larger-than=1 -Wno-pointer-sign  -Wcast-function-type  -Wno-unterminated-string-initialization -Wno-array-bounds  -Wno-stringop-overflow -Wno-alloc-size-larger-than -Wimplicit-fallthrough=5 -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -Wenum-conversion -Wunused  -Wno-unused-but-set-variable  -Wno-unused-const-variable  -Wno-packed-not-aligned  -Wno-format-overflow  -Wno-format-truncation  -Wno-stringop-truncation -Wno-override-init  -Wno-missing-field-initializers -Wno-type-limits -Wno-shift-negative-value -Wno-maybe-uninitialized -Wno-sign-compare -Wno-unused-parameter -g -gdwarf-5

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
