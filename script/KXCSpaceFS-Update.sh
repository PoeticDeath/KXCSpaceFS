sudo cp Source/PoeticDeath/KXCSpaceFS/build/kxcspacefs.ko /usr/lib/modules/$(realpath /boot/initrd.img | cut -b 18-)/
sudo depmod -a $(realpath /boot/initrd.img | cut -b 18-)
sudo update-initramfs -u
