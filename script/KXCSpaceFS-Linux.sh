cd /mnt/nvme0n1p3/
sudo mount --bind /dev dev && sudo mount --bind /dev/pts dev/pts && sudo mount -t proc proc proc && sudo mount -t sysfs sysfs sys && sudo mount -t tmpfs tmpfs tmp
sudo chroot /mnt/nvme0n1p3 /bin/bash
sudo umount dev/pts && sudo umount dev && sudo umount proc && sudo umount sys && sudo umount tmp
