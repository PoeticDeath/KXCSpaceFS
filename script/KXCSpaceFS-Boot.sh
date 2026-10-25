sudo qemu-system-x86_64 -enable-kvm -m 8G -cpu host -smp 16 -kernel /boot/vmlinuz -initrd /boot/initrd.img -append "root=/dev/vda3" -drive file=/dev/nvme0n1,format=raw,if=virtio
