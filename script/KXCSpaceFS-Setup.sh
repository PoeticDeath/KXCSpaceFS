cd Downloads
sudo apt update
sudo apt install -y git make gcc
git clone https://github.com/PoeticDeath/KXCSpaceFS
mkdir KXCSpaceFS/build
make -C /lib/modules/$(uname -r)/build M=~/Downloads/KXCSpaceFS/src MO=~/Downloads/KXCSpaceFS/build modules
