#!/bin/csh

set DISK		= hdd.img
set DISK_SIZE		= 128M

# create disk
dd if=/dev/zero of=$DISK bs=1 count=1 seek=$DISK_SIZE
mkfs.minix -1 $DISK

# mount disk
mkdir tmp >& /dev/null
sudo mount $DISK tmp

# create init
sudo mkdir tmp/sbin
sudo mkdir tmp/bin
sudo cp usr/init tmp/sbin/
sudo cp dash/dash-0.5.10.2-build/bin/dash tmp/bin
sudo cp toybox/toybox-0.8.4-build/bin/toybox tmp/bin

# create devices nodes
sudo mkdir tmp/dev
sudo mknod tmp/dev/tty c 4 0
sudo mknod tmp/dev/tty1 c 4 1
sudo mknod tmp/dev/tty2 c 4 2
sudo mknod tmp/dev/tty3 c 4 3
sudo mknod tmp/dev/tty4 c 4 4

# unmount disk
sudo umount tmp
sudo rm -rf tmp
