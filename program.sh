
ROOTFS=./test/rootfs.img
MODULE=./scull/scull.ko
MODULE_NAME=scull.ko

mount $ROOTFS /mnt
cp $MODULE /mnt/usr/src/$MODULE_NAME
sync
umount /mnt
