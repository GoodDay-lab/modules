MODULE_NAME=pshdev.ko
ROOTFS=./test/rootfs.img
MODULE=./netdev/$MODULE_NAME

mount $ROOTFS /mnt
cp $MODULE /mnt/usr/src/$MODULE_NAME
sync
umount /mnt
