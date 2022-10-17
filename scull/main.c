#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/errno.h>

#include <asm/uaccess.h>
#include <asm/current.h>
#include <linux/uidgid.h>
#include <linux/slab.h>

/*
 *  Семафор необходим для создания мультипроцессорного ресурса
 * и для минимизации рисков утечки памяти.
 */
#include <linux/semaphore.h>

#include "scull.h"

struct message_item;
struct device_info {
    struct cdev cdev;
    struct mutex lock;
    ssize_t length;
    struct message_item *items;
};

struct device_info *scull_devices;

struct message_item {
    kuid_t user;
    ssize_t buffer_size;
    char buffer[BUFFER_SIZE];
    struct message_item *next;
};

void device_clear(struct device_info *dev)
{
    struct message_item *item;

    while ((item = dev->items) != NULL) {
        dev->items = item->next;
        kfree(item);
    }
    dev->length = 0;
}

int static lopen(struct inode *inodep, struct file *filp)
{
    struct device_info *dev;
    dev = container_of(inodep->i_cdev, struct device_info, cdev);
    filp->private_data = dev;

    return 0;
}

int static lrelease(struct inode *inodep, struct file *filp)
{
    /*
     * Will be called when file is closing by process.
     * Just 1 time even was fork().
     */
    return 0;
}

ssize_t static lwrite(struct file *filp, const char __user *from_user, size_t sz, loff_t *f_op)
{
    int retval;
    struct device_info *dev = filp->private_data;
    struct message_item *item;
    ssize_t writted_size;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS; 

    if ((item = kmalloc(sizeof(struct message_item), GFP_KERNEL)) == NULL) {
        retval = -ENOMEM;
        goto out;
    }
    writted_size = MINIMAL(sz, BUFFER_SIZE);
    if (copy_from_user(item->buffer, from_user, writted_size)) {
        kfree(item);
        retval = -EFAULT;
        goto out;
    }
    item->user = current->cred->uid;
    item->buffer_size = writted_size;
    item->next = dev->items;
    dev->items = item;
    dev->length += 1;
    retval = writted_size;

out:
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t static lread(struct file *filp, char __user *to_user, size_t sz, loff_t *f_op)
{
    int retval;
    struct device_info *dev = filp->private_data;
    struct message_item *item = dev->items;
    ssize_t readed_size;

    if (dev->length <= 0) return 0;
    readed_size = MINIMAL(sz, item->buffer_size);
    if (copy_to_user(to_user, item->buffer, readed_size)) {
        retval = -EFAULT;
        goto out;
    }
    dev->items = item->next;
    kfree(item);
    dev->length -= 1;
    retval = readed_size;

out:
    return retval;
}


static dev_t device_number;
static struct file_operations f_ops = {
    .owner = THIS_MODULE,
    .open = &lopen,
    .release = &lrelease,
    .write = &lwrite,
    .read = &lread
};

int static __init scull_init(void)
{
    struct device_info *dev;
    dev_t local_device_num;
    int retval = 0;
    int counter;

    /*
     *  Выделяем память для устройств 'scull' и устанавливаем 
     * в ноль, используя 'memset'
     */

    if (alloc_chrdev_region(&device_number, CHRDEV_BASEMINOR, CHRDEV_COUNT, THIS_MODULE->name)) {
        retval = -EFAULT;
        goto out;
    }
    
    if ((scull_devices = kmalloc(CHRDEV_COUNT * sizeof(struct device_info), GFP_KERNEL)) == NULL) {
        retval = -EADDRNOTAVAIL;
        goto out;
    }
    memset(scull_devices, 0, CHRDEV_COUNT * sizeof(struct device_info));

    for (counter = 0; counter < CHRDEV_COUNT; counter++) {
        dev = &scull_devices[counter];
        mutex_init(&dev->lock);
        cdev_init(&dev->cdev, &f_ops);
        dev->cdev.owner = THIS_MODULE;
        local_device_num = MKDEV(MAJOR(device_number), MINOR(device_number) + counter);
        if (cdev_add(&dev->cdev, local_device_num, 1)) {
            retval = -ERESTART;
            goto out;
        }
    }

out:
    printk("scull: device '%s' loaded with status (%d)\n", THIS_MODULE->name, retval);    
    return retval;
}

void static __exit scull_exit(void)
{
    int counter;
    struct device_info *dev;
    for (counter = 0; counter < CHRDEV_COUNT; counter++) {
        dev = &scull_devices[counter];
        device_clear(dev);
        cdev_del(&dev->cdev);
    }
    kfree(scull_devices);
    unregister_chrdev_region(device_number, CHRDEV_COUNT);
    printk("scull: device '%s' unloaded\n", THIS_MODULE->name);
}

module_init(scull_init);
module_exit(scull_exit);

MODULE_LICENSE("GPLv3");
MODULE_AUTHOR("Pavel Vasilev <django@altlinux.org>");
MODULE_DESCRIPTION("SCULL - is a simple implementation of global storage");