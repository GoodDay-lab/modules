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

#include "main.h"

struct message_item;
struct device_info {
    struct cdev cdev;
    ssize_t length;
    struct message_item *items;
};

struct message_item {
    kuid_t user;
    ssize_t buffer_size;
    char buffer[BUFFER_SIZE];
    struct message_item *next;
};

int static lopen(struct inode *inodep, struct file *filp)
{
    struct device_info *dev;
    int count;
    struct message_item *item;
    dev = container_of(inodep->i_cdev, struct device_info, cdev);
    for (count = 0, item = dev->items; item != NULL; count++, item = item->next);
    dev->length = count;
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
    struct device_info *dev = filp->private_data;
    struct message_item *item = kmalloc(sizeof(struct message_item), GFP_KERNEL);
    ssize_t writted_size = MINIMAL(sz, BUFFER_SIZE);
    if (copy_from_user(item->buffer, from_user, writted_size)) {
        kfree(item);
        return -EFAULT;
    }
    item->user = current->cred->uid;
    item->buffer_size = writted_size;
    item->next = dev->items;
    dev->items = item;
    dev->length += 1;
    return writted_size;
}

ssize_t static lread(struct file *filp, char __user *to_user, size_t sz, loff_t *f_op)
{
    struct device_info *dev = filp->private_data;
    struct message_item *item = dev->items;
    ssize_t readed_size;
    if (dev->length <= 0) return 0;
    readed_size = MINIMAL(sz, item->buffer_size);
    if (copy_to_user(to_user, item->buffer, readed_size)) {
        return -EFAULT;
    }
    dev->items = item->next;
    kfree(item);
    dev->length -= 1;
    return readed_size;
}


static dev_t device_number;
static struct cdev cdev_device;
static struct file_operations f_ops = {
    .owner = THIS_MODULE,
    .open = &lopen,
    .release = &lrelease,
    .write = &lwrite,
    .read = &lread
};

int static __init scull_init(void)
{
    int retval = 0;
    if (alloc_chrdev_region(&device_number, CHRDEV_BASEMINOR, CHRDEV_COUNT, THIS_MODULE->name)) {
        retval = -EFAULT;
        goto out;
    }

    cdev_init(&cdev_device, &f_ops);
    if (cdev_add(&cdev_device, device_number, CHRDEV_COUNT)) {
        retval = -EFAULT;
        goto out;
    }

out:
    printk("Device '%s' loadded with status (%d)\n", THIS_MODULE->name, retval);    
    return retval;
}

void static __exit scull_exit(void)
{
    cdev_del(&cdev_device);
    unregister_chrdev_region(device_number, CHRDEV_COUNT);
    printk("Device '%s' unloaded\n", THIS_MODULE->name);
}

module_init(scull_init);
module_exit(scull_exit);

MODULE_LICENSE("GPLv2");
MODULE_AUTHOR("Pavel Vasilev <django@altlinux.org>");
MODULE_DESCRIPTION("SCULL - is a simple implementation of global storage");