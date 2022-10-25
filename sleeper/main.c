#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/kernel.h>

#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/errno.h>

#include "sleeper.h"

static DECLARE_WAIT_QUEUE_HEAD(wait_queue_head);
static atomic_t flag = ATOMIC_INIT(0);
struct sleeper_dev {
    struct cdev cdev;
    char buffer[4096];
    size_t length;
};

int static sleeper_open(struct inode *inodep, struct file *filp)
{
    // Получаем из родительской структуры 'inodep->i_cdev' объект 'struct cdev'
    // и помещаем в другую структуру 'struct sleeper_dev' в поле 'cdev'
    struct sleeper_dev *dev = container_of(inodep->i_cdev, struct sleeper_dev, cdev);
    filp->private_data = dev;
    return 0;
}

int static sleeper_release(struct inode *inodep, struct file *filp)
{
    return 0;
}

ssize_t static sleeper_write(struct file *filp, const char __user *buf, size_t sz, loff_t *f_op)
{
    struct sleeper_dev *dev = filp->private_data;
    size_t writted_data = (sz < 4096 ? sz : 4096);
    if (copy_from_user(dev->buffer, buf, writted_data))
        return -EFAULT;
    atomic_set(&flag, 1);
    wake_up_interruptible(&wait_queue_head);
    dev->length = writted_data;
    return writted_data;
}

ssize_t static sleeper_read(struct file *filp, char __user *buf, size_t sz, loff_t *f_op)
{
    struct sleeper_dev *dev = filp->private_data;
    size_t readed_data;
    if (!dev->length) {
        if (wait_event_interruptible(wait_queue_head, atomic_read(&flag) > 0))
            return -ERESTARTSYS;
    }
    readed_data = dev->length;
    if (copy_to_user(buf, dev->buffer, readed_data))
        return -EFAULT;
    atomic_set(&flag, 0);
    dev->length = 0;
    return readed_data;
}

static dev_t sleeper_info;
struct cdev cdev;
static struct file_operations f_ops = {
    .owner = THIS_MODULE,
    .open = &sleeper_open,
    .release = &sleeper_release,
    .write = &sleeper_write,
    .read = &sleeper_read
};

int static __init sleeper_init(void)
{
    int retval = 0;

#ifdef SLEEPER_MAJOR
    sleeper_info = MKDEV(SLEEPER_MAJOR, SLEEPER_MINOR);
    register_chrdev_region(sleeper_info, SLEEPER_COUNT, THIS_MODULE->name);
#else
    alloc_chrdev_region(&sleeper_info, SLEEPER_MINOR, SLEEPER_COUNT, THIS_MODULE->name);
#endif
    
    cdev_init(&cdev, &f_ops);
    if (cdev_add(&cdev, sleeper_info, SLEEPER_COUNT))
        return -ERESTARTSYS;

    return retval;
}

void static __exit sleeper_exit(void)
{
    cdev_del(&cdev);
    unregister_chrdev_region(sleeper_info, SLEEPER_COUNT);
}

module_init(sleeper_init);
module_exit(sleeper_exit);

MODULE_LICENSE("GPLv2");
MODULE_AUTHOR("Pavel Vasilev <django@altlinux.org>");
MODULE_DESCRIPTION("SLEEPER - sample of using sleep/wake in kernel");
