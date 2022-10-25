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

#include <linux/poll.h>

/*
 *  Семафор необходим для создания мультипроцессорного ресурса
 * и для минимизации рисков утечки памяти.
 */
#include <linux/semaphore.h>
#include <linux/capability.h>
#include <linux/wait.h>

#include "scull.h"
#include "round_buffer.h"

static DECLARE_WAIT_QUEUE_HEAD(wait_queue_head);
struct device_info *scull_devices;

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
     *  Будет вызвана после закрытия последнего дескриптора 'struct file *'
     * Примечание: будет вызвана 1 раз, несмотря на вызов 'fork()'
     *
     *  Здесь ничего нет, потому что это обеспечит возможность хранить
     * данные глобально! Одна структура для всех процессов.
     */
    return 0;
}

ssize_t static lwrite(struct file *filp, const char __user *from_user, size_t sz, loff_t *f_op)
{
    ssize_t retval = sz;
    struct device_info *dev = filp->private_data;
    struct rounded_buffer *buf = &dev->buffer;

    rounded_buffer_add_item(buf, from_user, &retval);
    return retval;
}

ssize_t static lread(struct file *filp, char __user *to_user, size_t sz, loff_t *f_op)
{
    ssize_t retval = sz;
    struct device_info *dev = filp->private_data;
    struct rounded_buffer *buf = &dev->buffer;

    rounded_buffer_get_item(buf, to_user, &retval);
    return retval;
}

long static lioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    /*
     *  'cmd' - command parameter, defineds by '_IO()', '_IO{W,R}()', '_IOWR()'
     */
    struct device_info *dev = filp->private_data;
    int retval = 0;

    if (_IOC_TYPE(cmd) != SCULL_IOC_TYPE) return -ENOTTY;
    if (_IOC_NR(cmd) > SCULL_IOC_MAXNR) return -ENOTTY;


    switch (cmd) {

        case SCULL_IOCRESET:
            if (!capable(CAP_SYS_ADMIN))
                return -EPERM;
            rounded_buffer_clean(&dev->buffer);
            break;
        
        default:
            return -ENOTTY;
    }
    return retval;
}

static unsigned int lpoll(struct file *filp, poll_table *wait)
{
    struct device_info *dev = filp->private_data;
    struct rounded_buffer *buf = &dev->buffer;
    unsigned int mask = 0;

    if (mutex_lock_interruptible(&dev->lock)) {
        // If mutex wasn't lock!
        return -ERESTARTSYS;
    }
    
    poll_wait(filp, &wait_queue_head, wait);
    if (!rounded_buffer_is_free(buf)) {
        mask |= POLLIN | POLLRDNORM;
    } else {
        mask |= POLLOUT | POLLWRNORM;
    }
    mutex_unlock(&dev->lock);
    return mask;
}


static dev_t device_number;
static struct file_operations f_ops = {
    .owner = THIS_MODULE,
    .open = &lopen,
    .release = &lrelease,
    .write = &lwrite,
    .read = &lread,
    .unlocked_ioctl = &lioctl,
    .poll = &lpoll
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
        rounded_buffer_init(&dev->buffer, 2);
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
        rounded_buffer_clear(&dev->buffer);
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