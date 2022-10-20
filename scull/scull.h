#ifndef MMAIN_H
#define MMAIN_H

/*
 *  Добавляет несколько полезный макросов:
 * '_IO()', '_IO{W,R}()', '_IOWR()'
 *  
 *  Потому что мы уважаем наставления эльфов и это модно :)
 */
#include <linux/ioctl.h>
#include <linux/semaphore.h>
#include <linux/cdev.h>

#include "round_buffer.h"

#define CHRDEV_BASEMINOR 0
#define CHRDEV_COUNT 4

#define BUFFER_SIZE 512

#define MINIMAL(a, b) ((a) < (b) ? (a) : (b))

#define SCULL_IOC_TYPE 0xF9
#define SCULL_IOC_MAXNR 0x00

#define SCULL_IOCRESET _IO(SCULL_IOC_TYPE, 0)

struct device_info {
    struct cdev cdev;
    struct mutex lock;
    struct rounded_buffer buffer;
};

#endif
