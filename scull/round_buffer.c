#include <linux/slab.h>
#include <asm/current.h>
#include <linux/errno.h>

#include <asm/uaccess.h>

#include "scull.h"
#include "round_buffer.h"

struct rounded_buffer *rounded_buffer_alloc(void)
{
    struct rounded_buffer *buf = kmalloc(sizeof(struct rounded_buffer), GFP_KERNEL);
    return buf;
}

void rounded_buffer_clear(struct rounded_buffer *ptr)
{
    if (ptr->items != NULL)
        kfree(ptr->items);
    ptr->w_head = 0;
    ptr->r_head = 0;
    ptr->length = 0;
}

void rounded_buffer_clean(struct rounded_buffer *ptr)
{
    unsigned int counter;
    for (counter = 0; counter < ptr->length; counter++) {
        ptr->items[counter].flag = 0;
    }
    ptr->r_head = 0;
    ptr->w_head = 0;
}

int rounded_buffer_init(struct rounded_buffer *buf, size_t length)
{
    buf->items = kmalloc(sizeof(struct rounded_buffer_item) * length, GFP_KERNEL);
    buf->w_head = buf->r_head = 0;
    buf->length = length;
    if (buf->items != NULL) {
        int i, j;
        for (i = 0; i < length; i++) {
            buf->items[i].flag = 0;
            for (j = 0; j < ROUNDED_BUFFER_ITEM_SIZE; j++) {
                buf->items[i].buffer[i] = 0;
            }
        }
    }
    return (buf->items == NULL);
}

void rounded_buffer_release(struct rounded_buffer *buf)
{
    rounded_buffer_clear(buf);
    kfree(buf);
}

// Возвращает количество записанных байт в переменной 'size_t *size'
// Оттуда же в самом начале берётся количество байт для записи!
void rounded_buffer_add_item(struct rounded_buffer *ptr, const char *from, size_t *size)
{
    struct rounded_buffer_item *item;
    size_t writted_data = 0;

    if (ptr->length <= 0 || (ptr->items[ptr->w_head]).flag) {
        writted_data = -ENOSPC;
        goto out;
    }
    if (!access_ok(from, *size)) {
        writted_data = -EFAULT;
        goto out;
    }

    item = &ptr->items[ptr->w_head];
    writted_data = MINIMAL(*size, ROUNDED_BUFFER_ITEM_SIZE);
    memcpy(item->buffer, from, writted_data);
    item->size = writted_data;
    item->flag = 1;

    ptr->w_head = ROUNDED_BUFFER_ITEM_NEXT(ptr->w_head, ptr->length);

out:
    *size = writted_data;
}

// Возвращает количество записанных байт в переменной 'size_t *size'
// Оттуда же в самом начале берётся количество байт для чтения!
void rounded_buffer_get_item(struct rounded_buffer *ptr, char *to, size_t *size)
{
    struct rounded_buffer_item *item;
    size_t readed_data = 0;
    
    if (!(ptr->items[ptr->r_head]).flag || ptr->length <= 0) {
        readed_data = 0;
        goto out;
    }
    if (!access_ok(to, *size)) {
        readed_data = -EFAULT;
        goto out;
    }

    item = &ptr->items[ptr->r_head];
    readed_data = MINIMAL(*size, ROUNDED_BUFFER_ITEM_SIZE);
    memcpy(to, item->buffer, readed_data);
    item->size = 0;
    item->flag = 0;

    ptr->r_head = ROUNDED_BUFFER_ITEM_NEXT(ptr->r_head, ptr->length);

out:
    *size = readed_data;
}
