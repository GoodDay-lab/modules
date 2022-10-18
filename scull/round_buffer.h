#ifndef MROUNDBUFFER_H
#define MROUNDBUFFER_H

#include <linux/types.h>
#include <linux/uidgid.h>

#define ROUNDED_BUFFER_ITEM_SIZE 512
#define ROUNDED_BUFFER_ITEM_NEXT(INDEX, SIZE) (((INDEX) + 1) % (SIZE))

struct rounded_buffer_item;
struct rounded_buffer {
    unsigned int w_head;
    unsigned int r_head;
    size_t length;
    struct rounded_buffer_item *items;
};

struct rounded_buffer_item {
    kuid_t user;
    size_t size;
    int flag;
    char buffer[ROUNDED_BUFFER_ITEM_SIZE];
};

struct rounded_buffer *rounded_buffer_alloc(void);
int rounded_buffer_init(struct rounded_buffer *, size_t);
void rounded_buffer_release(struct rounded_buffer *);
void rounded_buffer_add_item(struct rounded_buffer *, const char *, size_t *);
void rounded_buffer_get_item(struct rounded_buffer *, char *, size_t *);
void rounded_buffer_clear(struct rounded_buffer *);

#endif