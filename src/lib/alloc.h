#ifndef _ALLOC_H_
#define _ALLOC_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#endif

void *alloc(size_t size);

void release(void *ptr);

#endif
