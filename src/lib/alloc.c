#ifdef __KERNEL__
#include <linux/vmalloc.h>
#else
#include <stdlib.h>
#endif

void *alloc(size_t size) {
	#ifdef __KERNEL__
	return vmalloc(size);
	#else
	return malloc(size);
	#endif
}

void release(void *ptr) {
	#ifdef __KERNEL__
	vfree(ptr);
	#else
	free(ptr);
	#endif
}