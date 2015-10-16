#ifndef _HASHTABLE_H_
#define _HASHTABLE_H_

#include <stdbool.h>

typedef struct Hashtable {
	void *impl;
	bool (*exists)(struct Hashtable *self, int key);
	bool (*set)(struct Hashtable *self, int key, void *value);
	void *(*get)(struct Hashtable *self, int key);
	bool (*tryGet)(struct Hashtable *self, int key, void **value);
	int *(*getBucketSizes)(struct Hashtable *self);
	void (*iterateAll)(struct Hashtable *self, void (*visit)(int key, void *value, void *context), void *context);
	void (*destroy)(struct Hashtable *self);
} Hashtable;

Hashtable *Hashtable_Create(int buckets, unsigned int (*hash)(int key));

#endif