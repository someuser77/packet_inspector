#include <stdlib.h>
#include <string.h>
#include "hashtable.h"

typedef struct HashtableNode {
	int key;
	void *value;
} HashtableNode;

typedef struct HashtableBucket {
	HashtableNode *head;
	int capacity;
	int size;
} HashtableBucket;

typedef struct HashtableImpl {
	HashtableBucket *(*buckets)[];
	int numberOfBuckets;
	unsigned int (*hash)(int key);
} HashtableImpl;

static HashtableImpl *impl(Hashtable *self) {
	return (HashtableImpl *)self->impl;
}


#define for_each_node_in_bucket(idx, node, bucket) \
for (idx = 0, node = bucket->head; idx < bucket->size; idx++, node = bucket->head + idx)

static HashtableBucket *getBucketByIndex(Hashtable *self, unsigned int bucketIndex) {
	HashtableBucket *bucket;
	
	if ((int)bucketIndex >= impl(self)->numberOfBuckets)
		return NULL;
	
	bucket = (*(impl(self)->buckets))[bucketIndex];
	
	return bucket;
}

static HashtableBucket *getBucket(Hashtable *self, int key) {
	unsigned int bucketIndex = impl(self)->hash(key);
	return getBucketByIndex(self, bucketIndex);
}

static HashtableNode *getBucketNode(Hashtable *self, int key) {
	HashtableBucket *bucket = getBucket(self, key);
	HashtableNode *ptr;
	int i;
	
	if (!bucket) 
		return NULL;
	
	for_each_node_in_bucket(i, ptr, bucket) {
		if (key == ptr->key) {
			return ptr;
		}
	}
	
	return NULL;
}

static 	bool exists(struct Hashtable *self, int key) {
	return getBucketNode(self, key) != NULL;
}

static bool tryGet(struct Hashtable *self, int key, void **value) {
	HashtableNode *node = getBucketNode(self, key);
	if (!node)
		return false;
	*value = node->value;
	return true;
}

static void *get(struct Hashtable *self, int key) {
	void *value;
	
	if (tryGet(self, key, &value)) {
		return value;
	}
	
	return NULL;
}

static bool set(Hashtable *self, int key, void *value) {
	HashtableBucket *bucket;
	HashtableNode *node;
	unsigned int bucketIndex;
	bucket = getBucket(self, key);
	
	if (!bucket) {
		bucket = (HashtableBucket *)malloc(sizeof(HashtableBucket));
		
		if (!bucket)
			return false;
		
		bucket->head = NULL;
		bucket->size = 0;
		bucket->capacity = 0;
		
		bucketIndex = impl(self)->hash(key);
		(*(impl(self)->buckets))[bucketIndex] = bucket;
	}
	
	node = getBucketNode(self, key);
	
	if (node) {
		
		node->value = value;
		
	} else {
	
		if (bucket->size == bucket->capacity) {
			// the bucket is full so it has to be increased.
			bucket->capacity = bucket->capacity == 0 ? 1 : bucket->capacity << 1;
			bucket->head = (HashtableNode *)realloc(bucket->head, bucket->capacity * sizeof(HashtableNode));
			if (!bucket->head)
				return false;
		}
		
		node = bucket->head + bucket->size;
		
		bucket->size++;
		
		node->key = key;
		node->value = value;
	}
	
	return true;
}

static int *getBucketSizes(struct Hashtable *self) {
	int buckets = impl(self)->numberOfBuckets;
	int *result;
	int i;
	HashtableBucket *bucket;
	result = (int *)malloc(sizeof(int) * buckets);
	memset(result, 0, sizeof(int) * buckets);
	
	for (i = 0; i < buckets; i++) {
		bucket = getBucketByIndex(self, i);
		
		if (!bucket)
			continue;
		
		result[i] = bucket->size;
	}
	
	return result;
}


static void destroy(struct Hashtable *self) {
	int i;
	HashtableBucket *bucket;
	
	for (i = 0; i < impl(self)->numberOfBuckets; i++) {
		bucket = getBucketByIndex(self, i);
		
		if (!bucket)
			continue;
		
		free(bucket->head);
		free(bucket);
	}
	
	free(impl(self)->buckets);
	free(impl(self));
	free(self);
}


Hashtable *Hashtable_Create(int buckets, unsigned int (*hash)(int key)) {
	size_t size = sizeof(HashtableBucket *) * buckets;
	Hashtable *hashtable = (Hashtable *)malloc(sizeof(Hashtable));
	hashtable->impl = (HashtableImpl *)malloc(sizeof(HashtableImpl));
	impl(hashtable)->buckets = (HashtableBucket *(*)[])malloc(size);
	if (!impl(hashtable)->buckets)
		return NULL;
	
	memset(impl(hashtable)->buckets, 0, size);
	impl(hashtable)->numberOfBuckets = buckets;
	impl(hashtable)->hash = hash;
	hashtable->exists = exists;
	hashtable->set = set;
	hashtable->get = get;
	hashtable->tryGet = tryGet;
	hashtable->getBucketSizes = getBucketSizes;
	hashtable->destroy = destroy;
	
	return hashtable;
}

