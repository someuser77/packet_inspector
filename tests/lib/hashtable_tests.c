 #include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../minunit.h" 
#include "hashtable.h"

Hashtable *hashtable;
const int DEFAULT_BUCKETS_COUNT = 1024;

struct Person {
	char *name;
	int age;
};

static int Dummy_Func(int a, int b) {
	return a + b;
}

static unsigned int simpleModuloHash(int key) {
	return (unsigned int)(key % DEFAULT_BUCKETS_COUNT);
}

char *test_Hashtable_SimpleInsertionAndLookup() {
	int data = 8;
	int key = 1;
	mu_assert(!hashtable->exists(hashtable, key), "Exits failed on empty hashtable.");
	hashtable->set(hashtable, key, &data);
	mu_assert(hashtable->get(hashtable, key) == &data, "Unable to returned stored value.");
	return NULL;
}

char *test_Hashtable_DifferentTypes() {
	int a = 8;
	float b = 10.1;
	struct Person c = { .name = "Name", .age = 10 };
	int (*d)(int a, int b) = Dummy_Func;
	
	hashtable->set(hashtable, 1, &a);
	hashtable->set(hashtable, 2, &b);
	hashtable->set(hashtable, 3, &c);
	hashtable->set(hashtable, 4, &d);
	
	mu_assert(hashtable->get(hashtable, 1) == &a, "Setting Int failed.");
	mu_assert(hashtable->get(hashtable, 2) == &b, "Setting float failed.");
	mu_assert(hashtable->get(hashtable, 3) == &c, "Setting struct failed.");
	mu_assert(hashtable->get(hashtable, 4) == &d, "Setting function pointer failed.");
	return NULL;
}
static void printBucketSizes(Hashtable *hashtable, int buckets) __attribute__ ((unused));
static void printBucketSizes(Hashtable *hashtable, int buckets) {
	int i;
	int *sizes = hashtable->getBucketSizes(hashtable);
	for (i = 0; i < buckets; i++) {
		printf("Bucket %d: %d\n", i, sizes[i]);
	}
	free(sizes);
}

static bool sizesMinMaxValuesAre(Hashtable *hashtable, int min, int max) {
	int *sizes = hashtable->getBucketSizes(hashtable);
	int actualMin, actualMax, i;
	actualMin = actualMax = sizes[0];
	for (i = 1; i < DEFAULT_BUCKETS_COUNT; i++) {
		if (sizes[i] < actualMin) actualMin = sizes[i];
		if (sizes[i] > actualMax) actualMax = sizes[i];
	}
	return min == actualMin && max == actualMax;
}

char *test_Hashtable_TestCollision() {
	int data1 = 8;
	int data2 = 9;
	int data3 = 10;
	int data4 = 11;
	int key1 = 5;
	int key2 = key1 + DEFAULT_BUCKETS_COUNT;
	int key3 = key2 + DEFAULT_BUCKETS_COUNT;
	
	mu_assert(sizesMinMaxValuesAre(hashtable, 0, 0), "The uninitialized bucket sizes were wrong.");
	
	hashtable->set(hashtable, key1, &data1);
	
	hashtable->set(hashtable, key2, &data2);
	
	hashtable->set(hashtable, key3, &data3);
	
	mu_assert(sizesMinMaxValuesAre(hashtable, 0, 3), "The bucket sizes were wrong.");
	
	mu_assert(hashtable->get(hashtable, key1) == &data1, "Failed to find value of key1");
	mu_assert(hashtable->get(hashtable, key2) == &data2, "Failed to find value of key2");
	mu_assert(hashtable->get(hashtable, key3) == &data3, "Failed to find value of key3");
	
	hashtable->set(hashtable, key2, &data4);
	
	mu_assert(hashtable->get(hashtable, key2) == &data4, "Failed to find value of key2 after overwriting it.");
	
	return NULL;
}

static unsigned int simpleModuloHashForHugeTable(int key) {
	return (unsigned int)(key % 65536);
}

char *test_Hashtable_HugeHashtable() {
	int size = 65536;
	Hashtable *hugeHashtable = Hashtable_Create(size, simpleModuloHashForHugeTable);
	int *array;
	int i, *value;
	array = (int *)malloc(sizeof(int) * size);
	for (i = 0; i < size; i++) {
		array[i] = i;
		hugeHashtable->set(hugeHashtable, i, array + i); 
	}
	for (i = 0; i < size; i++) {
		value = hugeHashtable->get(hugeHashtable, i);
		mu_assert(*value == i, "Huge Hashtable failed to get an item key.");
	}
	return NULL;
}

void sumAllValues(__attribute__((unused)) int key, void *value, void *context) {
	*((int *)context) += *((int *)value);
}

char *test_Hashtable_Iteration() {
	int keys[] = { 1, 2, 3, 1 + DEFAULT_BUCKETS_COUNT, 2 + DEFAULT_BUCKETS_COUNT, 3 + DEFAULT_BUCKETS_COUNT };
	int values[] = { 1, 2, 3, 4, 5, 6 };
	int i, size = 6;
	int expected = 0, actual = 0;
	
	for (i = 0; i < size; i++) {
		hashtable->set(hashtable, keys[i], &values[i]);
		expected += values[i];
	}
	
	hashtable->iterateAll(hashtable, sumAllValues, &actual);

	mu_assert(expected == actual, "Iteration returned wrong sum.");
	
	return NULL;
}

char *all_tests() {
	mu_suite_start();

	mu_run_test(test_Hashtable_SimpleInsertionAndLookup);
	mu_run_test(test_Hashtable_DifferentTypes);
	mu_run_test(test_Hashtable_TestCollision);
	mu_run_test(test_Hashtable_HugeHashtable);
	mu_run_test(test_Hashtable_Iteration);
	return NULL;
}

void init() {
	hashtable = Hashtable_Create(DEFAULT_BUCKETS_COUNT, simpleModuloHash); 
}

void cleanup() {
	hashtable->destroy(hashtable);
	hashtable = NULL;
}

RUN_TESTS_WITH_SETUP(all_tests, init, cleanup);
