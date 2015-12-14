#ifndef _FILTER_CLIENT_H_ 
#define _FILTER_CLIENT_H_ 

#include "directional_filter_options.h"

typedef struct FilterClient {
	void *impl;
	
	bool (*initialize)(struct FilterClient *self, DirectionalFilterOptions *options);
	unsigned char * (*receive)(struct FilterClient *self, size_t *size);
	void (*destroy)(struct FilterClient *self);
} FilterClient;

FilterClient *FilterClient_Create();

#endif