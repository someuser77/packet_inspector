#ifndef _DIRECTIONAL_FILTER_OPTIONS_H_
#define _DIRECTIONAL_FILTER_OPTIONS_H_

#include "filter_options.h"

typedef struct DirectionalFilterOptions {
	void *impl;
	
	struct FilterOptions *(*getIncomingFilterOptions)(struct DirectionalFilterOptions *self);
	void (*setIncomingFilterOptions)(struct DirectionalFilterOptions *self, FilterOptions *incoming);
	
	struct FilterOptions *(*getOutgoingFilterOptions)(struct DirectionalFilterOptions *self);
	void (*setOutgoingFilterOptions)(struct DirectionalFilterOptions *self, FilterOptions *outgoing);
	
	size_t (*serialize)(struct DirectionalFilterOptions *self, unsigned char *buffer, size_t size);
	
	bool (*equals)(struct DirectionalFilterOptions *self, struct DirectionalFilterOptions *other);
	
} DirectionalFilterOptions;

DirectionalFilterOptions *DirectionalFilterOptions_Create(void);
DirectionalFilterOptions *DirectionalFilterOptions_Deserialize(const unsigned char *buffer, size_t size);
void DirectionalFilterOptions_Destroy(DirectionalFilterOptions **);
#endif
