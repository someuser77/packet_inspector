#ifndef __KERNEL__
#include <string.h>
#endif

#include "alloc.h"
#include "directional_filter_options.h"

typedef struct {
	FilterOptions *incoming;
	FilterOptions *outgoing;	
} DirectionalFilterOptionsImpl;

static inline DirectionalFilterOptionsImpl *impl(struct DirectionalFilterOptions *self) {
	return (DirectionalFilterOptionsImpl *)self->impl;
}

static FilterOptions *getIncomingFilterOptions(struct DirectionalFilterOptions *self) {
	return impl(self)->incoming;
}

static void setIncomingFilterOptions(struct DirectionalFilterOptions *self, FilterOptions *incoming) {
	impl(self)->incoming = incoming;
}

static FilterOptions *getOutgoingFilterOptions(struct DirectionalFilterOptions *self) {
	return impl(self)->outgoing;
}

static void setOutgoingFilterOptions(struct DirectionalFilterOptions *self, FilterOptions *outgoing) {
	impl(self)->outgoing =  outgoing;
}

static size_t serialize(struct DirectionalFilterOptions *self, unsigned char *buffer, size_t size) {
	FilterOptions *incoming = getIncomingFilterOptions(self);
	FilterOptions *outgoing = getOutgoingFilterOptions(self);
	
	size_t incomingSize = incoming->serialize(incoming, NULL, 0);
	size_t outgoingSize = outgoing->serialize(outgoing, NULL, 0);
	size_t expectedSize = incomingSize + outgoingSize;
		
	if (buffer != NULL && size >= expectedSize) {
		incoming->serialize(incoming, buffer, incomingSize);
		outgoing->serialize(outgoing, buffer + incomingSize, outgoingSize);
	}
	
	return expectedSize;
}

bool equals(struct DirectionalFilterOptions *self, struct DirectionalFilterOptions *other) {
	FilterOptions *incomingSelf, *incomingOther, *outgoingSelf, *outgoingOther;
	
	if (other == NULL)
		return false;
	
	if (self == other)
		return true;
	
	incomingSelf = self->getIncomingFilterOptions(self);
	outgoingSelf = self->getOutgoingFilterOptions(self);
	
	incomingOther = other->getIncomingFilterOptions(other);
	outgoingOther = other->getOutgoingFilterOptions(other);
	
	return incomingSelf->equals(incomingSelf, incomingOther) && outgoingSelf->equals(outgoingSelf, outgoingOther);
}

DirectionalFilterOptions *DirectionalFilterOptions_Create(void) {
	DirectionalFilterOptions *options = (DirectionalFilterOptions *)alloc(sizeof(DirectionalFilterOptions));
	if (!options) {
		return NULL;
	}
	
	memset(options, 0, sizeof(DirectionalFilterOptions));
	
	options->impl = (DirectionalFilterOptionsImpl *)alloc(sizeof(DirectionalFilterOptionsImpl));
	if (!options->impl)
		return NULL;
	
	memset(options->impl, 0, sizeof(DirectionalFilterOptionsImpl));
	
	options->getIncomingFilterOptions = getIncomingFilterOptions;
	options->setIncomingFilterOptions = setIncomingFilterOptions;
	options->getOutgoingFilterOptions = getOutgoingFilterOptions;
	options->setOutgoingFilterOptions = setOutgoingFilterOptions;
	options->serialize = serialize;
	options->equals = equals;
	
	return options;
}

DirectionalFilterOptions *DirectionalFilterOptions_Deserialize(const unsigned char *buffer, size_t size) {
	DirectionalFilterOptions *options;
	FilterOptions *incoming, *outgoing;
	size_t firstSize;
	
	if (size < sizeof(DirectionalFilterOptionsImpl)) {
		return NULL;
	}

	options = DirectionalFilterOptions_Create();
	
	incoming = FilterOptions_Deserialize(buffer, size);
	
	firstSize = incoming->serialize(incoming, NULL, 0);
	
	outgoing = FilterOptions_Deserialize(buffer + firstSize, size - firstSize);
	
	options->setIncomingFilterOptions(options, incoming);
	options->setOutgoingFilterOptions(options, outgoing);
	
	return options;
}

void DirectionalFilterOptions_Destroy(DirectionalFilterOptions **options) {
	FilterOptions *incoming = (*options)->getIncomingFilterOptions(*options);
	FilterOptions *outgoing = (*options)->getOutgoingFilterOptions(*options);
	bool sameFilterOptions = incoming == outgoing;
	
	FilterOptions_Destroy(&incoming);
	
	if (!sameFilterOptions)
		FilterOptions_Destroy(&outgoing);
	
	release(impl(*options));
	release(*options);
	*options = NULL;
}
 
