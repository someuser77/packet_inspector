#include <linux/in.h>
#include "../minunit.h" 
#include "filter_options_tests_utils.h"
#include "directional_filter_options.h"

char *test_DirectionalFilterOptions_Serialization() {
	/* FilterOptions *f1, *f2; */
	size_t size;
	unsigned char *buffer;
	
	DirectionalFilterOptions *options = DirectionalFilterOptions_Create();
	DirectionalFilterOptions *other = DirectionalFilterOptions_Create();
	
	FilterOptions *incoming = FilterOptions_Create();
	FilterOptions *outgoing = FilterOptions_Create();
		
	FillFilterOptions(incoming);
	FillFilterOptions(outgoing);
	
	outgoing->setSrcPort(outgoing, 456);
	outgoing->setProtocol(outgoing, IPPROTO_UDP);
	
	options->setIncomingFilterOptions(options, incoming);
	options->setOutgoingFilterOptions(options, outgoing);
	
	size = options->serialize(options, NULL, 0);
	buffer = (unsigned char *)malloc(size);
	options->serialize(options, buffer, size);
	
	other = DirectionalFilterOptions_Deserialize(buffer, size);
	
	free(buffer);
	/*
	f1 = other->getIncomingFilterOptions(other);
	f2 = other->getOutgoingFilterOptions(other);
	printf("\nIncoming:\n%s\n\n", f1->description(f1));
	printf("\nOutgoing:\n%s\n\n", f2->description(f2));
	*/
	
	mu_assert(options->equals(options, other), "Deserializatoin Failed.");
	
	DirectionalFilterOptions_Destroy(&options);
	
	return NULL;
}

char *test_DirectionalFilterOptions_FreeSameFilterOptions() {
	DirectionalFilterOptions *options = DirectionalFilterOptions_Create();
	FilterOptions *filterOptions = FilterOptions_Create();
	
	options->setIncomingFilterOptions(options, filterOptions);
	options->setOutgoingFilterOptions(options, filterOptions);
	
	DirectionalFilterOptions_Destroy(&options);
	
	return NULL;
}

char *all_tests() {
	mu_suite_start();
	mu_run_test(test_DirectionalFilterOptions_Serialization);
	mu_run_test(test_DirectionalFilterOptions_FreeSameFilterOptions);
	return NULL;
}

RUN_TESTS(all_tests);
