#include <stdlib.h>
#include <stdio.h>
#include "lib/filter_client.h"

int main(int __attribute__((unused)) argc, char __attribute__((unused)) *argv[]) {
	FilterClient *filterClient;
	FilterOptions *filterOptions;
	
	filterOptions = FilterOptions_Create();
	
	filterClient = FilterClient_Create();
	filterClient->initialize(filterClient, filterOptions);
	filterClient->destroy(filterClient);
	free(filterClient);
	return 0;
}
