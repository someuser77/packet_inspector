#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> // for getpid()
#include "lib/filter_client.h"
#include "lib/parser.h"
#include "lib/parser_repository.h"
#include "lib/utils.h"
#include "client_parser.h"
#include "cmd_args.h"

static volatile bool enabled = true;

int main(int argc, char *argv[]) {
	unsigned char *buffer;
	
	size_t size;
	FilterClient *filterClient;
	DirectionalFilterOptions *options;
	
	ParserRepository *repository = ParserRepository_Create();
	
	printf("PID: %d\n", getpid());
	
	options = parseCommandLineArguments(argc, argv);
	
	if (!options) {
		return EXIT_FAILURE;
	}
	
	filterClient = FilterClient_Create();
	
	if (!repository->populate(repository, "parsers")) {
		log_error("Error populating parser repository.");
		return EXIT_FAILURE;
	}
	
	if (!filterClient->initialize(filterClient, options)) {
		printf("Error initializing. Did you remember to load the module?\n");
		return EXIT_FAILURE;
	}
	
	while (1) {
		printf("Waiting for data... \n");
		fflush(stdout);
		buffer = filterClient->receive(filterClient, &size);
		if (!buffer) {
			break;
		}
		printf("==========[ %zu bytes ]===============\n", size);
		//hex_dump(buffer, size);
		
		displayPacket(repository, buffer, size);		
		
		printf("\n");
		
		free(buffer);
	}
	printf("Destroy...");
	filterClient->destroy(filterClient);
	repository->destroy(repository);
	DirectionalFilterOptions_Destroy(&options);
	free(filterClient);
	
	return EXIT_SUCCESS;
}
