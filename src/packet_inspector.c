#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include "lib/utils.h"
#include "lib/filter_client.h"
#include "lib/parser.h"
#include "lib/parser_repository.h"

static volatile bool enabled = true;

#define MAX_PAYLOAD ETH_FRAME_LEN

void hex_dump(unsigned char *buffer, size_t size) {
	const int line_length = 16;
	size_t i, line_offset, j;
	int padding;
	
	for (i = 0; i < size; i += line_length) {
		
		printf("%04X\t", (i / line_length) * line_length);
		
		for (line_offset = i; line_offset < i + line_length && line_offset < size; line_offset++) {
			printf("%02X ", buffer[line_offset]);
		}
		
		padding = (line_length - (line_offset % line_length)) % line_length;
		
		for (j = 0; j < padding; j++) {
			printf("   ");
		}
		
		printf(" |  ");
		
		for (line_offset = i; line_offset < i + line_length && line_offset < size; line_offset++) {
			char ch = buffer[line_offset];
			if (ch >= ' ')
				printf("%c ", ch);
			else
				printf(". ");
		}
		
		printf("\n");
	}
}

void displayPacket(ParserRepository *repo, unsigned char *buffer, size_t size) {
	char *packet;
	Parser parser;
	parser = repo->getEthParser(repo);
	
	printf("=========================");
	
	
	packet = parser(buffer, size);
	printf("%s", packet);
	free(packet);
}

int main(int __attribute__((unused)) argc, char __attribute__((unused)) *argv[]) {
	unsigned char *buffer;
	size_t size;
	FilterClient *filterClient;
	FilterOptions *filterOptions;	
	ParserRepository *repository = ParserRepository_Create();
	
	printf("PID: %d", getpid());
	filterOptions = FilterOptions_Create();
	
	unsigned char srcMac[ETH_ALEN] = {0x6, 0x5, 0x4, 0x3, 0x2, 0x1};
	unsigned char dstMac[ETH_ALEN] = {0x00, 0x22, 0xfa, 0xe8, 0xc2, 0x42};
	
	uint32_t srcIp, dstIp;
	unsigned char srcIp6[IP6_ALEN] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
	unsigned char dstIp6[IP6_ALEN] = { 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1 };	
	
	inet_pton(AF_INET, "192.0.2.33", &srcIp);
	inet_pton(AF_INET, "192.229.233.146", &dstIp);
	
	//filterOptions->setSrcMac(filterOptions, srcMac);
	
	//filterOptions->setDstMac(filterOptions, dstMac);
	
	//filterOptions->setSrcIp(filterOptions, srcIp);
	//filterOptions->setDstIp(filterOptions, ntohl(dstIp));
	
	//filterOptions->setSrcIp6(filterOptions, srcIp6);
	//filterOptions->setDstIp6(filterOptions, dstIp6);
	
	filterOptions->setDevice(filterOptions, "wlan0", 5);
	
	filterOptions->setProtocol(filterOptions, IPPROTO_TCP);
	
	filterOptions->setEtherType(filterOptions, ETH_P_IP);
	
	//filterOptions->setSrcPort(filterOptions, 80);
	//filterOptions->setDstPort(filterOptions, 80);
	
	printf("Initializing with %s", filterOptions->description(filterOptions));
	
	filterClient = FilterClient_Create();
	
	if (!repository->populate(repository, "parsers")) {
		log_error("Error populating parser repository.");
		return EXIT_FAILURE;
	}
	
	if (!filterClient->initialize(filterClient, filterOptions)) {
		printf("Error initializing. Did you remember to load the module?\n");
		return EXIT_FAILURE;
	}
	
	while (1) {
		printf("Waiting for data... \n");
		fflush(stdout);
		buffer = filterClient->receive(filterClient, &size);
		if (buffer == NULL) {
			break;
		}
		printf("Got %zu bytes.\n", size);
		//hex_dump(buffer, size);
		
		displayPacket(repository, buffer, size);		
		
		free(buffer);
	}
	printf("Destroy...");
	filterClient->destroy(filterClient);
	free(filterClient);
	
	return EXIT_SUCCESS;
}
