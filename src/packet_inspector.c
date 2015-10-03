#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include "lib/filter_client.h"

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

int main(int __attribute__((unused)) argc, char __attribute__((unused)) *argv[]) {
	unsigned char *buffer;
	size_t size;
	FilterClient *filterClient;
	FilterOptions *filterOptions;
	
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
	filterOptions->setDstIp(filterOptions, ntohl(dstIp));
	
	//filterOptions->setSrcIp6(filterOptions, srcIp6);
	//filterOptions->setDstIp6(filterOptions, dstIp6);
	
	//filterOptions->setDevice(filterOptions, "MyDevice", 8);
	
	//filterOptions->setProtocol(filterOptions, IPPROTO_TCP);
	
	//filterOptions->setSrcPort(filterOptions, 80);
	//filterOptions->setDstPort(filterOptions, 80);
	
	printf("Initializing with %s", filterOptions->description(filterOptions));
	
	filterClient = FilterClient_Create();
	filterClient->initialize(filterClient, filterOptions);
	
	while (1) {
		printf("Waiting for data... ");
		buffer = filterClient->receive(filterClient, &size);
		printf("Got %zu bytes.\n", size);
		hex_dump(buffer, size);
		free(buffer);
	}
	
	filterClient->destroy(filterClient);
	free(filterClient);
	
	return 0;
}
