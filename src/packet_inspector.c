#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include "lib/filter_client.h"

#define MAX_PAYLOAD ETH_FRAME_LEN	

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
	inet_pton(AF_INET, "192.0.2.34", &dstIp);
	
	//filterOptions->setSrcMac(filterOptions, srcMac);
	
	filterOptions->setDstMac(filterOptions, dstMac);
	/*
	filterOptions->setSrcIp(filterOptions, srcIp);
	filterOptions->setDstIp(filterOptions, dstIp);
	
	filterOptions->setSrcIp6(filterOptions, srcIp6);
	filterOptions->setDstIp6(filterOptions, dstIp6);
	
	filterOptions->setDevice(filterOptions, "MyDevice", 8);
	
	filterOptions->setProtocol(filterOptions, IPPROTO_TCP);
	
	filterOptions->setSrcPort(filterOptions, 123);
	filterOptions->setDstPort(filterOptions, 65535);
	*/
	printf("Initializing with %s", filterOptions->description(filterOptions));
	
	filterClient = FilterClient_Create();
	filterClient->initialize(filterClient, filterOptions);
	
	while (1) {
		printf("Waiting for data... ");
		buffer = filterClient->receive(filterClient, &size);
		printf("Got %zu bytes.\n", size);
		
		free(buffer);
	}
	
	filterClient->destroy(filterClient);
	free(filterClient);
	
	return 0;
}
