#include <arpa/inet.h>
#include "filter_options.h"

void FillFilterOptions(FilterOptions *filterOptions) {
	unsigned char srcMac[ETH_ALEN] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6};
	unsigned char dstMac[ETH_ALEN] = {0x6, 0x5, 0x4, 0x3, 0x2, 0x1};
	uint32_t srcIp, dstIp;
	unsigned char srcIp6[IP6_ALEN] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
	unsigned char dstIp6[IP6_ALEN] = { 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1 };	
	
	inet_pton(AF_INET, "192.0.2.33", &srcIp);
	inet_pton(AF_INET, "192.0.2.34", &dstIp);
	
	filterOptions->setSrcMac(filterOptions, srcMac);
	filterOptions->setDstMac(filterOptions, dstMac);
	
	filterOptions->setSrcIp(filterOptions, srcIp);
	filterOptions->setDstIp(filterOptions, dstIp);
	
	filterOptions->setSrcIp6(filterOptions, srcIp6);
	filterOptions->setDstIp6(filterOptions, dstIp6);
	
	filterOptions->setDevice(filterOptions, "MyDevice", 8);
	
	filterOptions->setProtocol(filterOptions, IPPROTO_TCP);
	
	filterOptions->setSrcPort(filterOptions, 123);
	filterOptions->setDstPort(filterOptions, 65535);
}