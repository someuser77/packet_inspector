#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>

#include "parser.h" 
#include "parser_repository.h"
#include "asprintf.h"

static char *getEtherType(unsigned short protocol) {
	switch(protocol) {
		case ETH_P_IP:
			return "IP";
		case ETH_P_IPV6:
			return "IPv6";
		case ETH_P_ARP:
			return "ARP";
		default:
			return "";
	}
}

static char* getMacString(const struct ether_addr *addr, char *buf) {
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr->ether_addr_octet[0], addr->ether_addr_octet[1],
            addr->ether_addr_octet[2], addr->ether_addr_octet[3],
            addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
    return buf;
}

static char* ParseEthermetHeader(const unsigned char * const buffer, size_t size) {
	if (size < sizeof(struct ethhdr)) {
		return "Unable to parse Eth header. Header size was too small.";
	}
	char dst[ETH_ALEN * 2 + 5 + 1],  src[ETH_ALEN * 2 + 5 + 1];
	struct ethhdr *eth = (struct ethhdr *)buffer;
	char *result = "";
	unsigned short proto = ntohs(eth->h_proto);
	
	if (asprintf(&result, "[Ethernet Header]\n"
			"Destination MAC: %s \n"
			"Source MAC: %s \n"
			"Protocol: %s %u 0x%04x\n",
			getMacString((struct ether_addr *)&(eth->h_dest), dst),
			getMacString((struct ether_addr *)&(eth->h_source), src),
			getEtherType(proto), proto, proto
		) == -1) {
			return "Error allocating memory for output of ethhdr.";
		}
	return result;
}

bool InitParser(ParserRepository *repo) {
	repo->registerEthParser(repo, ParseEthermetHeader);
	return true;
}
