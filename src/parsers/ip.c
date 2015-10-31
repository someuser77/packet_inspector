#include <stdlib.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include "parser.h" 
#include "parser_repository.h"
#include "asprintf.h"


static char* parseIpHeader(const unsigned char * const buffer, size_t size) {
	if (size < sizeof(struct iphdr)) {
		return "Unable to parse IP header. Header size was too small.";
	}
	
	char dst[INET_ADDRSTRLEN],  src[INET_ADDRSTRLEN];
	
	struct iphdr *ip = (struct iphdr *)buffer;
	char *result = "";

	if (asprintf(&result, "[IP Header]\n\t"
		" Header Length: %u"
		" Version: %u"
		" TOS: %u"
		" Len: %u"
		" ID: %u"
		" Fragment Offset: %u"
		" TTL: %u"
		" Protocol: %u"
		" Checksum: %u"
		" Source: %s"
		" Destination: %s\n",
		ip->ihl, ip->version,
		ip->tos, ip->tot_len, ip->id, ip->frag_off,
		ip->ttl, ip->protocol, ip->check,
		inet_ntop(AF_INET, &ip->saddr, src, INET_ADDRSTRLEN),
		inet_ntop(AF_INET, &ip->daddr, dst, INET_ADDRSTRLEN)
		) == -1) {
			return "Error allocating memory for output of iphdr.\n";
	}
	return result;
}

bool InitParser(ParserRepository *repo) {
	repo->registerInternetParser(repo, ETH_P_IP, parseIpHeader);
	return true;
}