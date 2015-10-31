#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/icmp.h>

#include "parser.h" 
#include "parser_repository.h"
#include "asprintf.h"

static char *icmpTypeString(unsigned char type) {
	static char buffer[4];
	
	switch (type) {
		case 0 : return "Echo Reply";
		case 3 : return "Destination Unreachable";
		case 4 : return "Source Quench";
		case 8 : return "Echo Request";
		case 9 : return "Router Advertisement";
		case 10 : return "Router Solicitation";
		case 11 : return "Time Exceeded";
		case 12 : return "Parameter Problem: Bad IP heade";
		case 13:  return "Timestamp";
		case 14:  return "Timestamp Reply";
		default: {
			// poor man's itoa
			memset(buffer, 0, 4);
			if (type < 10) {
				buffer[0] = type + '0';
			} else if (type < 100) {
				buffer[0] = (type % 10) + '0';
				type /= 10;
				buffer[1] = type + '0';
			} else {
				buffer[0] = (type % 10) + '0';
				type /= 10;
				buffer[1] = (type % 10) + '0';
				type /= 10;
				buffer[2] =  type + '0';
			}
			return buffer;
		}
	}
}

static char* parseIcmpHeader(const unsigned char * const buffer, size_t size) {
	if (size < sizeof(struct icmphdr)) {
		return "Unable to parse ICMP header. Header size was too small.";
	}
	struct icmphdr *icmp = (struct icmphdr *)buffer;
	char *result = "";
	
	
	if (asprintf(&result, "[ICMP Header]\n\t"
			"Type: %s\t"
			"Code: %u\n",
			icmpTypeString(icmp->type),
			icmp->code
		) == -1) {
			return "Error allocating memory for output of icmphdr.";
	}
	
	return result;
}

bool InitParser(ParserRepository *repo) {
	repo->registerTransportParser(repo, IPPROTO_ICMP, parseIcmpHeader);
	//repo->registerTransportParser(repo, IPPROTO_ICMPV6, Parser parser);
	return true;
}

