#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

#include "client_parser.h"

#include "utils.h"

#define MAX_PAYLOAD ETH_FRAME_LEN

// from net/ipv6.h

#define NEXTHDR_HOP             0       /* Hop-by-hop option header. */
#define NEXTHDR_TCP             6       /* TCP segment. */
#define NEXTHDR_UDP             17      /* UDP message. */
#define NEXTHDR_IPV6            41      /* IPv6 in IPv6 */
#define NEXTHDR_ROUTING         43      /* Routing header. */
#define NEXTHDR_FRAGMENT        44      /* Fragmentation/reassembly header. */
#define NEXTHDR_ESP             50      /* Encapsulating security payload. */
#define NEXTHDR_AUTH            51      /* Authentication header. */
#define NEXTHDR_ICMP            58      /* ICMP for IPv6. */
#define NEXTHDR_NONE            59      /* No next header */
#define NEXTHDR_DEST            60      /* Destination options header. */
#define NEXTHDR_MOBILITY        135     /* Mobility header. */

int ipv6_ext_hdr(unsigned char nexthdr)
{
	/*
	* find out if nexthdr is an extension header or a protocol
	*/
	return	(nexthdr == NEXTHDR_HOP)       		||
				(nexthdr == NEXTHDR_ROUTING)   	||
				(nexthdr == NEXTHDR_FRAGMENT)  ||
				(nexthdr == NEXTHDR_AUTH)      	||
				(nexthdr == NEXTHDR_NONE)      	||
				(nexthdr == NEXTHDR_DEST);
}


void hexDump(unsigned char *buffer, size_t size) {
	const size_t line_length = 16;
	size_t i, line_offset, j;
	size_t padding;
	size_t original_size = size;
	bool truncated = false;
	
	if (size > HEX_DUMP_LIMIT_BYTES) {
		size = HEX_DUMP_LIMIT_BYTES;
		truncated = true;
	}
	
	for (i = 0; i < size; i += line_length) {
		
		printf("%04zx\t", (i / line_length) * line_length);
		
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
	
	if (truncated) {
		printf("\n... (truncated %zu bytes.)\n", original_size - HEX_DUMP_LIMIT_BYTES);
	}
}

void parsePacket(Parser parser, unsigned char *p, size_t size){
	char *packet;
	if (!parser) {
		hexDump(p, size);
		return;
	}
	
	packet = parser(p, size);
	
	if (!packet) {
		printf("Unable to parse packet using parser.\n");
		hexDump(p, size);
		return;
	}
		
	printf("%s\n", packet);
	free(packet);
}

void displayPacket(ParserRepository *repo, unsigned char *buffer, size_t size) {
	unsigned char *p = buffer;
	size_t pSize = size;
	Parser parser;
	unsigned char ipProtocol;
	unsigned short srcPort, dstPort;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct ipv6hdr *ip6;
	struct tcphdr *tcp;
	struct udphdr *udp;
	
	eth = (struct ethhdr *)p;
	
	parser = repo->getEthParser(repo);
	parsePacket(parser, p, pSize);
	
	p += sizeof(struct ethhdr);
	pSize -= sizeof(struct ethhdr);
	
	parser = repo->getInternetParser(repo, ntohs(eth->h_proto));
	parsePacket(parser, p, pSize);
	
	switch (ntohs(eth->h_proto)) {
		case ETH_P_IP:
			ip = (struct iphdr *)p;
			ipProtocol = ip->protocol;
			p += sizeof(struct iphdr);
			pSize -= sizeof(struct iphdr);
			break;
		case ETH_P_IPV6:
			ip6 = (struct ipv6hdr *)p;
			if (ipv6_ext_hdr(ip6->nexthdr)) {
				log_info("IPv6 extension header parsing is unsupported.");
				return;
			}
			ipProtocol = ip6->nexthdr;
			p += sizeof(struct ipv6hdr);
			pSize -= sizeof(struct ipv6hdr);
			break;
		default:
			log_info("Unsupported EtherType %04x %d\n", ntohs(eth->h_proto), ntohs(eth->h_proto));
			return;
	}
	
	parser = repo->getTransportParser(repo, ipProtocol);
	parsePacket(parser, p, pSize);
	
	switch (ipProtocol) {
		case IPPROTO_TCP:
			tcp = (struct tcphdr *)p;
			srcPort = ntohs(tcp->source);
			dstPort = ntohs(tcp->dest);
			p += tcp->doff * sizeof(uint32_t);
			pSize -= sizeof(struct tcphdr);
			break;
		case IPPROTO_UDP:
			udp = (struct udphdr *)p;
			srcPort = ntohs(udp->source);
			dstPort = ntohs(udp->dest);
			p += sizeof(struct udphdr);
			pSize -= sizeof(struct udphdr);
			break;
		default:
			return;
	}
	
	parser = repo->getDataParser(repo, ipProtocol, srcPort);
	if (!parser)
		parser = repo->getDataParser(repo, ipProtocol, dstPort);
	
	parsePacket(parser, p, pSize);	
}
 
