#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "lib/utils.h"
#include "lib/filter_client.h"
#include "lib/parser.h"
#include "lib/parser_repository.h"

static volatile bool enabled = true;

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
	return ( (nexthdr == NEXTHDR_HOP)	||
	(nexthdr == NEXTHDR_ROUTING)   		||
	(nexthdr == NEXTHDR_FRAGMENT)  	||
	(nexthdr == NEXTHDR_AUTH)      		||
	(nexthdr == NEXTHDR_NONE)      		||
	(nexthdr == NEXTHDR_DEST) );
}

void hexDump(unsigned char *buffer, size_t size) {
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

void parsePacket(Parser parser, unsigned char *p, size_t size){
	char *packet;
	if (!parser) {
		hexDump(p, size);
		return;
	}
	
	packet = parser(p, size);
	printf("%s\n", packet);
	free(packet);
}

void displayPacket(ParserRepository *repo, unsigned char *buffer, size_t size) {
	char *packet;
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
			ipProtocol = ((struct iphdr *)p)->protocol;
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
			srcPort = tcp->source;
			dstPort = tcp->dest;		
			p += sizeof(struct tcphdr);
			pSize -= sizeof(struct tcphdr);
			break;
		case IPPROTO_UDP:
			udp = (struct udphdr *)p;
			srcPort = udp->source;
			dstPort = udp->dest;
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

int main(int __attribute__((unused)) argc, char __attribute__((unused)) *argv[]) {
	unsigned char *buffer;
	char *description;
	size_t size;
	FilterClient *filterClient;
	DirectionalFilterOptions *options = DirectionalFilterOptions_Create();
	FilterOptions *incoming, *outgoing;
	ParserRepository *repository = ParserRepository_Create();
	
	printf("PID: %d\n", getpid());
	incoming = FilterOptions_Create();
	outgoing = FilterOptions_Create();
	
	unsigned char srcMac[ETH_ALEN] = {0x6, 0x5, 0x4, 0x3, 0x2, 0x1};
	unsigned char dstMac[ETH_ALEN] = {0x00, 0x22, 0xfa, 0xe8, 0xc2, 0x42};
	
	uint32_t srcIp, dstIp;
	unsigned char srcIp6[IP6_ALEN] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
	unsigned char dstIp6[IP6_ALEN] = { 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1 };	
	
	inet_pton(AF_INET, "10.0.0.5", &srcIp);
	inet_pton(AF_INET, "10.0.0.5", &dstIp);
	
	incoming->setDevice(incoming, "wlan0", 5);
	outgoing->setDevice(outgoing, "wlan0", 5);
	
	incoming->setProtocol(incoming, IPPROTO_TCP);
	outgoing->setProtocol(outgoing, IPPROTO_TCP);
	
	incoming->setEtherType(incoming, ETH_P_IP);
	outgoing->setEtherType(outgoing, ETH_P_IP);
	
	outgoing->setDstPort(outgoing, 80);
	
	incoming->setDstIp(incoming, ntohl(dstIp));
	outgoing->setSrcIp(outgoing, ntohl(srcIp));
	
	//filterOptions->setSrcPort(filterOptions, 80);
	//filterOptions->setDstPort(filterOptions, 80);
	
	description = incoming->description(incoming);
	printf("Incoming: %s", description);
	free(description);
	
	description = outgoing->description(outgoing);
	printf("Outgoing: %s", description);
	free(description);
	
	options->setIncomingFilterOptions(options, incoming);
	options->setOutgoingFilterOptions(options, outgoing);
	
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
