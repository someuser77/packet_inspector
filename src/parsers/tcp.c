#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include "parser.h" 
#include "parser_repository.h"
#include "asprintf.h"


static char* parseTcpHeader(const unsigned char * const buffer, size_t size) {
	if (size < sizeof(struct tcphdr)) {
		return "Unable to parse TCP header. Header size was too small.";
	}
	
	struct tcphdr *tcp = (struct tcphdr *)buffer;
	char *result = "";

	if (asprintf(&result, "[TCP Header]\n\t"
		" Source: %u"
		" Destination: %u"
		" SEQ #: %u"
		" ACK #: %u"
		" Data Offset: %u"
		" CWR: %u"
		" URG: %u"
		" ACK: %u"
		" PSH: %u"
		" RST: %u"
		" SYN: %u"
		" FIN: %u"
		" Window: %u"
		" Checksum: %u\n",
		ntohs(tcp->source),
		ntohs(tcp->dest),
		ntohl(tcp->seq),
		ntohl(tcp->ack_seq),
		tcp->doff,
		tcp->cwr,
		tcp->urg,
		tcp->ack,
		tcp->psh,
		tcp->rst,
		tcp->syn,
		tcp->fin,
		tcp->window,
		tcp->check
		) == -1) {
			return "Error allocating memory for output of tcphdr.\n";
	}
	return result;
}

bool InitParser(ParserRepository *repo) {
	repo->registerTransportParser(repo, IPPROTO_TCP, parseTcpHeader);
	return true;
}