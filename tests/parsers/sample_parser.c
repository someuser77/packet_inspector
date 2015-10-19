#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <linux/in.h>
#include <linux/if_ether.h>

#include "parser.h" 
#include "parser_repository.h"

static char* ParseEthermetHeader(const unsigned char * const buffer, size_t size) {
	return "ETH";
}

static char* ParseIpHeader(const unsigned char * const buffer, size_t size) {
	return "IP";
}

static char* ParseIp6Header(const unsigned char * const buffer, size_t size) {
	return "IPv6";
}

static char* ParseTcpHeader(const unsigned char * const buffer, size_t size) {
	return "TCP";
}

static char* ParseUdpHeader(const unsigned char * const buffer, size_t size) {
	return "UDP";
}

static char* ParseHttpHeader(const unsigned char * const buffer, size_t size) {
	return "HTTP";
}

static char* ParseFtpHeader(const unsigned char * const buffer, size_t size) {
	return "FTP";
}



bool InitParser(ParserRepository *repo) {
	repo->registerEthParser(repo, ParseEthermetHeader);
	repo->registerInternetParser(repo, ETH_P_IP, ParseIpHeader);
	repo->registerInternetParser(repo, ETH_P_IPV6, ParseIp6Header);
	repo->registerTransportParser(repo, IPPROTO_TCP, ParseTcpHeader);
	repo->registerTransportParser(repo, IPPROTO_UDP, ParseUdpHeader);
	repo->registerDataParser(repo, IPPROTO_TCP, 80, ParseHttpHeader);
	repo->registerDataParser(repo, IPPROTO_TCP, 21, ParseFtpHeader);
	return true;
}
