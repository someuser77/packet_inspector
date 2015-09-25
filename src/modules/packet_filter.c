#include <string.h>
#include "packet_filter.h"

#ifdef __KERNEL__
#define malloc(x) vmalloc(x)
#define free(x) vfree(x)
#else
#include <stdlib.h>
#endif

static bool filterSrcMac(const struct ethhdr * const packet, void *param) {
	unsigned char mac[ETH_ALEN];
	memcpy(mac, param, ETH_ALEN);
	const unsigned char *srcMac = packet->h_source;
	return memcmp(srcMac, mac, ETH_ALEN) == 0;
}

static bool filterDstMac(const struct ethhdr * const packet, void *param) {
	unsigned char mac[ETH_ALEN];
	memcpy(mac, param, ETH_ALEN);
	const unsigned char *dstMac = packet->h_dest;
	return memcmp(dstMac, mac, ETH_ALEN) == 0;
}

static bool filterSrcIp(const struct iphdr * const packet, void *param) {
	uint32_t ip;
	memcpy(&ip, param, sizeof(uint32_t));
	return packet->saddr == htonl(ip);
}

static bool filterDstIp(const struct iphdr * const packet, void *param) {
	uint32_t ip;
	memcpy(&ip, param, sizeof(uint32_t));
	return packet->daddr == htonl(ip);
}

static bool filterSrcIp6(const struct ipv6hdr * const packet, void *param) {
	unsigned char ip6[IP6_ALEN];
	memcpy(ip6, param, IP6_ALEN);
	return memcmp(packet->saddr.s6_addr, ip6, IP6_ALEN) == 0;
}

static bool filterDstIp6(const struct ipv6hdr * const packet, void *param) {
	unsigned char ip6[IP6_ALEN];
	memcpy(ip6, param, IP6_ALEN);
	return memcmp(packet->daddr.s6_addr, ip6, IP6_ALEN) == 0;
}

static bool filterIpProtocol(const struct iphdr * const packet, void *param) {
	unsigned char protocol;
	memcpy(&protocol, param, sizeof(unsigned char));
	return packet->protocol == protocol;
}

static bool filterTcpSrcPort(const struct tcphdr * const packet, void *param) {
	uint16_t port;
	uint16_t src = ntohs(packet->source);
	memcpy(&port, param, sizeof(uint16_t));
	return port == src;
}

static bool filterTcpDstPort(const struct tcphdr * const packet, void *param) {
	uint16_t port;
	uint16_t dst = ntohs(packet->dest);
	memcpy(&port, param, sizeof(uint16_t));
	return port == dst;
}

static bool filterUdpSrcPort(const struct udphdr * const packet, void *param) {
	uint16_t port;
	uint16_t src = ntohs(packet->source);
	memcpy(&port, param, sizeof(uint16_t));
	return port == src;
}

static bool filterUdpDstPort(const struct udphdr * const packet, void *param) {
	uint16_t port;
	uint16_t dst = ntohs(packet->dest);
	memcpy(&port, param, sizeof(uint16_t));
	return port == dst;
}

#define DEFINE_MATCH(TYPE, HEADER)																														\
static bool match##TYPE(const struct TYPE##PacketFilter * const packetFilter, const HEADER * const packet) {	\
	return packetFilter->matcher(packet, packetFilter->params);																					\
}

DEFINE_MATCH(Eth, struct ethhdr)
DEFINE_MATCH(Ip, struct iphdr)
DEFINE_MATCH(Ip6, struct ipv6hdr)
DEFINE_MATCH(Tcp, struct tcphdr)
DEFINE_MATCH(Udp, struct udphdr)

typedef enum  {PacketFilter_Eth, PacketFilter_Ip, PacketFilter_Ip6, PacketFilter_Tcp, PacketFilter_Udp} PacketFilterType;

static void *create(PacketFilterType packetFilterType) {	
	EthPacketFilter *ethFilter;
	IpPacketFilter *ipFilter;
	Ip6PacketFilter *ip6Filter;
	TcpPacketFilter *tcpFilter;
	UdpPacketFilter *udpFilter;
	
	switch (packetFilterType) {
		case PacketFilter_Eth:
			ethFilter = (struct EthPacketFilter *)malloc(sizeof(struct EthPacketFilter));
			ethFilter->match = matchEth;
			return ethFilter;
		case PacketFilter_Ip:
			ipFilter = (struct IpPacketFilter *)malloc(sizeof(struct IpPacketFilter));
			ipFilter->match = matchIp;
			return ipFilter;
		case PacketFilter_Ip6:
			ip6Filter = (struct Ip6PacketFilter *)malloc(sizeof(struct Ip6PacketFilter));
			ip6Filter->match = matchIp6;
			return ip6Filter;
		case PacketFilter_Tcp:
			tcpFilter = (struct TcpPacketFilter *)malloc(sizeof(struct TcpPacketFilter));
			tcpFilter->match = matchTcp;
			return tcpFilter;
		case PacketFilter_Udp:
			udpFilter = (struct UdpPacketFilter *)malloc(sizeof(struct UdpPacketFilter));
			udpFilter->match = matchUdp;
			return udpFilter;
		default:
			return NULL;
	}
}

static EthPacketFilter *PacketFilter_createEthMacFilter(bool (*filterMac)(const struct ethhdr * const packet, void *mac), const unsigned char const mac[ETH_ALEN]) {
	EthPacketFilter *filter = (EthPacketFilter *)create(PacketFilter_Eth);
	filter->params = malloc(ETH_ALEN);
	memcpy(filter->params, mac, ETH_ALEN);
	filter->matcher = filterMac;
	return filter;
}

EthPacketFilter *PacketFilter_createEthSrcMacFilter(const unsigned char const mac[ETH_ALEN]) {
	return PacketFilter_createEthMacFilter(filterSrcMac, mac);
}

EthPacketFilter *PacketFilter_createEthDstMacFilter(const unsigned char const mac[ETH_ALEN]) {
	return PacketFilter_createEthMacFilter(filterDstMac, mac);
}

static IpPacketFilter *PacketFilter_createIpFilter(bool (*filterIp)(const struct iphdr * const packet, void *ip), uint32_t ip) {
	IpPacketFilter *filter = create(PacketFilter_Ip);
	filter->params = malloc(sizeof(uint32_t));
	*((uint32_t *)filter->params) = ip;
	filter->matcher = filterIp;
	return filter;
}

IpPacketFilter *PacketFilter_createIpSrcIpFilter(uint32_t ip) {
	return PacketFilter_createIpFilter(filterSrcIp, ip);
}

IpPacketFilter *PacketFilter_createIpDstIpFilter(uint32_t ip) {
	return PacketFilter_createIpFilter(filterDstIp, ip);
}

static Ip6PacketFilter *PacketFilter_createIp6Filter(bool (*filterIp6)(const struct ipv6hdr * const packet, void *ip6), const unsigned char const ip6[IP6_ALEN]) {
	Ip6PacketFilter *filter = create(PacketFilter_Ip6);
	filter->params = malloc(IP6_ALEN);
	memcpy(filter->params, ip6, IP6_ALEN);
	filter->matcher = filterIp6;
	return filter;
}

Ip6PacketFilter *PacketFilter_createIp6SrcIpFilter(const unsigned char const ip6[IP6_ALEN]) {
	return PacketFilter_createIp6Filter(filterSrcIp6, ip6);
}

Ip6PacketFilter *PacketFilter_createIp6DstIpFilter(const unsigned char const ip6[IP6_ALEN]) {
	return PacketFilter_createIp6Filter(filterDstIp6, ip6);
}

IpPacketFilter *PacketFilter_createIpProtocolFilter(unsigned char protocol) {
	IpPacketFilter *filter = create(PacketFilter_Ip);
	filter->params = malloc(sizeof(unsigned char));
	memcpy(filter->params, &protocol, sizeof(unsigned char));
	filter->matcher = filterIpProtocol;
	return filter;
}

static TcpPacketFilter *PacketFilter_createTcpPortFilter(bool (*filterPort)(const struct tcphdr * const packet, void *port), uint16_t port) {
	TcpPacketFilter *filter = create(PacketFilter_Tcp);
	filter->params = malloc(sizeof(uint16_t));
	memcpy(filter->params, &port, sizeof(uint16_t));
	filter->matcher = filterPort;
	return filter;
}

TcpPacketFilter *PacketFilter_createTcpSrcPortFilter(uint16_t port) {
	return PacketFilter_createTcpPortFilter(filterTcpSrcPort, port);
}

TcpPacketFilter *PacketFilter_createTcpDstPortFilter(uint16_t port) {
	return PacketFilter_createTcpPortFilter(filterTcpDstPort, port);
}

static UdpPacketFilter *PacketFilter_createUdpPortFilter(bool (*filterPort)(const struct udphdr * const packet, void *port), uint16_t port) {
	UdpPacketFilter *filter = create(PacketFilter_Udp);
	filter->params = malloc(sizeof(uint16_t));
	*((uint16_t *)filter->params) = port;
	filter->matcher = filterPort;
	return filter;
}

UdpPacketFilter *PacketFilter_createUdpSrcPortFilter(uint16_t port) {
	return PacketFilter_createUdpPortFilter(filterUdpSrcPort, port);
}

UdpPacketFilter *PacketFilter_createUdpDstPortFilter(uint16_t port) {
	return PacketFilter_createUdpPortFilter(filterUdpDstPort, port);
}


#ifdef __KERNEL__
#undefine malloc
#undefine free
#endif
