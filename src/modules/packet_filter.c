#ifndef __KERNEL__
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include "../lib/alloc.h"

#include "packet_filter.h"

#ifndef __KERNEL__
static int min(int a, int b) {return a < b ? a : b; }
#endif

static bool filterDeviceName(const char const device[IFNAMSIZ], void *param) {
	char paramDevice[IFNAMSIZ] = {0};
	memcpy(paramDevice, param, IFNAMSIZ);
	return memcmp(device, paramDevice, min(strlen(device), strlen(paramDevice))) == 0;
}

static bool filterEtherType(const struct ethhdr * const packet, void *param) {
	unsigned short etherType;
	memcpy(&etherType, param, sizeof(unsigned short));
	return packet->h_proto == htons(etherType);
}

static bool filterSrcMac(const struct ethhdr * const packet, void *param) {
	unsigned char mac[ETH_ALEN];
	const unsigned char *srcMac = packet->h_source;
	memcpy(mac, param, ETH_ALEN);
	return memcmp(srcMac, mac, ETH_ALEN) == 0;
}

static bool filterDstMac(const struct ethhdr * const packet, void *param) {
	unsigned char mac[ETH_ALEN];
	const unsigned char *dstMac = packet->h_dest;
	memcpy(mac, param, ETH_ALEN);
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

static bool matchDevice(const struct DeviceFilter * const filter, const char const device[IFNAMSIZ]) {
	return filter->matcher(device, filter->params);
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

static char *getDefaultDescription(void) {
	return "No Description Exists.";
}

#define DEFINE_DESCRIPTION_FUNC(NAME, DESC)	\
static char *get##NAME##Description(void) {				\
	return DESC;														\
}

//DEFINE_DESCRIPTION_FUNC(SrcMac, "Src MAC");
//DEFINE_DESCRIPTION_FUNC(DstMac, "Dst MAC");
DEFINE_DESCRIPTION_FUNC(SrcIp, "Src Ip");
DEFINE_DESCRIPTION_FUNC(DstIp, "Dst Ip");
DEFINE_DESCRIPTION_FUNC(Protocol, "Ip Protocol");
DEFINE_DESCRIPTION_FUNC(SrcPort, "Src Port");
DEFINE_DESCRIPTION_FUNC(DstPort, "Dst Port");

typedef enum  {PacketFilter_Device, PacketFilter_Eth, PacketFilter_Ip, PacketFilter_Ip6, PacketFilter_Tcp, PacketFilter_Udp} PacketFilterType;

static void *create(PacketFilterType packetFilterType) {	
	DeviceFilter *deviceFilter;
	EthPacketFilter *ethFilter;
	IpPacketFilter *ipFilter;
	Ip6PacketFilter *ip6Filter;
	TcpPacketFilter *tcpFilter;
	UdpPacketFilter *udpFilter;
	
	switch (packetFilterType) {
		case PacketFilter_Device:
			deviceFilter = (struct DeviceFilter *)alloc(sizeof(struct DeviceFilter));
			deviceFilter->match = matchDevice;
			deviceFilter->description = getDefaultDescription;
			return deviceFilter;
		case PacketFilter_Eth:
			ethFilter = (struct EthPacketFilter *)alloc(sizeof(struct EthPacketFilter));
			ethFilter->match = matchEth;
			ethFilter->description = getDefaultDescription;
			return ethFilter;
		case PacketFilter_Ip:
			ipFilter = (struct IpPacketFilter *)alloc(sizeof(struct IpPacketFilter));
			ipFilter->match = matchIp;
			ipFilter->description = getDefaultDescription;
			return ipFilter;
		case PacketFilter_Ip6:
			ip6Filter = (struct Ip6PacketFilter *)alloc(sizeof(struct Ip6PacketFilter));
			ip6Filter->match = matchIp6;
			ip6Filter->description = getDefaultDescription;
			return ip6Filter;
		case PacketFilter_Tcp:
			tcpFilter = (struct TcpPacketFilter *)alloc(sizeof(struct TcpPacketFilter));
			tcpFilter->match = matchTcp;
			tcpFilter->description = getDefaultDescription;
			return tcpFilter;
		case PacketFilter_Udp:
			udpFilter = (struct UdpPacketFilter *)alloc(sizeof(struct UdpPacketFilter));
			udpFilter->match = matchUdp;
			udpFilter->description = getDefaultDescription;
			return udpFilter;
		default:
			return NULL;
	}
}

DeviceFilter *PacketFilter_createDeviceNameFilter(const char const device[IFNAMSIZ]) {
	DeviceFilter *filter = (DeviceFilter *)create(PacketFilter_Device);
	filter->params = alloc(IFNAMSIZ);
	memcpy(filter->params, device, IFNAMSIZ);
	filter->matcher = filterDeviceName;
	return filter;
}

static EthPacketFilter *PacketFilter_createEthMacFilter(bool (*filterMac)(const struct ethhdr * const packet, void *mac), const unsigned char const mac[ETH_ALEN]) {
	EthPacketFilter *filter = (EthPacketFilter *)create(PacketFilter_Eth);
	filter->params = alloc(ETH_ALEN);
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

EthPacketFilter *PacketFilter_createEthEtherTypeFilter(unsigned short etherType) {
	EthPacketFilter *filter = (EthPacketFilter *)create(PacketFilter_Eth);
	filter->params = alloc(sizeof(unsigned short));
	*((unsigned short *)filter->params) = etherType;
	filter->matcher = filterEtherType;
	return filter;
}

static IpPacketFilter *PacketFilter_createIpFilter(bool (*filterIp)(const struct iphdr * const packet, void *ip), char *(*getDescription)(void), uint32_t ip) {
	IpPacketFilter *filter = create(PacketFilter_Ip);
	filter->params = alloc(sizeof(uint32_t));
	*((uint32_t *)filter->params) = ip;
	filter->matcher = filterIp;
	filter->description = getDescription;
	return filter;
}

IpPacketFilter *PacketFilter_createIpSrcIpFilter(uint32_t ip) {
	return PacketFilter_createIpFilter(filterSrcIp, getSrcIpDescription, ip);
}

IpPacketFilter *PacketFilter_createIpDstIpFilter(uint32_t ip) {
	return PacketFilter_createIpFilter(filterDstIp, getDstIpDescription, ip);
}

static Ip6PacketFilter *PacketFilter_createIp6Filter(bool (*filterIp6)(const struct ipv6hdr * const packet, void *ip6), const unsigned char const ip6[IP6_ALEN]) {
	Ip6PacketFilter *filter = create(PacketFilter_Ip6);
	filter->params = alloc(IP6_ALEN);
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
	filter->params = alloc(sizeof(unsigned char));
	memcpy(filter->params, &protocol, sizeof(unsigned char));
	filter->matcher = filterIpProtocol;
	filter->description = getProtocolDescription;
	return filter;
}

static TcpPacketFilter *PacketFilter_createTcpPortFilter(bool (*filterPort)(const struct tcphdr * const packet, void *port), char *(*getDescription)(void), uint16_t port) {
	TcpPacketFilter *filter = create(PacketFilter_Tcp);
	filter->params = alloc(sizeof(uint16_t));
	memcpy(filter->params, &port, sizeof(uint16_t));
	filter->matcher = filterPort;
	filter->description = getDescription;
	return filter;
}

TcpPacketFilter *PacketFilter_createTcpSrcPortFilter(uint16_t port) {
	return PacketFilter_createTcpPortFilter(filterTcpSrcPort, getSrcPortDescription, port);
}

TcpPacketFilter *PacketFilter_createTcpDstPortFilter(uint16_t port) {
	return PacketFilter_createTcpPortFilter(filterTcpDstPort, getDstPortDescription, port);
}

static UdpPacketFilter *PacketFilter_createUdpPortFilter(bool (*filterPort)(const struct udphdr * const packet, void *port), char *(*getDescription)(void), uint16_t port) {
	UdpPacketFilter *filter = create(PacketFilter_Udp);
	filter->params = alloc(sizeof(uint16_t));
	*((uint16_t *)filter->params) = port;
	filter->matcher = filterPort;
	filter->description = getDescription;
	return filter;
}

UdpPacketFilter *PacketFilter_createUdpSrcPortFilter(uint16_t port) {
	return PacketFilter_createUdpPortFilter(filterUdpSrcPort, getSrcPortDescription, port);
}

UdpPacketFilter *PacketFilter_createUdpDstPortFilter(uint16_t port) {
	return PacketFilter_createUdpPortFilter(filterUdpDstPort, getDstPortDescription, port);
}