#ifndef _PACKET_FILETER_H_
#define _PACKET_FILETER_H_

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#ifndef IP6_ALEN
#define IP6_ALEN 16
#endif
/*
#define DEFINE_PACKET_FILTER(TYPE, HEADER) 																											\
typedef struct TYPE##PacketFilter {																																		\
	void *params;																																										\
	bool (*match)(const struct TYPE##PacketFilter * const packetFilter, const struct HEADER * const packet);		\
	bool (*matcher)(const HEADER * const packet, void *params);																	\
	void (*destroy)(TYPE##PacketFilter);																																\
} TYPE##PacketFilter

DEFINE_PACKET_FILTER(Eth, ethhdr);
DEFINE_PACKET_FILTER(Ip, iphdr);
DEFINE_PACKET_FILTER(Ip6, ipv6hdr);
DEFINE_PACKET_FILTER(Tcp, tcphdr);
DEFINE_PACKET_FILTER(Udp, udphdr);
*/

typedef struct EthPacketFilter {
	void *params;
	bool (*match)(const struct EthPacketFilter * const packetFilter, const struct ethhdr * const packet);
	bool (*matcher)(const struct ethhdr * const packet, void *params);
	void (*destroy)(struct EthPacketFilter *);
} EthPacketFilter;

typedef struct IpPacketFilter {
	void *params;
	bool (*match)(const struct IpPacketFilter * const packetFilter, const struct iphdr * const packet);
	bool (*matcher)(const struct iphdr * const packet, void *params);
	void (*destroy)(struct IpPacketFilter *);
} IpPacketFilter;

typedef struct Ip6PacketFilter {
	void *params;
	bool (*match)(const struct Ip6PacketFilter * const packetFilter, const struct ipv6hdr * const packet);
	bool (*matcher)(const struct ipv6hdr * const packet, void *params);
	void (*destroy)(struct Ip6PacketFilter *);
} Ip6PacketFilter;

typedef struct TcpPacketFilter {
	void *params;
	bool (*match)(const struct TcpPacketFilter * const packetFilter, const struct tcphdr * const packet);
	bool (*matcher)(const struct tcphdr * const packet, void *params);
	void (*destroy)(struct TcpPacketFilter *);
} TcpPacketFilter;

typedef struct UdpPacketFilter {
	void *params;
	bool (*match)(const struct UdpPacketFilter * const packetFilter, const struct udphdr * const packet);
	bool (*matcher)(const struct udphdr * const packet, void *params);
	void (*destroy)(struct UdpPacketFilter *);
} UdpPacketFilter;

EthPacketFilter *PacketFilter_createEthSrcMacFilter(const unsigned char const mac[ETH_ALEN]);
EthPacketFilter *PacketFilter_createEthDstMacFilter(const unsigned char const mac[ETH_ALEN]);

EthPacketFilter *PacketFilter_createEthEthTypeFilter(unsigned short ethType);

IpPacketFilter *PacketFilter_createIpIpSrcIpFilter(uint32_t ip);
IpPacketFilter *PacketFilter_createIpIpDstIpFilter(uint32_t ip);

Ip6PacketFilter *PacketFilter_createIp6SrcIp6Filter(const unsigned char const Ip6[IP6_ALEN]);
Ip6PacketFilter *PacketFilter_createIp6DstIp6Filter(const unsigned char const Ip6[IP6_ALEN]);

IpPacketFilter *PacketFilter_createIpProtocolFilter(unsigned char protocol);
Ip6PacketFilter *PacketFilter_createIp6ProtocolFilter(unsigned char protocol);

TcpPacketFilter *PacketFilter_createTcpSrcPortFilter(uint16_t port);
TcpPacketFilter *PacketFilter_createTcpDstPortFilter(uint16_t port);

UdpPacketFilter *PacketFilter_createUdpSrcPortFilter(uint16_t port);
UdpPacketFilter *PacketFilter_createUdpDstPortFilter(uint16_t port);

#endif
