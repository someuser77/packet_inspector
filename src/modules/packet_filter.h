#ifndef _PACKET_FILETER_H_
#define _PACKET_FILETER_H_

#include <stdbool.h>

#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#ifdef __KERNEL__
#include <linux/list.h>
#endif

#ifndef IP6_ALEN
#define IP6_ALEN 16
#endif

typedef struct DeviceFilter {
	void *params;
	bool (*match)(const struct DeviceFilter * const deviceFilter, const char const device[IFNAMSIZ]);
	bool (*matcher)(const char * const device, void *params);
	void (*destroy)(struct DeviceFilter *);
	char *(*description)(void);
} DeviceFilter;

#define DEFINE_PACKET_FILTER(Type, Header) typedef struct Type##PacketFilter { \
	void *params; \
	bool (*match)(const struct Type##PacketFilter * const packetFilter, const struct Header * const packet); \
	bool (*matcher)(const struct Header * const packet, void *params); \
	void (*destroy)(struct Type##PacketFilter *); \
	char *(*description)(void); \
} Type##PacketFilter;

DEFINE_PACKET_FILTER(Eth, ethhdr);
DEFINE_PACKET_FILTER(Ip, iphdr);
DEFINE_PACKET_FILTER(Ip6, ipv6hdr);
DEFINE_PACKET_FILTER(Tcp, tcphdr);
DEFINE_PACKET_FILTER(Udp, udphdr);

DeviceFilter *PacketFilter_createDeviceNameFilter(const char const device[IFNAMSIZ]);

EthPacketFilter *PacketFilter_createEthSrcMacFilter(const unsigned char const mac[ETH_ALEN]);
EthPacketFilter *PacketFilter_createEthDstMacFilter(const unsigned char const mac[ETH_ALEN]);

EthPacketFilter *PacketFilter_createEthEtherTypeFilter(unsigned short etherType);

IpPacketFilter *PacketFilter_createIpSrcIpFilter(uint32_t ip);
IpPacketFilter *PacketFilter_createIpDstIpFilter(uint32_t ip);

Ip6PacketFilter *PacketFilter_createIp6SrcIpFilter(const unsigned char const Ip6[IP6_ALEN]);
Ip6PacketFilter *PacketFilter_createIp6DstIpFilter(const unsigned char const Ip6[IP6_ALEN]);

IpPacketFilter *PacketFilter_createIpProtocolFilter(unsigned char protocol);
Ip6PacketFilter *PacketFilter_createIp6ProtocolFilter(unsigned char protocol);

TcpPacketFilter *PacketFilter_createTcpSrcPortFilter(uint16_t port);
TcpPacketFilter *PacketFilter_createTcpDstPortFilter(uint16_t port);

UdpPacketFilter *PacketFilter_createUdpSrcPortFilter(uint16_t port);
UdpPacketFilter *PacketFilter_createUdpDstPortFilter(uint16_t port);

#endif
