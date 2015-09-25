//#include <linux/in.h>
#include <arpa/inet.h>
//#include <linux/socket.h> // for AF_INET6
#include "../minunit.h"
#include "packet_filter.h"

// sample captue from https://www.cloudshark.org/captures/0012f52602a3 (Frame 4)
const unsigned char tcp_ip_packet[] = { 
	0x00, 0x26, 0x62, 0x2f, 0x47, 0x87, 0x00, 0x1d, 
	0x60, 0xb3, 0x01, 0x84, 0x08, 0x00, 0x45, 0x00, 
	0x00, 0xba, 0xcb, 0x5d, 0x40, 0x00, 0x40, 0x06, 
	0x28, 0x64, 0xc0, 0xa8, 0x01, 0x8c, 0xae, 0x8f, 
	0xd5, 0xb8, 0xe1, 0x4e, 0x00, 0x50, 0x8e, 0x50, 
	0x19, 0x02, 0xc7, 0x52, 0x9d, 0x89, 0x80, 0x18, 
	0x00, 0x2e, 0x47, 0x29, 0x00, 0x00, 0x01, 0x01, 
	0x08, 0x0a, 0x00, 0x21, 0xd2, 0x5f, 0x31, 0xc7, 
	0xba, 0x48, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x69, 
	0x6d, 0x61, 0x67, 0x65, 0x73, 0x2f, 0x6c, 0x61, 
	0x79, 0x6f, 0x75, 0x74, 0x2f, 0x6c, 0x6f, 0x67, 
	0x6f, 0x2e, 0x70, 0x6e, 0x67, 0x20, 0x48, 0x54, 
	0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, 0x0d, 0x0a, 
	0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 
	0x6e, 0x74, 0x3a, 0x20, 0x57, 0x67, 0x65, 0x74, 
	0x2f, 0x31, 0x2e, 0x31, 0x32, 0x20, 0x28, 0x6c, 
	0x69, 0x6e, 0x75, 0x78, 0x2d, 0x67, 0x6e, 0x75, 
	0x29, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 
	0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 
	0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x70, 0x61, 
	0x63, 0x6b, 0x65, 0x74, 0x6c, 0x69, 0x66, 0x65, 
	0x2e, 0x6e, 0x65, 0x74, 0x0d, 0x0a, 0x43, 0x6f, 
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 
	0x3a, 0x20, 0x4b, 0x65, 0x65, 0x70, 0x2d, 0x41, 
	0x6c, 0x69, 0x76, 0x65, 0x0d, 0x0a, 0x0d, 0x0a
};

// sample capture from https://www.cloudshark.org/captures/91745cbe14d1 (Frame 2)
const unsigned char udp_ip6_packet[] = {
	0x00, 0x50, 0x56, 0x87, 0x06, 0xb6, 0x54, 0x75,
	0xd0, 0xc9, 0x0b, 0x81, 0x86, 0xdd, 0x60, 0x00,
	0x00, 0x00, 0x00, 0x83, 0x11, 0x3f, 0x20, 0x01,
	0x04, 0x70, 0xe5, 0xbf, 0x10, 0x96, 0x00, 0x02,
	0x00, 0x99, 0x00, 0xc1, 0x00, 0x10, 0x20, 0x01,
	0x04, 0x70, 0xe5, 0xbf, 0x10, 0x01, 0x1c, 0xc7,
	0x73, 0xff, 0x65, 0xf5, 0xa2, 0xf7, 0x00, 0xa1, 
	0xb4, 0xd1, 0x00, 0x83, 0x45, 0x57, 0x30, 0x79,
	0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x29, 
	0xcd, 0xb1, 0x7a, 0x02, 0x03, 0x00, 0xff, 0xcf,
	0x04, 0x01, 0x00, 0x02, 0x01, 0x03, 0x04, 0x26, 
	0x30, 0x24, 0x04, 0x14, 0x80, 0x00, 0x4f, 0x4d,
	0xb1, 0xaa, 0xdc, 0xad, 0xbc, 0x89, 0xaf, 0xfa, 
	0x11, 0x8d, 0xbd, 0x53, 0x82, 0x4c, 0x6b, 0x05,
	0x02, 0x01, 0x03, 0x02, 0x03, 0x01, 0x0a, 0x1d, 
	0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x30, 0x39,
	0x04, 0x14, 0x80, 0x00, 0x4f, 0x4d, 0xb1, 0xaa,
	0xdc, 0xad, 0xbc, 0x89, 0xaf, 0xfa, 0x11, 0x8d,
	0xbd, 0x53, 0x82, 0x4c, 0x6b, 0x05, 0x04, 0x00, 
	0xa8, 0x1f, 0x02, 0x04, 0x60, 0xba, 0x10, 0xf6,
	0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x11,
	0x30, 0x0f, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x06,
	0x03, 0x0f, 0x01, 0x01, 0x04, 0x00, 0x41, 0x01, 
	0x04
};

static inline struct ethhdr *eth_header(const void *packet) {
	return (struct ethhdr *)packet;
}

static inline struct iphdr *ip_header(const void *packet) {
	return (struct iphdr *)(packet + sizeof(struct ethhdr));
}

static inline struct ipv6hdr *ip6_header(const void *packet) {
	return (struct ipv6hdr *)(packet + sizeof(struct ethhdr));
}

static inline struct tcphdr *tcp_ip_header(const void *packet) {
	return (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
}

static inline struct udphdr *udp_ip6_header(const void *packet) {
	return (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
}

char *test_PacketFilter_FilterSrcMac() {
	const unsigned char srcMac[ETH_ALEN] = {0x00, 0x1d, 0x60, 0xb3, 0x01, 0x84};
	EthPacketFilter *filter = PacketFilter_createEthSrcMacFilter(srcMac);
	mu_assert(filter->match(filter, eth_header(tcp_ip_packet)), "Source MAC did not match TCP packet.");
	return NULL;
}

char *test_PacketFilter_FilterDstMac() {
	const unsigned char dstMac[ETH_ALEN] = {0x00, 0x26, 0x62, 0x2f, 0x47, 0x87};
	EthPacketFilter *filter = PacketFilter_createEthDstMacFilter(dstMac);
	mu_assert(filter->match(filter, eth_header(tcp_ip_packet)), "Destination MAC did not match TCP packet.");
	return NULL;
}

char *test_PacketFilter_FilterIpProtocol() {
	IpPacketFilter *filter = PacketFilter_createIpProtocolFilter(IPPROTO_TCP);
	mu_assert(filter->match(filter, ip_header(tcp_ip_packet)), "Protocol did not match TCP packet.");
	return NULL;
}

char *test_PacketFilter_FilterSrcIp() {
	uint32_t ip;
	inet_pton(AF_INET, "192.168.1.140", &ip);
	IpPacketFilter *filter = PacketFilter_createIpSrcIpFilter(ntohl(ip));
	mu_assert(filter->match(filter, ip_header(tcp_ip_packet)), "Source IP did not match TCP packet.");
	return NULL;
}

char *test_PacketFilter_FilterDstIp() {
	uint32_t ip;
	inet_pton(AF_INET, "174.143.213.184", &ip);
	IpPacketFilter *filter = PacketFilter_createIpDstIpFilter(ntohl(ip));
	mu_assert(filter->match(filter, ip_header(tcp_ip_packet)), "Destination IP did not match TCP packet.");
	return NULL;
}

char *test_PacketFilter_FilterSrcIp6() {
	const unsigned char const ip6[IP6_ALEN];
	inet_pton(AF_INET6, "2001:470:e5bf:1096:2:99:c1:10", &ip6);
	Ip6PacketFilter *filter = PacketFilter_createIp6SrcIpFilter(ip6);
	mu_assert(filter->match(filter, ip6_header(udp_ip6_packet)), "Source IPv6 did not match UDP packet.");
	return NULL;
}

char *test_PacketFilter_FilterDstIp6() {
	const unsigned char const ip6[IP6_ALEN];
	inet_pton(AF_INET6, "2001:470:e5bf:1001:1cc7:73ff:65f5:a2f7", &ip6);
	Ip6PacketFilter *filter = PacketFilter_createIp6DstIpFilter(ip6);
	mu_assert(filter->match(filter, ip6_header(udp_ip6_packet)), "Destination IPv6 did not match UDP packet.");
	return NULL;
}

char *test_PacketFilter_FilterTcpSrcPort() {
	uint16_t port = 57678;
	TcpPacketFilter *filter = PacketFilter_createTcpSrcPortFilter(port);
	mu_assert(filter->match(filter, tcp_ip_header(tcp_ip_packet)), "Source port did not match TCP packet.");
	return NULL;
}

char *test_PacketFilter_FilterTcpDstPort() {
	uint16_t port = 80;
	TcpPacketFilter	*filter = PacketFilter_createTcpDstPortFilter(port);
	mu_assert(filter->match(filter, tcp_ip_header(tcp_ip_packet)), "Destination port did not match TCP packet.");
	return NULL;
}

char *test_PacketFilter_FilterUdpSrcPort() {
	uint16_t port = 161;
	UdpPacketFilter *filter = PacketFilter_createUdpSrcPortFilter(port);
	mu_assert(filter->match(filter, udp_ip6_header(udp_ip6_packet)), "Source port did not match UDP packet.");
	return NULL;
}

char *test_PacketFilter_FilterUdpDstPort() {
	uint16_t port = 46289;
	UdpPacketFilter	*filter = PacketFilter_createUdpDstPortFilter(port);
	mu_assert(filter->match(filter, udp_ip6_header(udp_ip6_packet)), "Destination port did not match UDP packet.");
	return NULL;
}



char *all_tests() {
	mu_suite_start();
	mu_run_test(test_PacketFilter_FilterSrcMac);
	mu_run_test(test_PacketFilter_FilterDstMac);
	mu_run_test(test_PacketFilter_FilterIpProtocol);
	mu_run_test(test_PacketFilter_FilterSrcIp);
	mu_run_test(test_PacketFilter_FilterDstIp);
	mu_run_test(test_PacketFilter_FilterSrcIp6);
	mu_run_test(test_PacketFilter_FilterDstIp6);
	mu_run_test(test_PacketFilter_FilterTcpSrcPort);
	mu_run_test(test_PacketFilter_FilterTcpDstPort);
	mu_run_test(test_PacketFilter_FilterUdpSrcPort);
	mu_run_test(test_PacketFilter_FilterUdpDstPort);
	return NULL;
}

RUN_TESTS(all_tests);