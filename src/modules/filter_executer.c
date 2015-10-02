#include "utils.h"
#include <linux/vmalloc.h>
#include <linux/list.h>
#include <net/ipv6.h>

#include "filter_executer.h"
#include "packet_filter.h"
#include "utils.h"

#define PACKET_FILTER_TYPE_ETH					1
#define PACKET_FILTER_TYPE_IP						2
#define PACKET_FILTER_TYPE_IP6						3
#define PACKET_FILTER_TYPE_UDP					4
#define PACKET_FILTER_TYPE_TCP						5
#define NUMBER_OF_PACKET_FILTER_TYPES		PACKET_FILTER_TYPE_TCP


#define NUM_OF_FILTER_TYPES 

#define DEFINE_FILTER_LIST_TYPE(Type) typedef struct Type##FilterList {	\
	struct list_head filters;																				\
	Type##PacketFilter *filter;																			\
} Type##FilterList

DEFINE_FILTER_LIST_TYPE(Eth);
DEFINE_FILTER_LIST_TYPE(Ip);
DEFINE_FILTER_LIST_TYPE(Ip6);
DEFINE_FILTER_LIST_TYPE(Tcp);
DEFINE_FILTER_LIST_TYPE(Udp);
	

typedef struct FilterExecuterImpl {
	struct list_head eth;
	struct list_head ip;
	struct list_head ip6;
	struct list_head tcp;
	struct list_head udp;
	int totalFilters;
} FilterExecuterImpl;

static inline FilterExecuterImpl *impl(FilterExecuter *self) {
	return (FilterExecuterImpl *)self->impl;
}

static inline struct list_head * ethFilters(FilterExecuter *self) {
	return &impl(self)->eth;
}

static inline struct list_head * ipFilters(FilterExecuter *self) {
	return &impl(self)->ip;
}

static inline struct list_head * ip6Filters(FilterExecuter *self) {
	return &impl(self)->ip6;
}

static inline struct list_head * tcpFilters(FilterExecuter *self) {
	return &impl(self)->tcp;
}

static inline struct list_head * udpFilters(FilterExecuter *self) {
	return &impl(self)->udp;
}

static void destroy(FilterExecuter *self) {
	vfree(self->impl);
	vfree(self);
}

int getTotalFilters(struct FilterExecuter *self) {
	return impl(self)->totalFilters;
}

static struct ipv6hdr *getIp6Header(struct sk_buff *skb) {
	int offset;
	struct ipv6hdr _ipv6h, *ip6;

	offset = skb_network_offset(skb);	
	ip6 = skb_header_pointer(skb, offset, sizeof(_ipv6h), &_ipv6h);
	return ip6;
}

static bool getIp6Protocol(struct sk_buff *skb, unsigned char *protocol) {
	__be16 frag_off;
	u8 nexthdr;
	int offset;
	struct ipv6hdr _ipv6h, *ip6;

	offset = skb_network_offset(skb);	
	ip6 = skb_header_pointer(skb, offset, sizeof(_ipv6h), &_ipv6h);
	
	nexthdr = ip6->nexthdr;
	offset += sizeof(_ipv6h);
	offset = ipv6_skip_exthdr(skb, offset, &nexthdr, &frag_off);
	if (offset < 0)
		return false;
	
	*protocol = nexthdr;
	return true;
}

#define ITERATE_FILTERS(pos, head, member, param) do {	\
list_for_each_entry(pos, head, member) {							\
				if (pos->filter->match(pos->filter, param)) {		\
					matchedFilters++;											\
				} else {																\
					return false;														\
				}																			\
			} 																				\
	} while (0)																						

bool matchAll(struct FilterExecuter *self, struct sk_buff *skb) {
	struct ethhdr *eth;
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct iphdr *ip;
	struct ipv6hdr *ip6;
	int matchedFilters = 0;
	
	struct EthFilterList *ethFilter = NULL;
	struct IpFilterList *ipFilter = NULL;
	struct Ip6FilterList *ip6Filter = NULL;
	struct TcpFilterList *tcpFilter = NULL;
	struct UdpFilterList *udpFilter = NULL;
	
	unsigned char ipProtocol;
	
	eth = eth_hdr(skb);
	if (eth == NULL) {
		klog_warn("SKB ETH header was null.");
		return false;
	}
	
	ITERATE_FILTERS(ethFilter, ethFilters(self), filters, eth);
	
	switch (ntohs(eth->h_proto)) {
		case ETH_P_IP:
			if ((ip = ip_hdr(skb)) == NULL){
				klog_error("Protocol was IP but header was null.");
				return false;
			}
			ITERATE_FILTERS(ipFilter, ipFilters(self), filters, ip);
			ipProtocol = ip->protocol;
			break;
		case ETH_P_IPV6:
			if ((ip6 = getIp6Header(skb)) == NULL) {
				klog_error("Protocol was IPv6 but header was null.");
				return false;
			}
			ITERATE_FILTERS(ip6Filter, ip6Filters(self), filters, ip6);
			if (!getIp6Protocol(skb, &ipProtocol)) {
				klog_error("Error extracting protocol from IPv6 packet.");
				return false;
			}
			break;
		default:
			// only IP and IPv6 is currently supported.
			return false;
	}
	
	switch (ipProtocol) {
		case IPPROTO_TCP:
			if ((tcp = (struct tcphdr *)skb_transport_header(skb)) == NULL) {
				klog_error("Protocol was TCP but header was null.");
				return false;
			}
			ITERATE_FILTERS(tcpFilter, tcpFilters(self), filters, tcp);
			break;
		case IPPROTO_UDP:
			if ((udp = (struct udphdr *)skb_transport_header(skb)) == NULL) {
				klog_error("Protocol was UDP but header was null.");
				return false;
			}
			ITERATE_FILTERS(udpFilter, udpFilters(self), filters, udp);
			break;
		default:
			return false;
	}
	
	//unsigned char *data = skb_mac_header(skb);
	//klog_info("%02x:%02x:%02x:%02x:%02x:%02x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	
	//klog_info("Inside Match All... Packet Protocol was: %04X", ntohs(skb->protocol));
	
	
	return matchedFilters == getTotalFilters(self);
}

FilterExecuter *FilterExecuter_Create(FilterOptions *filterOptions) {
	FilterExecuter *result = (FilterExecuter *)vzalloc(sizeof(FilterExecuter));
	FilterExecuterImpl *impl = (FilterExecuterImpl *)vzalloc(sizeof(FilterExecuterImpl));
	impl->totalFilters = 0;
	
	INIT_LIST_HEAD(&impl->eth);
	INIT_LIST_HEAD(&impl->ip);
	INIT_LIST_HEAD(&impl->ip6);
	INIT_LIST_HEAD(&impl->tcp);
	INIT_LIST_HEAD(&impl->udp);
	
	
	if (filterOptions->isSrcMacSet(filterOptions)) {
		unsigned char mac[ETH_ALEN];
		EthFilterList *ethFilter = (EthFilterList *)vmalloc(sizeof(EthFilterList));
		filterOptions->getSrcMac(filterOptions, mac);
		ethFilter->filter = PacketFilter_createEthSrcMacFilter(mac);
		list_add(&ethFilter->filters, &impl->eth);
		impl->totalFilters++;
	}
	
	if (filterOptions->isDstMacSet(filterOptions)) {
		unsigned char mac[ETH_ALEN];
		EthFilterList *ethFilter = (EthFilterList *)vmalloc(sizeof(EthFilterList));
		filterOptions->getDstMac(filterOptions, mac);
		ethFilter->filter = PacketFilter_createEthDstMacFilter(mac);
		list_add(&ethFilter->filters, &impl->eth);
		impl->totalFilters++;
	}
	
	if (filterOptions->isSrcIpSet(filterOptions)) {
		impl->totalFilters++;
	}
	
	if (filterOptions->isDstIpSet(filterOptions)) {
		impl->totalFilters++;
	}
	
	if (filterOptions->isSrcIp6Set(filterOptions)) {
		impl->totalFilters++;
	}
	
	if (filterOptions->isDstIp6Set(filterOptions)) {
		impl->totalFilters++;
	}
	
	if (filterOptions->isDeviceSet(filterOptions)) {
		impl->totalFilters++;
	}
	
	if (filterOptions->isProtocolSet(filterOptions)) {
		impl->totalFilters++;
	}
	
	if (filterOptions->isSrcPortSet(filterOptions)) {
		impl->totalFilters++;
	}
	
	if (filterOptions->isDstPortSet(filterOptions)) {
		impl->totalFilters++;
	}
	
	result->matchAll = matchAll;
	result->impl = impl;
	result->destroy = destroy;
	return result;
}
