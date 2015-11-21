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
	int debugPrint;
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

static bool getIp6Protocol(struct sk_buff *skb, unsigned char *protocol) __attribute__((unused));
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

static struct ethhdr *getEthhdrByOffset(struct sk_buff *skb, size_t offset) {
	return (struct ethhdr *)(skb->data + offset);
}

static struct ethhdr *getEthhdrByFunction(struct sk_buff *skb, __attribute__((unused)) size_t offset) {
	return eth_hdr(skb);
}

static struct iphdr *getIphdrByOffset(struct sk_buff *skb, size_t offset) {
	return (struct iphdr *)(skb->data + offset);
}

static struct iphdr *getIphdrByFunction(struct sk_buff *skb, __attribute__((unused)) size_t offset) {
	return ip_hdr(skb);
}

static struct ipv6hdr *getIpv6hdrByOffset(struct sk_buff *skb, size_t offset) {
	return (struct ipv6hdr *)(skb->data + offset);
}

static struct ipv6hdr *getIpv6hdrByFunction(struct sk_buff *skb, __attribute__((unused)) size_t offset) {
	return getIp6Header(skb);
}

static unsigned char *getTransporthdrByOffset(struct sk_buff *skb, size_t offset) {
	return skb->data + offset;
}

static unsigned char *getTransporthdrByFunction(struct sk_buff *skb, __attribute__((unused)) size_t offset) {
	return skb_transport_header(skb);
}

void setDebugPrint(struct FilterExecuter *self, int debugPrint) {
	impl(self)->debugPrint = debugPrint;
}

bool matchAll(struct FilterExecuter *self, struct sk_buff *skb) {
	struct ethhdr *eth;
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct iphdr *ip;
	struct ipv6hdr *ip6;
	int matchedFilters = 0;
	bool isIpProtocol = false;
	int debugPrint = impl(self)->debugPrint;
	
	struct EthFilterList *ethFilter = NULL;
	struct IpFilterList *ipFilter = NULL;
	struct Ip6FilterList *ip6Filter = NULL;
	struct TcpFilterList *tcpFilter = NULL;
	struct UdpFilterList *udpFilter = NULL;
	
	unsigned char ipProtocol;
	
	size_t offset = 0;
		
	struct ethhdr *(*getEthhdr)(struct sk_buff *skb, size_t offset);
	struct iphdr *(*getIphdr)(struct sk_buff *skb, size_t offset);
	struct ipv6hdr *(*getIpv6hdr)(struct sk_buff *skb, size_t offset);
	unsigned char *(*getTransporthdr)(struct sk_buff *skb, size_t offset);
	
	if (skb->pkt_type != PACKET_OUTGOING) {
		getEthhdr = getEthhdrByFunction;
		getIphdr = getIphdrByFunction;
		getIpv6hdr = getIpv6hdrByFunction;
		getTransporthdr = getTransporthdrByFunction;
		skb_push(skb, ETH_HLEN);
		skb_reset_mac_header(skb);
	} else {
		getEthhdr = getEthhdrByOffset;
		getIphdr = getIphdrByOffset;
		getIpv6hdr = getIpv6hdrByOffset;
		getTransporthdr = getTransporthdrByOffset;
	}
	
	
	eth = getEthhdr(skb, offset);
	//eth = (struct ethhdr *)skb->data;
	offset += sizeof(struct ethhdr);
	/*
	if (skb->pkt_type == PACKET_OUTGOING) {
		// temporary fix for the fact PACKET_OUTGOING skb data is not set correctly.
		
	} else {		
		skb_reset_mac_header(skb);
		eth = eth_hdr(skb);
		if (eth == NULL) {
			klog_warn("SKB ETH header was null.");
			return false;
		}
	}
	*/
	if (debugPrint) {
		klog_info("SKB: Head %p Data %p", skb->head, skb->data);
		klog_info("Src: %pM Dst: %pM Proto: %04x", eth->h_source, eth->h_dest, ntohs(eth->h_proto));
	}
	
	ITERATE_FILTERS(ethFilter, ethFilters(self), filters, eth);
	
	switch (ntohs(eth->h_proto)) {
		case ETH_P_IP:
			//ip = ip_hdr(skb);
			//ip = (struct iphdr *)(skb->data + offset);
			ip = getIphdr(skb, offset);
			offset += sizeof(struct iphdr);
			if (!ip){
				klog_error("Protocol was IP but header was null.");
				return false;
			}
			if (debugPrint) klog_info("Src: %pI4 Dst: %pI4: Proto: %u", &ip->saddr, &ip->daddr, ip->protocol);
			ITERATE_FILTERS(ipFilter, ipFilters(self), filters, ip);
			ipProtocol = ip->protocol;
			isIpProtocol = true;
			break;
		case ETH_P_IPV6:
			//ip6 = getIp6Header(skb);
			//ip6 = (struct ipv6hdr *)(skb->data + offset);
			ip6 = getIpv6hdr(skb, offset);
			offset += sizeof(struct ipv6hdr);
			if (!ip6) {
				klog_error("Protocol was IPv6 but header was null.");
				return false;
			}
			ITERATE_FILTERS(ip6Filter, ip6Filters(self), filters, ip6);
			if (ipv6_ext_hdr(ip6->nexthdr)) {
				klog_error("Error extracting protocol from IPv6 packet.");
				return false;
			}
			
			ipProtocol = ip6->nexthdr;
			isIpProtocol = true;
			/*
			if (!getIp6Protocol(skb, &ipProtocol)) {
				klog_error("Error extracting protocol from IPv6 packet.");
				return false;
			}
			*/
			break;
	}

	if (isIpProtocol) {
		switch (ipProtocol) {
			case IPPROTO_TCP:
				//tcp = (struct tcphdr *)skb_transport_header(skb);
				//tcp = (struct tcphdr *)(skb->data + offset);
				tcp = (struct tcphdr *)getTransporthdr(skb, offset);
				if (!tcp) {
					klog_error("Protocol was TCP but header was null.");
					return false;
				}
				//klog_info("Iterating %s empty TCP Filters...", list_empty(tcpFilters(self)) ? "" : "non");
				//klog_info("Got TCP packet with SRC port of %d", ntohs(tcp->source));
				//klog_info("Got TCP packet with DST port of %d", ntohs(tcp->dest));
				ITERATE_FILTERS(tcpFilter, tcpFilters(self), filters, tcp);
				break;
			case IPPROTO_UDP:
				//udp = (struct udphdr *)skb_transport_header(skb);
				//udp = (struct udphdr *)(skb->data + offset);
				udp = (struct udphdr *)getTransporthdr(skb, offset);
				if (!udp) {
					klog_error("Protocol was UDP but header was null.");
					return false;
				}
				ITERATE_FILTERS(udpFilter, udpFilters(self), filters, udp);
				break;
		}
	}
	//unsigned char *data = skb_mac_header(skb);
	//klog_info("%02x:%02x:%02x:%02x:%02x:%02x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	
	//klog_info("Inside Match All... Packet Protocol was: %04X", ntohs(skb->protocol));
	
	//klog_info("Filters matched: %d out of %d.", matchedFilters, getTotalFilters(self));
	
	if (skb->pkt_type != PACKET_OUTGOING) {
		//skb_pull(skb, ETH_HLEN);
	}
	
	return matchedFilters == getTotalFilters(self);
}

FilterExecuter *FilterExecuter_Create(FilterOptions *filterOptions) {
	FilterExecuter *result = (FilterExecuter *)vzalloc(sizeof(FilterExecuter));
	FilterExecuterImpl *impl = (FilterExecuterImpl *)vzalloc(sizeof(FilterExecuterImpl));
	impl->totalFilters = 0;
	impl->debugPrint = 0;
	
	INIT_LIST_HEAD(&impl->eth);
	INIT_LIST_HEAD(&impl->ip);
	INIT_LIST_HEAD(&impl->ip6);
	INIT_LIST_HEAD(&impl->tcp);
	INIT_LIST_HEAD(&impl->udp);
	
	if (filterOptions->isEtherTypeSet(filterOptions)) {
		unsigned short etherType;
		EthFilterList *ethFilter = (EthFilterList *)vmalloc(sizeof(EthFilterList));
		etherType = filterOptions->getEtherType(filterOptions);
		ethFilter->filter = PacketFilter_createEthEtherTypeFilter(etherType);
		list_add(&ethFilter->filters, &impl->eth);
		impl->totalFilters++;
	}
	
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
		uint32_t ip;
		IpFilterList *ipFilter = (IpFilterList *)vmalloc(sizeof(IpFilterList));
		ip = filterOptions->getSrcIp(filterOptions);
		ipFilter->filter = PacketFilter_createIpSrcIpFilter(ip);
		list_add(&ipFilter->filters, &impl->ip);
		impl->totalFilters++;
	}
	
	if (filterOptions->isDstIpSet(filterOptions)) {
		uint32_t ip;
		IpFilterList *ipFilter = (IpFilterList *)vmalloc(sizeof(IpFilterList));
		ip = filterOptions->getDstIp(filterOptions);
		ipFilter->filter = PacketFilter_createIpDstIpFilter(ip);
		list_add(&ipFilter->filters, &impl->ip);
		impl->totalFilters++;
	}
	
	if (filterOptions->isSrcIp6Set(filterOptions)) {
		impl->totalFilters++;
	}
	
	if (filterOptions->isDstIp6Set(filterOptions)) {
		impl->totalFilters++;
	}
	
	if (filterOptions->isProtocolSet(filterOptions)) {
		unsigned char protocol;
		
		IpFilterList *ipFilter = (IpFilterList *)vmalloc(sizeof(IpFilterList));
		protocol = filterOptions->getProtocol(filterOptions);
		ipFilter->filter = PacketFilter_createIpProtocolFilter(protocol);
		list_add(&ipFilter->filters, &impl->ip);
		
		impl->totalFilters++;
	}
	
	if (filterOptions->isSrcPortSet(filterOptions)) {
		uint16_t port;
		TcpFilterList *tcpFilter = (TcpFilterList *)vmalloc(sizeof(TcpFilterList));
		port = filterOptions->getSrcPort(filterOptions);
		tcpFilter->filter = PacketFilter_createTcpSrcPortFilter(port);
		list_add(&tcpFilter->filters, &impl->tcp);
		impl->totalFilters++;
	}
	
	if (filterOptions->isDstPortSet(filterOptions)) {
		uint16_t port;
		TcpFilterList *tcpFilter = (TcpFilterList *)vmalloc(sizeof(TcpFilterList));
		port = filterOptions->getDstPort(filterOptions);
		tcpFilter->filter = PacketFilter_createTcpDstPortFilter(port);
		list_add(&tcpFilter->filters, &impl->tcp);
		impl->totalFilters++;
	}
	
	result->matchAll = matchAll;
	result->impl = impl;
	result->destroy = destroy;
	result->setDebugPrint = setDebugPrint;
	return result;
}
