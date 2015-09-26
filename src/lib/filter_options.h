#ifndef _FILTER_OPTIONS_H_ 
#define _FILTER_OPTIONS_H_

#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h> // required for sockaddr definitions in other include files
#include <linux/if_ether.h>
#include <stdint.h>
#include <linux/if.h>

#ifndef IP6_ALEN
#define IP6_ALEN 16
#endif

typedef enum {
	Filter_None,
	Filter_SrcMac,
	Filter_DstMac,
	Filter_SrcIP,
	Filter_DstIP,
	Filter_SrcIP6,
	Filter_DstIP6,
	Filter_Device,
	Filter_Protocol,
	Filter_SrcPort,
	Filter_DstPort,
	Filter_EtherType
} FilterType;

typedef struct FilterOptions {
	void *FilterOptionsImpl;
	
	struct FilterOptions *(*init)();
	
	bool (*IsFilterSet)(struct FilterOptions *self, FilterType filterType);
	
	void (*clear)(struct FilterOptions *self);
	
	bool (*isSrcMacSet)(struct FilterOptions *self);
	bool (*setSrcMac)(struct FilterOptions *self, const unsigned char const mac[ETH_ALEN]);
	int (*getSrcMac)(struct FilterOptions *self, unsigned char mac[ETH_ALEN]);
	
	bool (*isDstMacSet)(struct FilterOptions *self);
	bool (*setDstMac)(struct FilterOptions *self, const unsigned char const mac[ETH_ALEN]);
	int (*getDstMac)(struct FilterOptions *self, unsigned char mac[ETH_ALEN]);
	
	bool (*isSrcIpSet)(struct FilterOptions *self);
	bool (*setSrcIp)(struct FilterOptions *self, uint32_t addr);
	uint32_t (*getSrcIp)(struct FilterOptions *self);
	
	bool (*isDstIpSet)(struct FilterOptions *self);
	bool (*setDstIp)(struct FilterOptions *self, uint32_t addr);
	uint32_t (*getDstIp)(struct FilterOptions *self);
	
	bool (*isSrcIp6Set)(struct FilterOptions *self);
	bool (*setSrcIp6)(struct FilterOptions *self, const unsigned char const addr[IP6_ALEN]);
	int (*getSrcIp6)(struct FilterOptions *self, unsigned char addr[IP6_ALEN]);
	
	bool (*isDstIp6Set)(struct FilterOptions *self);
	bool (*setDstIp6)(struct FilterOptions *self, const unsigned char const addr[IP6_ALEN]);
	int (*getDstIp6)(struct FilterOptions *self, unsigned char addr[IP6_ALEN]);
	
	bool (*isDeviceSet)(struct FilterOptions *self);
	int (*setDevice)(struct FilterOptions *self, const char * const device, int len);
	int (*getDevice)(struct FilterOptions *self, char device[IFNAMSIZ]);
	
	bool (*isProtocolSet)(struct FilterOptions *self);
	bool (*setProtocol)(struct FilterOptions *self, unsigned char protocol);
	unsigned char (*getProtocol)(struct FilterOptions *self);
	
	bool (*isSrcPortSet)(struct FilterOptions *self);
	bool (*setSrcPort)(struct FilterOptions *self, uint16_t port);
	uint16_t (*getSrcPort)(struct FilterOptions *self);
	
	bool (*isDstPortSet)(struct FilterOptions *self);
	bool (*setDstPort)(struct FilterOptions *self, uint16_t port);
	uint16_t (*getDstPort)(struct FilterOptions *self);
	
	char* (*description)(struct FilterOptions *self);
	
	size_t (*serialize)(struct FilterOptions *self, unsigned char *buffer, size_t size);
	
} FilterOptions;

FilterOptions *FilterOptions_Create();
FilterOptions *FilterOptions_Deserialize(const unsigned char *buffer, size_t size);
void FilterOptions_Destroy(FilterOptions **);

#endif