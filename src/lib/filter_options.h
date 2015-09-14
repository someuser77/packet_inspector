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
	Filter_DstPort
} FilterType;

typedef enum {
	FilterSetResult_Success,
	FilterSetResult_FilterTypeNotSupported,
	FilterSetResult_NotEnoughMemory,
	FilterSetResult_InvalidFilterData
} FilterSetResult;

typedef struct FilterOptions {
	void *FilterOptionsImpl;
	
	struct FilterOptions *(*init)();
	
	bool (*IsFilterSet)(struct FilterOptions *self, FilterType filterType);
	
	FilterSetResult (*clear)(struct FilterOptions *self);
	
	bool (*isSrcMacSet)(struct FilterOptions *self);
	FilterSetResult (*setSrcMac)(struct FilterOptions *self, unsigned char (*mac)[ETH_ALEN]);
	int (*getSrcMac)(struct FilterOptions *self, unsigned char (*mac)[ETH_ALEN]);
	
	bool (*isDstMacSet)(struct FilterOptions *self);
	FilterSetResult (*setDstMac)(struct FilterOptions *self, unsigned char (*mac)[ETH_ALEN]);
	int (*getDstMac)(struct FilterOptions *self, unsigned char (*mac)[ETH_ALEN]);
	
	bool (*isSrcIpSet)(struct FilterOptions *self);
	FilterSetResult (*setSrcIp)(struct FilterOptions *self, uint32_t addr);
	uint32_t (*getSrcIp)(struct FilterOptions *self);
	
	bool (*isDstIpSet)(struct FilterOptions *self);
	FilterSetResult (*setDstIp)(struct FilterOptions *self, uint32_t addr);
	uint32_t (*getDstIp)(struct FilterOptions *self);
	
	bool (*isSrcIp6Set)(struct FilterOptions *self);
	FilterSetResult (*setSrcIp6)(struct FilterOptions *self, unsigned char (*addr)[IP6_ALEN]);
	int (*getSrcIp6)(struct FilterOptions *self, unsigned char (*addr)[IP6_ALEN]);
	
	bool (*isDstIp6Set)(struct FilterOptions *self);
	FilterSetResult (*setDstIp6)(struct FilterOptions *self, unsigned char (*addr)[IP6_ALEN]);
	int (*getDstIp6)(struct FilterOptions *self, unsigned char (*addr)[IP6_ALEN]);
	
	bool (*isDeviceSet)(struct FilterOptions *self);
	FilterSetResult (*setDevice)(struct FilterOptions *self, char *device, int len);
	int (*getDevice)(struct FilterOptions *self, char *device);
	
	bool (*isProtocolSet)(struct FilterOptions *self);
	FilterSetResult (*setProtocol)(struct FilterOptions *self, unsigned char protocol);
	unsigned char (*getProtocol)(struct FilterOptions *self);
	
	bool (*isSrcPortSet)(struct FilterOptions *self);
	FilterSetResult (*setSrcPort)(struct FilterOptions *self, uint16_t port);
	uint16_t (*getSrcPort)(struct FilterOptions *self);
	
	bool (*isDstPortSet)(struct FilterOptions *self);
	FilterSetResult (*setDstPort)(struct FilterOptions *self, uint16_t port);
	uint16_t (*getDstPort)(struct FilterOptions *self);
	
	char (*description)(struct FilterOptions *self);
	
} FilterOptions;

FilterOptions *FilterOptions_Create();
void FilterOptions_Destroy(FilterOptions **);

#endif