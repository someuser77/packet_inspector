#include <string.h>
#include "filter_options.h"

#define set_bit(target, bit) ((target) |= 1<< (bit))
#define is_bit_set(target, bit) (((target) >> (bit)) & 1)

// impl(self)->property could be rewritten as a macro property(self)

// the FilterOptionsImpl could be encoded more efficiently but lets keep it simple.
typedef struct {
	unsigned short map;
	unsigned char srcMac[ETH_ALEN];
	unsigned char dstMac[ETH_ALEN];
	uint32_t srcIp;
	uint32_t dstIp;
	unsigned char srcIp6[IP6_ALEN];
	unsigned char dstIp6[IP6_ALEN];
	char device[IFNAMSIZ];	/* IFNAMSIZ is the constant defines the maximum buffer size needed
												to hold an interface name, including its terminating zero byte. 
												http://www.gnu.org/software/libc/manual/html_node/Interface-Naming.html */
	unsigned char protocol;
	uint16_t srcPort;
	uint16_t dstPort;	
} FilterOptionsImpl;

inline FilterOptionsImpl* impl(FilterOptions *self) {
	return (FilterOptionsImpl *)self->FilterOptionsImpl;
}

#define define_isSetFunction(name, bit)								\
				static bool name(FilterOptions *self) {					\
					return is_bit_set(impl(self)->map, bit);				\
				}

#define SRC_MAC_SET_BIT 		1
#define DST_MAC_SET_BIT 		2
#define SRC_IP_SET_BIT 			3
#define DST_IP_SET_BIT 			4
#define SRC_IP6_SET_BIT 		5
#define DST_IP6_SET_BIT 		6
#define DEVICE_SET_BIT 			7
#define PROTOCOL_SET_BIT 	8
#define SRC_PORT_SET_BIT 		9
#define DST_PORT_SET_BIT 		10


define_isSetFunction(isSrcMacSet, SRC_MAC_SET_BIT);
define_isSetFunction(isDstMacSet, DST_MAC_SET_BIT);
define_isSetFunction(isSrcIpSet, SRC_IP_SET_BIT);
define_isSetFunction(isDstIpSet, DST_IP_SET_BIT);
define_isSetFunction(isSrcIp6Set, SRC_IP6_SET_BIT);
define_isSetFunction(isDstIp6Set, DST_IP6_SET_BIT);
define_isSetFunction(isDeviceSet, DEVICE_SET_BIT);
define_isSetFunction(isProtocolSet, PROTOCOL_SET_BIT);
define_isSetFunction(isSrcPortSet, SRC_PORT_SET_BIT);
define_isSetFunction(isDstPortSet, DST_PORT_SET_BIT);

static void set(FilterOptions *self, int bit) {
	set_bit(impl(self)->map, bit);
}

static bool setSrcMac(FilterOptions *self, const unsigned char const mac[ETH_ALEN]) {
	set(self, SRC_MAC_SET_BIT);
	memcpy(impl(self)->srcMac, mac, ETH_ALEN);
	return true;
}

static int getSrcMac(struct FilterOptions *self, unsigned char mac[ETH_ALEN]) {
	if (!isSrcMacSet(self)) return -1;
	memcpy(mac, impl(self)->srcMac, ETH_ALEN);
	return 0;
}

static bool setDstMac(FilterOptions *self, const unsigned char const mac[ETH_ALEN]) {
	set(self, DST_MAC_SET_BIT);
	memcpy(impl(self)->dstMac, mac, ETH_ALEN);
	return true;
}

static int getDstMac(struct FilterOptions *self, unsigned char mac[ETH_ALEN]) {
	if (!isDstMacSet(self)) return -1;
	memcpy(mac, impl(self)->dstMac, ETH_ALEN);
	return 0;
}

static bool setSrcIp(struct FilterOptions *self, uint32_t addr) {
	set(self, SRC_IP_SET_BIT);
	impl(self)->srcIp = addr;
	return true;
}

static uint32_t getSrcIp(struct FilterOptions *self) {
	return impl(self)->srcIp;
}

static bool setDstIp(struct FilterOptions *self, uint32_t addr) {
	set(self, DST_IP_SET_BIT);
	impl(self)->dstIp = addr;
	return true;
}

static uint32_t getDstIp(struct FilterOptions *self) {
	return impl(self)->dstIp;
}

static bool setSrcIp6(struct FilterOptions *self, const unsigned char const addr[IP6_ALEN]) {
	set(self, SRC_IP6_SET_BIT);
	memcpy(impl(self)->srcIp6, addr, IP6_ALEN);
	return true;
}

static int getSrcIp6(struct FilterOptions *self, unsigned char addr[IP6_ALEN]) {
	if (!isSrcIp6Set(self)) return -1;
	memcpy(addr, impl(self)->srcIp6, IP6_ALEN);
	return 0;
}

static bool setDstIp6(struct FilterOptions *self, const unsigned char const addr[IP6_ALEN]) {
	set(self, DST_IP6_SET_BIT);
	memcpy(impl(self)->dstIp6, addr, IP6_ALEN);
	return true;
}

static int getDstIp6(struct FilterOptions *self, unsigned char addr[IP6_ALEN]) {
	if (!isDstIp6Set(self)) return -1;
	memcpy(addr, impl(self)->dstIp6, IP6_ALEN);
	return 0;
}

int setDevice(struct FilterOptions *self, const char const *device, int len) {
	if (len < 0) return -1;
	set(self, DEVICE_SET_BIT);
	if (len > IFNAMSIZ - 1) len = IFNAMSIZ - 1;
	memset(impl(self)->device, '\0', IFNAMSIZ);
	memcpy(impl(self)->device, device, len);
	return len;
}

int getDevice(struct FilterOptions *self, char *device) {
	if (!isDeviceSet(self)) return -1;
	int len = strlen(impl(self)->device);
	memcpy(device, impl(self)->device, len);
	device[len] = '\0';
	return len;
}

bool setProtocol(struct FilterOptions *self, unsigned char protocol) {
	set(self, PROTOCOL_SET_BIT);
	impl(self)->protocol = protocol;
	return true;
}

unsigned char getProtocol(struct FilterOptions *self) {
	return impl(self)->protocol;
}

bool setSrcPort(struct FilterOptions *self, uint16_t port) {
	set(self, SRC_PORT_SET_BIT);
	impl(self)->srcPort = port;
	return true;
}

uint16_t getSrcPort(struct FilterOptions *self) {
	return impl(self)->srcPort;
}
	
bool setDstPort(struct FilterOptions *self, uint16_t port) {
	set(self, DST_PORT_SET_BIT);
	impl(self)->dstPort = port;
	return true;
}

uint16_t getDstPort(struct FilterOptions *self) {
	return impl(self)->dstPort;
}


FilterOptions *FilterOptions_Create() {
	
	FilterOptions *filterOptions = (FilterOptions *)calloc(1, sizeof(FilterOptions));
	if (filterOptions == NULL) {
		return NULL;
	}
	filterOptions->FilterOptionsImpl = (FilterOptionsImpl *)calloc(1, sizeof(FilterOptionsImpl));
	if (filterOptions->FilterOptionsImpl == NULL) {
		return NULL;
	}	
	
	filterOptions->isSrcMacSet = isSrcMacSet;
	filterOptions->setSrcMac = setSrcMac;
	filterOptions->getSrcMac = getSrcMac;
	
	filterOptions->isDstMacSet = isDstMacSet;
	filterOptions->setDstMac = setDstMac;
	filterOptions->getDstMac = getDstMac;

	filterOptions->isSrcIpSet = isSrcIpSet;
	filterOptions->setSrcIp = setSrcIp;
	filterOptions->getSrcIp = getSrcIp;
	
	filterOptions->isDstIpSet = isDstIpSet;
	filterOptions->setDstIp = setDstIp;
	filterOptions->getDstIp = getDstIp;
	
	filterOptions->isSrcIp6Set = isSrcIp6Set;
	filterOptions->setSrcIp6 = setSrcIp6;
	filterOptions->getSrcIp6 = getSrcIp6;
	
	filterOptions->isDstIp6Set = isDstIp6Set;
	filterOptions->setDstIp6 = setDstIp6;
	filterOptions->getDstIp6 = getDstIp6;
	
	filterOptions->isDeviceSet = isDeviceSet;
	filterOptions->setDevice = setDevice;
	filterOptions->getDevice = getDevice;
	
	filterOptions->isProtocolSet = isProtocolSet;
	filterOptions->setProtocol = setProtocol;
	filterOptions->getProtocol = getProtocol;
	
	filterOptions->isSrcPortSet = isSrcPortSet;
	filterOptions->setSrcPort = setSrcPort;
	filterOptions->getSrcPort = getSrcPort;
	
	filterOptions->isDstPortSet = isDstPortSet;
	filterOptions->setDstPort = setDstPort;
	filterOptions->getDstPort = getDstPort;
	
	return filterOptions;
}

void FilterOptions_Destroy(FilterOptions **filterOptions) {
	free((*filterOptions)->FilterOptionsImpl);
	free(*filterOptions);
	*filterOptions = NULL;
}
