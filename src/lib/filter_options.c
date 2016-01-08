#include <stdarg.h>

// for scnprintf
#ifdef __KERNEL__
#include <linux/kernel.h>
#else
#include <string.h>
#include <stdio.h>
#endif

#include "alloc.h"
#include "filter_options.h"

#define set_bit(target, bit) ((target) |= 1<< (bit))
#define is_bit_set(target, bit) (((target) >> (bit)) & 1)

// impl(self)->property could be rewritten as a macro property(self)

// the FilterOptionsImpl could be encoded more efficiently but lets keep it simple.
// this struct is unaligned on purpose because we will hold a pointer to the struct and
// for now we don't want to work with unaligned pointer access.
typedef struct {
	unsigned short map;
	unsigned short etherType;
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

static inline FilterOptionsImpl* impl(FilterOptions *self) {
	return (FilterOptionsImpl *)self->FilterOptionsImpl;
}

#define define_isSetFunction(name, bit)								\
				static bool name(FilterOptions *self) {					\
					return is_bit_set(impl(self)->map, bit);				\
				}

#define ETHER_TYPE_SET_BIT	0
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
#define SHUTDOWN					15

define_isSetFunction(isEtherTypeSet, ETHER_TYPE_SET_BIT);
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
define_isSetFunction(isShutdownSet, SHUTDOWN);

static bool isEmpty(FilterOptions *self) {
	return impl(self)->map == 0;
}

static void set(FilterOptions *self, int bit) {
	set_bit(impl(self)->map, bit);
}

static bool setEtherType(FilterOptions *self, unsigned short etherType) {
	set(self, ETHER_TYPE_SET_BIT);
	impl(self)->etherType = etherType;
	return true;
}

static unsigned short getEtherType(FilterOptions *self) {
	return impl(self)->etherType;
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

static int setDevice(struct FilterOptions *self, const char const *device, int len) {
	if (len < 0) return -1;
	set(self, DEVICE_SET_BIT);
	if (len > IFNAMSIZ - 1) len = IFNAMSIZ - 1;
	memset(impl(self)->device, '\0', IFNAMSIZ);
	memcpy(impl(self)->device, device, len);
	return len;
}

static int getDevice(struct FilterOptions *self, char *device) {
	int len;
	if (!isDeviceSet(self)) return -1;
	len = strlen(impl(self)->device);
	memcpy(device, impl(self)->device, len);
	device[len] = '\0';
	return len;
}

static bool setProtocol(struct FilterOptions *self, unsigned char protocol) {
	set(self, PROTOCOL_SET_BIT);
	impl(self)->protocol = protocol;
	return true;
}

static unsigned char getProtocol(struct FilterOptions *self) {
	return impl(self)->protocol;
}

static bool setSrcPort(struct FilterOptions *self, uint16_t port) {
	set(self, SRC_PORT_SET_BIT);
	impl(self)->srcPort = port;
	return true;
}

static uint16_t getSrcPort(struct FilterOptions *self) {
	return impl(self)->srcPort;
}
	
static bool setDstPort(struct FilterOptions *self, uint16_t port) {
	set(self, DST_PORT_SET_BIT);
	impl(self)->dstPort = port;
	return true;
}

static uint16_t getDstPort(struct FilterOptions *self) {
	return impl(self)->dstPort;
}

static void setShutdown(struct FilterOptions *self) {
	set(self, SHUTDOWN);
}

static int snprintf_wrap(char *buf, size_t size, struct FilterOptions *self) {
	const char *format = "FilterOptions:\n"
							"\tSHUTDOWN: %d srcMac: %d dstMac: %d srcIp: %d dstIp: %d srcIp6: %d dstIp6: %d device: %d protocol: %d srcPort: %d dstPort: %d\n"
							"\tsrcMac: %02x:%02x:%02x:%02x:%02x:%02x\n"
							"\tdstMac: %02x:%02x:%02x:%02x:%02x:%02x\n"
							"\tsrcIp: %d.%d.%d.%d\n"
							"\tdstIp: %d.%d.%d.%d\n"
							"\tsrcIp6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n"
							"\tdstIp6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n"
							"\tdevice: %s\n"
							"\tprotocol: %d\n"
							"\tsrcPort: %hu\n"
							"\tdstPort: %hu\n";	
	
	return snprintf(buf, size, format, 
		isShutdownSet(self), isSrcMacSet(self), isDstMacSet(self), isSrcIpSet(self), isDstIpSet(self), isSrcIp6Set(self), isDstIp6Set(self), isDeviceSet(self), isProtocolSet(self), isSrcPortSet(self), isDstPortSet(self),
		impl(self)->srcMac[0], impl(self)->srcMac[1], impl(self)->srcMac[2], impl(self)->srcMac[3], impl(self)->srcMac[4], impl(self)->srcMac[5],
		impl(self)->dstMac[0], impl(self)->dstMac[1], impl(self)->dstMac[2], impl(self)->dstMac[3], impl(self)->dstMac[4], impl(self)->dstMac[5],
		(impl(self)->srcIp >> 24) & 0xff, (impl(self)->srcIp >> 16) & 0xff, (impl(self)->srcIp >> 8) & 0xff, (impl(self)->srcIp >> 0) & 0xff,
		(impl(self)->dstIp >> 24) & 0xff, (impl(self)->dstIp >> 16) & 0xff, (impl(self)->dstIp >> 8) & 0xff, (impl(self)->dstIp >> 0) & 0xff,
		impl(self)->srcIp6[0], impl(self)->srcIp6[1], impl(self)->srcIp6[2], impl(self)->srcIp6[3], impl(self)->srcIp6[4], impl(self)->srcIp6[5], impl(self)->srcIp6[6], impl(self)->srcIp6[7],
		impl(self)->srcIp6[8], impl(self)->srcIp6[9], impl(self)->srcIp6[10], impl(self)->srcIp6[11], impl(self)->srcIp6[12], impl(self)->srcIp6[13], impl(self)->srcIp6[14], impl(self)->srcIp6[15],
		impl(self)->dstIp6[0], impl(self)->dstIp6[1], impl(self)->dstIp6[2], impl(self)->dstIp6[3], impl(self)->dstIp6[4], impl(self)->dstIp6[5], impl(self)->dstIp6[6], impl(self)->dstIp6[7],
		impl(self)->dstIp6[8], impl(self)->dstIp6[9], impl(self)->dstIp6[10], impl(self)->dstIp6[11], impl(self)->dstIp6[12], impl(self)->dstIp6[13], impl(self)->dstIp6[14], impl(self)->dstIp6[15],
		impl(self)->device,
		impl(self)->protocol,
		impl(self)->srcPort,
		impl(self)->dstPort);
}

static char *getDescription(struct FilterOptions *self) {
	char *result = NULL;
	int length;
	int expected_length = snprintf_wrap(NULL, 0, self);
	
	if (expected_length < 0) return NULL;
	
	result = (char *)alloc((sizeof(char) * expected_length) + 1);
	
	if (result == NULL) 
		return NULL;
	
	length = snprintf_wrap(result, expected_length + 1, self);
	
	if (length < 0 || length > expected_length + 1) {
		release(result);
		return NULL;
	}
	
	return result;
}

static size_t serialize(struct FilterOptions *self, unsigned char *buffer, size_t size) {
	if (size >= sizeof(FilterOptionsImpl) && buffer != NULL) 
		memcpy(buffer, impl(self), sizeof(FilterOptionsImpl));
	return sizeof(FilterOptionsImpl);
}

static struct FilterOptions *clone(struct FilterOptions *self) {
	unsigned char *buffer;
	size_t buffer_size;
	FilterOptions *result;
	
	buffer_size = self->serialize(self, NULL, 0);
	buffer = (unsigned char *)alloc(buffer_size);
	self->serialize(self, buffer, buffer_size);
	
	result = FilterOptions_Deserialize(buffer, buffer_size);
	release(buffer);
	
	return result;
}

static bool equals(struct FilterOptions *self, struct FilterOptions *other) {
	unsigned char mac1[ETH_ALEN] = {0};
	unsigned char mac2[ETH_ALEN] = {0};
	unsigned char addr1[IP6_ALEN] = {0};
	unsigned char addr2[IP6_ALEN] = {0};
	char device1[IFNAMSIZ] = {0};
	char device2[IFNAMSIZ] = {0};
	bool set;
	
	if (other == NULL) 
		return false;
	
	if (self == other) 
		return true;
	
	if (self->isEmpty(self) != other->isEmpty(other))
		return false;
	
	if ((set = self->isSrcMacSet(self)) != other->isSrcMacSet(other))
		return false;
	
	if (set) {
		self->getSrcMac(self, mac1);
		other->getSrcMac(other, mac2);
		
		if (memcmp(mac1, mac2, ETH_ALEN) != 0) 
			return false;
	}
	
	if ((set = self->isDstMacSet(self)) != other->isDstMacSet(other))
		return false;
	
	if (set) {
		self->getDstMac(self, mac1);
		other->getDstMac(other, mac2);
		
		if (memcmp(mac1, mac2, ETH_ALEN) != 0) 
			return false;
	}
	
	if ((set = self->isSrcIpSet(self)) != other->isSrcIpSet(other))
		return false;
	
	if (set) {
		if (self->getSrcIp(self) != other->getSrcIp(other))
			return false;
	}
	
	if ((set = self->isDstIpSet(self)) != other->isDstIpSet(other))
		return false;
	
	if (set) {		
		if (self->getDstIp(self) != other->getDstIp(other))
			return false;
	}
	
	if ((set = self->isSrcIp6Set(self)) != other->isSrcIp6Set(other)) {
		return false;
	}
	
	if (set) {
		self->getSrcIp6(self, addr1);
		other->getSrcIp6(other, addr2);
		
		if (memcmp(addr1, addr2, IP6_ALEN) != 0)
			return false;
	}
	
	if ((set = self->isDstIp6Set(self)) != other->isDstIp6Set(other))
		return false;
	
	if (set) {		
		self->getDstIp6(self, addr1);
		other->getDstIp6(other, addr2);
		
		if (memcmp(addr1, addr2, IP6_ALEN) != 0)
			return false;
	}
	
	if ((set = self->isDeviceSet(self)) != other->isDeviceSet(other))
		return false;
	
	if (set) {
		self->getDevice(self, device1);
		self->getDevice(self, device2);
	
		if (strncmp(device1, device2, IFNAMSIZ) != 0)
			return false;
	}
	
	if ((set = self->isProtocolSet(self)) != other->isProtocolSet(other))
		return false;
	
	if (set) {
		if (self->getProtocol(self) != other->getProtocol(other))
			return false;
	}
	
	if ((set = self->isSrcPortSet(self)) != other->isSrcPortSet(other))
		return false;
	
	if (set) {
		if (self->getSrcPort(self) != other->getSrcPort(other))
			return false;
	}
	
	if ((set = self->isDstPortSet(self)) != other->isDstPortSet(other))
		return false;
	
	if (set) {
		if (self->getDstPort(self) != other->getDstPort(other))
			return false;
	}
	
	if ((set = self->isEtherTypeSet(self)) != other->isEtherTypeSet(other))
		return false;
	
	if (set) {
		if (self->getEtherType(self) != other->getEtherType(other))
			return false;
	}
	
	return true;
}

FilterOptions *FilterOptions_Create() {
	
	FilterOptions *filterOptions = (FilterOptions *)alloc(sizeof(FilterOptions));
	if (filterOptions == NULL) {
		return NULL;
	}
	
	memset(filterOptions, 0, sizeof(FilterOptions));
	
	filterOptions->FilterOptionsImpl = (FilterOptionsImpl *)alloc(sizeof(FilterOptionsImpl));
	if (filterOptions->FilterOptionsImpl == NULL) {
		return NULL;
	}
	
	memset(filterOptions->FilterOptionsImpl, 0, sizeof(FilterOptionsImpl));
	
	
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
	
	filterOptions->isEtherTypeSet = isEtherTypeSet;
	filterOptions->setEtherType = setEtherType;
	filterOptions->getEtherType = getEtherType;
	
	filterOptions->description = getDescription;

	filterOptions->serialize = serialize;
	
	filterOptions->isShutdownSet = isShutdownSet;
	filterOptions->setShutdown = setShutdown;
	
	filterOptions->isEmpty = isEmpty;
	
	filterOptions->equals = equals;

	filterOptions->clone = clone;

	return filterOptions;
}

FilterOptions *FilterOptions_Deserialize(const unsigned char *buffer, size_t size) {
	FilterOptions *filter;
	if (size < sizeof(FilterOptionsImpl)) {
		return NULL;
	}

	filter = FilterOptions_Create();
	
	memcpy(impl(filter), buffer, sizeof(FilterOptionsImpl));
	
	return filter;
}

void FilterOptions_Destroy(FilterOptions **filterOptions) {
	release((*filterOptions)->FilterOptionsImpl);
	release(*filterOptions);
	*filterOptions = NULL;
}

