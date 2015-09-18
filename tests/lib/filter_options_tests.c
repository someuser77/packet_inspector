#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../minunit.h" 
#include "filter_options.h"
 
FilterOptions *filterOptions;
 
char *test_FilterOptions_NULL_After_Destroy() {
	FilterOptions *filterOptions = FilterOptions_Create();
	FilterOptions_Destroy(&filterOptions);
	mu_assert(filterOptions == NULL, "Reference was not NULL after Destroy.");
	return NULL;
}
 
static char *test_FilterOptions_SetGetMac(
	int (*getMac)(struct FilterOptions *self, unsigned char mac[ETH_ALEN]),
	bool (*setMac)(struct FilterOptions *self, const unsigned char const mac[ETH_ALEN]),
	FilterOptions *target,
	unsigned char mac[ETH_ALEN]
	) {
	unsigned char tmp[ETH_ALEN] = {0};
	
	mu_assert((*getMac)(target, tmp) == -1, "getMac didn't return error although mac was not set");
	
	bool filterSetResult = (*setMac)(target, mac);
	
	mu_assert(filterSetResult, "setMac failed.");
	
	mu_assert((*getMac)(target, tmp) == 0, "getMac failed");
	
	mu_assert(memcmp(tmp, mac, ETH_ALEN) == 0, "getMac returned wrong mac");
	
	return NULL;
}

char *test_FilterOptions_SetGetSrcMac() {
	unsigned char mac[ETH_ALEN] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6};
	return test_FilterOptions_SetGetMac(filterOptions->getSrcMac, filterOptions->setSrcMac, filterOptions, mac);
}

char *test_FilterOptions_SetGetDstMac() {
	unsigned char mac[ETH_ALEN] = {0x6, 0x5, 0x4, 0x3, 0x2, 0x1};
	return test_FilterOptions_SetGetMac(filterOptions->getDstMac, filterOptions->setDstMac, filterOptions, mac);
}

static char *test_FilterOptions_SetGetIp(
	uint32_t (*getIp)(struct FilterOptions *self),
	bool (*setIp)(struct FilterOptions *self, uint32_t addr),
	FilterOptions *target,
	uint32_t addr
	) {	
	uint32_t expected;
	
	expected = addr;
		
	bool filterSetResult = (*setIp)(target, addr);
	
	mu_assert(filterSetResult, "setIp failed.");
	
	mu_assert((*getIp)(target) == expected, "getIp failed");
	
	return NULL;
}

char *test_FilterOptions_SetGetSrcIp() {
	uint32_t addr;
	inet_pton(AF_INET, "192.0.2.33", &addr);
	return test_FilterOptions_SetGetIp(filterOptions->getSrcIp, filterOptions->setSrcIp, filterOptions, addr);
}

char *test_FilterOptions_SetGetDstIp() {
	uint32_t addr;
	inet_pton(AF_INET, "192.0.2.34", &addr);
	return test_FilterOptions_SetGetIp(filterOptions->getDstIp, filterOptions->setDstIp, filterOptions, addr);
}

static char *test_FilterOptions_SetGetIp6(
	int (*getIp6)(struct FilterOptions *self, unsigned char addr[IP6_ALEN]),
	bool (*setIp6)(struct FilterOptions *self, const unsigned char const addr[IP6_ALEN]),
	FilterOptions *target,
	unsigned char addr[IP6_ALEN]
	) {
	unsigned char tmp[IP6_ALEN] = {0};
	
	mu_assert((*getIp6)(target, tmp) == -1, "getIp6 didn't return error although ip6 was not set");
	
	bool filterSetResult = (*setIp6)(target, addr);
	
	mu_assert(filterSetResult, "setIp6 failed.");
	
	mu_assert((*getIp6)(target, tmp) == 0, "getIp6 failed");
	
	mu_assert(memcmp(tmp, addr, IP6_ALEN) == 0, "getip6 returned wrong mac");
	
	return NULL;
}

char *test_FilterOptions_SetGetSrcIp6() {
	unsigned char ip6[IP6_ALEN] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
	return test_FilterOptions_SetGetIp6(filterOptions->getSrcIp6, filterOptions->setSrcIp6, filterOptions, ip6);
}

char *test_FilterOptions_SetGetDstIp6() {
	unsigned char ip6[IP6_ALEN] = { 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1 };
	return test_FilterOptions_SetGetIp6(filterOptions->getDstIp6, filterOptions->setDstIp6, filterOptions, ip6);
}

char *test_FilterOptions_SetGetDevice() {
	char *device = "MyDevice12345678901234567890";
	char expected[IFNAMSIZ] = {0};
	char tmp[IFNAMSIZ] = {0};
	int len;
	
	strncpy(expected, device, IFNAMSIZ);
	
	mu_assert(filterOptions->getDevice(filterOptions, tmp) == -1, "getDevice didn't return an error althrough device was not set.");
	
	int filterSetResult = filterOptions->setDevice(filterOptions, device, strlen(device));
	
	mu_assert(filterSetResult >= 0, "setDevice failed.");
	
	len = filterOptions->getDevice(filterOptions, tmp);
	
	mu_assert(len == IFNAMSIZ - 1, "getDevice didn't return the expected length.");
	
	mu_assert(memcmp(tmp, device, len) == 0, "getDevice returned wrong device_name.");
	
	return NULL;
}

char *test_FilterOptions_SetDevice_BadLength() {
	char *device = "MyDevice12345678901234567890";
	
	int len = filterOptions->setDevice(filterOptions, device, -1);
	
	mu_assert(len == -1, "setDevice didn't fail on negatve length.");
	
	return NULL;
}

char *test_FilterOptions_SetGetProtocol() {
	unsigned char protocol = IPPROTO_TCP;
	
	bool filterSetResult = filterOptions->setProtocol(filterOptions, protocol);
	
	mu_assert(filterSetResult, "setProtocol failed.");
	
	mu_assert(filterOptions->getProtocol(filterOptions) == protocol, "getProtocol failed");
	return NULL;
}

static char *test_FilterOptions_SetGetPort(
	uint16_t (*getPort)(struct FilterOptions *self),
	bool (*setPort)(struct FilterOptions *self, uint16_t port),	
	FilterOptions *target,
	uint16_t port
	) {	
	bool filterSetResult = (*setPort)(target, port);
	
	mu_assert(filterSetResult, "setPort failed.");
	
	mu_assert((*getPort)(target) == port, "getPort returned wrong port");
	
	return NULL;
}

char *test_FilterOptions_SetGetSrcPort() {
	uint16_t port = 123;
	return test_FilterOptions_SetGetPort(filterOptions->getSrcPort, filterOptions->setSrcPort, filterOptions, port);
}

char *test_FilterOptions_SetGetDstPort() {
	uint16_t port = 456;
	return test_FilterOptions_SetGetPort(filterOptions->getDstPort, filterOptions->setDstPort, filterOptions, port);
}

void init() {
	filterOptions = FilterOptions_Create();
}

void cleanup() {
	FilterOptions_Destroy(&filterOptions);
}

char *all_tests() {
	mu_suite_start();
	mu_run_test(test_FilterOptions_NULL_After_Destroy);
	mu_run_test(test_FilterOptions_SetGetSrcMac);
	mu_run_test(test_FilterOptions_SetGetDstMac);
	mu_run_test(test_FilterOptions_SetGetSrcIp);
	mu_run_test(test_FilterOptions_SetGetDstIp);
	mu_run_test(test_FilterOptions_SetGetSrcIp6);
	mu_run_test(test_FilterOptions_SetGetDstIp6);
	mu_run_test(test_FilterOptions_SetGetDevice);
	mu_run_test(test_FilterOptions_SetDevice_BadLength);
	mu_run_test(test_FilterOptions_SetGetProtocol);
	mu_run_test(test_FilterOptions_SetGetSrcPort);
	mu_run_test(test_FilterOptions_SetGetDstPort);
	return NULL;
}

RUN_TESTS_WITH_SETUP(all_tests, init, cleanup);