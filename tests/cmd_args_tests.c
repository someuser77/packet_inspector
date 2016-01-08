#include "minunit.h" 
#include <arpa/inet.h>
#include "directional_filter_options.h"
#include "cmd_args.h"

char *test_CommandLineArgs_ParsingAll() {
	
	char *argv[] = {
		"xxx", 
		"--device=device1", 
		"--protocol=tcp", 
		"--ether-type=ip",		
		
		"--incoming-src-mac=06:05:04:03:02:01",
		"--incoming-dst-mac=00:22:fa:e8:c2:42",
		"--incoming-src-ip=10.0.0.2",
		"--incoming-dst-ip=10.0.0.3",
		"--incoming-src-ip6=102:304:506:708:90a:b0c:d0e:f00",
		"--incoming-dst-ip6=f0e:d0c:b0a:908:706:504:302:100",
		"--incoming-src-port=80",
		"--incoming-dst-port=81",
		
		"--outgoing-src-mac=06:05:04:03:02:01",
		"--outgoing-dst-mac=00:22:fa:e8:c2:42",
		"--outgoing-src-ip=10.0.0.2",
		"--outgoing-dst-ip=10.0.0.3",
		"--outgoing-src-ip6=102:304:506:708:90a:b0c:d0e:f00",
		"--outgoing-dst-ip6=f0e:d0c:b0a:908:706:504:302:100",
		"--outgoing-src-port=80",
		"--outgoing-dst-port=81"
	};
	int argc = sizeof(argv) / sizeof(char *);
	
	DirectionalFilterOptions *expected = DirectionalFilterOptions_Create();
	DirectionalFilterOptions *options;
	
	FilterOptions *incoming = FilterOptions_Create();
	FilterOptions *outgoing = FilterOptions_Create();
	
	unsigned char srcMac[ETH_ALEN] = {0x6, 0x5, 0x4, 0x3, 0x2, 0x1};
	unsigned char dstMac[ETH_ALEN] = {0x00, 0x22, 0xfa, 0xe8, 0xc2, 0x42};
	
	uint32_t srcIp, dstIp;
	unsigned char srcIp6[IP6_ALEN] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
	unsigned char dstIp6[IP6_ALEN] = { 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1 };	
	
	/*
	char buffer[256] = {0};
	inet_ntop(AF_INET6, dstIp6, buffer,  INET6_ADDRSTRLEN);
	printf("\n\n\n%s\n\n\n", buffer);
	*/
	inet_pton(AF_INET, "10.0.0.2", &srcIp);
	inet_pton(AF_INET, "10.0.0.3", &dstIp);
	
	incoming->setDevice(incoming, "device1", 7);
	
	incoming->setProtocol(incoming, IPPROTO_TCP);
	
	incoming->setEtherType(incoming, ETH_P_IP);
	
	incoming->setSrcMac(incoming, srcMac);
	incoming->setDstMac(incoming, dstMac);
	
	incoming->setSrcPort(incoming, 80);
	incoming->setDstPort(incoming, 81);
	
	incoming->setSrcIp(incoming, ntohl(srcIp));
	incoming->setDstIp(incoming, ntohl(dstIp));
	
	incoming->setSrcIp6(incoming, srcIp6);
	incoming->setDstIp6(incoming, dstIp6);
	
	outgoing = incoming->clone(incoming);
	
	expected->setIncomingFilterOptions(expected, incoming);
	expected->setOutgoingFilterOptions(expected, outgoing);
	
	options = parseCommandLineArguments(argc, argv);
	
	mu_assert(expected->equals(expected, options), "Parsing Failed.");
	
	DirectionalFilterOptions_Destroy(&options);
	DirectionalFilterOptions_Destroy(&expected);
	return NULL;
}


char *all_tests() {
	mu_suite_start();
	mu_run_test(test_CommandLineArgs_ParsingAll);
	return NULL;
}

RUN_TESTS(all_tests);
 
