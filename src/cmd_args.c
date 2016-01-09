#include <stdio.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <string.h>
#include "lib/directional_filter_options.h"
#include "lib/utils.h"

enum {
	Option_None = 258,
	
	Option_List_Devices,
	
	Option_Device,
	Option_Protocol,
	Option_EtherType,
	Option_Help,
	
	Option_Incoming_SrcMac,
	Option_Incoming_DstMac,
	Option_Incoming_SrcIp,
	Option_Incoming_DstIp,
	Option_Incoming_SrcIp6,
	Option_Incoming_DstIp6,
	Option_Incoming_SrcPort,
	Option_Incoming_DstPort,
	
	Option_Outgoing_SrcMac,
	Option_Outgoing_DstMac,
	Option_Outgoing_SrcIp,
	Option_Outgoing_DstIp,
	Option_Outgoing_SrcIp6,
	Option_Outgoing_DstIp6,
	Option_Outgoing_SrcPort,
	Option_Outgoing_DstPort,
	
	Option_Total
};

static struct option long_options[] = {
	{"list-devices", required_argument, 0, Option_List_Devices},
	{"device", required_argument, 0, Option_Device},
	{"protocol", required_argument, 0, Option_Protocol},
	{"ether-type", required_argument, 0, Option_EtherType},
	{"help", no_argument, 0, Option_Help},
	
	{"incoming-src-mac", required_argument, 0, Option_Incoming_SrcMac}, 
	{"incoming-dst-mac", required_argument, 0, Option_Incoming_DstMac},
	{"incoming-src-ip", required_argument, 0, Option_Incoming_SrcIp},
	{"incoming-dst-ip", required_argument, 0, Option_Incoming_DstIp},
	{"incoming-src-ip6", required_argument, 0, Option_Incoming_SrcIp6},
	{"incoming-dst-ip6", required_argument, 0, Option_Incoming_DstIp6},
	{"incoming-src-port", required_argument, 0, Option_Incoming_SrcPort},
	{"incoming-dst-port", required_argument, 0, Option_Incoming_DstPort},
	
	{"outgoing-src-mac", required_argument, 0, Option_Outgoing_SrcMac}, 
	{"outgoing-dst-mac", required_argument, 0, Option_Outgoing_DstMac},
	{"outgoing-src-ip", required_argument, 0, Option_Outgoing_SrcIp},
	{"outgoing-dst-ip", required_argument, 0, Option_Outgoing_DstIp},
	{"outgoing-src-ip6", required_argument, 0, Option_Outgoing_SrcIp6},
	{"outgoing-dst-ip6", required_argument, 0, Option_Outgoing_DstIp6},
	{"outgoing-src-port", required_argument, 0, Option_Outgoing_SrcPort},
	{"outgoing-dst-port", required_argument, 0, Option_Outgoing_DstPort},
	
	{0, 0, 0, 0}
};

static char *long_options_description[] = {
	"List the available devices.",
	"Device to capture.",
	"Protocol to capture.",
	"Ethernet type to capture",
	"Display this help screen",
	
	"Source MAC of incoming packets",
	"Destination MAC of incoming packets",
	"Source IP of incoming packets",
	"Destination IP of incoming packets",
	"Source IPv6 of incoming packets",
	"Destination IPv6 of incoming packets",
	"Source Port of incoming packets",
	"Destination Port of incoming packets",
	
	"Source MAC of outgoing packets",
	"Destination MAC of outgoing packets",
	"Source IP of outgoing packets",
	"Destination IP of outgoing packets",
	"Source IPv6 of outgoing packets",
	"Destination IPv6 of outgoing packets",
	"Source Port of outgoing packets",
	"Destination Port of outgoing packets"
};

static void displayUsage(void) {
	int i;
	printf("\n");
	for (i = 0; i < Option_Total - Option_None - 1; i++) {
		printf("--%s\t\t%s\n", long_options[i].name, long_options_description[i]);
	}
	printf("\n");
}

static bool parseMac(char *macStr, unsigned char mac[ETH_ALEN]) {
	int i;
	char c;
	unsigned int iMac[ETH_ALEN];
	int matched = sscanf(macStr, "%x:%x:%x:%x:%x:%x%c", &iMac[0], &iMac[1], &iMac[2], &iMac[3], &iMac[4], &iMac[5], &c);
	
	if (matched != ETH_ALEN) return false;
	
	for(i=0 ; i < ETH_ALEN; i++)
		if (iMac[i] > 256) 
			return false;
		else
			mac[i] = (unsigned char)iMac[i];
	
	return true;
}

DirectionalFilterOptions *parseCommandLineArguments(int argc, char *argv[]) {
	int opt, long_index, port;
	
	DirectionalFilterOptions *options = NULL;
	FilterOptions *incoming, *outgoing;
	
	int protocol;
	unsigned char mac[ETH_ALEN];
	uint32_t ip;
	unsigned char ip6[IP6_ALEN];
	
	incoming = FilterOptions_Create();
	outgoing = FilterOptions_Create();
	
	if (argc == 1) {
		displayUsage();
		return NULL;
	}
	
	while ((opt = getopt_long_only(argc, argv, "", long_options, &long_index)) != -1) {
		switch (opt) {
			case Option_Device:
				incoming->setDevice(incoming, optarg, strlen(optarg));
				outgoing->setDevice(outgoing, optarg, strlen(optarg));
				break;
			
			case Option_Protocol:
				if (strcmp(optarg, "tcp") == 0) {
					protocol = IPPROTO_TCP;
				} 
				else if (strcmp(optarg, "udp") == 0) {
					protocol = IPPROTO_UDP;
				}
				else if (strcmp(optarg, "icmp") == 0) {
					protocol = IPPROTO_ICMP;
				}
				else {
					log_error("Unsupported value for protocol: %s", optarg);
					goto failure;
				}
				
				incoming->setProtocol(incoming, protocol);
				outgoing->setProtocol(outgoing, protocol);
	
				break;
				
			case Option_EtherType:
				if (strcmp(optarg, "ip") != 0) {
					log_error("Unsupported value for ethernet type: %s", optarg);
					goto failure;
				}
				incoming->setEtherType(incoming, ETH_P_IP);
				outgoing->setEtherType(outgoing, ETH_P_IP);
				break;
///// INCOMING
			case Option_Incoming_SrcMac:
				if (!parseMac(optarg, mac)) {
					log_error("Error parsing mac address %s\n", optarg);
					goto failure;
				}
				incoming->setSrcMac(incoming, mac);
				break;
				
			case Option_Incoming_DstMac:
				if (!parseMac(optarg, mac)) {
					log_error("Error parsing mac address %s", optarg);
					goto failure;
				}
				incoming->setDstMac(incoming, mac);
				break;
				
			case Option_Incoming_SrcIp:
				if (inet_pton(AF_INET, optarg, &ip) != 1) {
					log_error("Error parsing ip address %s", optarg);
					goto failure;
				}
				incoming->setSrcIp(incoming, ntohl(ip));
				break;
				
			case Option_Incoming_DstIp:
				if (inet_pton(AF_INET, optarg, &ip) != 1) {
					log_error("Error parsing ip address %s", optarg);
					goto failure;
				}
				incoming->setDstIp(incoming, ntohl(ip));
				break;
				
			case Option_Incoming_SrcIp6:
				if (inet_pton(AF_INET6, optarg, &ip6) !=1) {
					log_error("Error parsing ip6 address %s", optarg);
					goto failure;
				}
				incoming->setSrcIp6(incoming, ip6);
				break;
				
			case Option_Incoming_DstIp6:
				if (inet_pton(AF_INET6, optarg, &ip6) !=1) {
					log_error("Error parsing ip6 address %s", optarg);
					goto failure;
				}
				incoming->setDstIp6(incoming, ip6);					
				break;
				
			case Option_Incoming_SrcPort:
				port = atoi(optarg);
				if (port == 0) {
					log_error("Error parsing port %s.", optarg);
					goto failure;
				}
				incoming->setSrcPort(incoming, atoi(optarg));
				break;
			
			case Option_Incoming_DstPort:	
				port = atoi(optarg);
				if (port == 0) {
					log_error("Error parsing port %s.", optarg);
					goto failure;
				}
				incoming->setDstPort(incoming, atoi(optarg));
				break;
///// OUTGOING				
			case Option_Outgoing_SrcMac:
				if (!parseMac(optarg, mac)) {
					log_error("Error parsing mac address %s\n", optarg);
					goto failure;
				}
				outgoing->setSrcMac(outgoing, mac);
				break;
				
			case Option_Outgoing_DstMac:
				if (!parseMac(optarg, mac)) {
					log_error("Error parsing mac address %s", optarg);
					goto failure;
				}
				outgoing->setDstMac(outgoing, mac);
				break;
				
			case Option_Outgoing_SrcIp:
				if (inet_pton(AF_INET, optarg, &ip) != 1) {
					log_error("Error parsing ip address %s", optarg);
					goto failure;
				}
				outgoing->setSrcIp(outgoing, ntohl(ip));
				break;
				
			case Option_Outgoing_DstIp:
				if (inet_pton(AF_INET, optarg, &ip) != 1) {
					log_error("Error parsing ip address %s", optarg);
					goto failure;
				}
				outgoing->setDstIp(outgoing, ntohl(ip));
				break;
				
			case Option_Outgoing_SrcIp6:
				if (inet_pton(AF_INET6, optarg, &ip6) !=1) {
					log_error("Error parsing ip6 address %s", optarg);
					goto failure;
				}
				outgoing->setSrcIp6(outgoing, ip6);
				break;
				
			case Option_Outgoing_DstIp6:
				if (inet_pton(AF_INET6, optarg, &ip6) !=1) {
					log_error("Error parsing ip6 address %s", optarg);
					goto failure;
				}
				outgoing->setDstIp6(outgoing, ip6);					
				break;
				
			case Option_Outgoing_SrcPort:
				port = atoi(optarg);
				if (port == 0) {
					log_error("Error parsing port %s.", optarg);
					goto failure;
				}
				outgoing->setSrcPort(outgoing, atoi(optarg));
				break;
			
			case Option_Outgoing_DstPort:	
				port = atoi(optarg);
				if (port == 0) {
					log_error("Error parsing port %s.", optarg);
					goto failure;
				}
				outgoing->setDstPort(outgoing, atoi(optarg));
				break;
			

			case Option_Help:
			case '?':
				displayUsage();
				break;
			default:
				log_error ("?? getopt returned character code 0%o ??\n", opt);
		}
	}
	
	options = DirectionalFilterOptions_Create();
	options->setIncomingFilterOptions(options, incoming);
	options->setOutgoingFilterOptions(options, outgoing);
	goto end;
failure:	
	FilterOptions_Destroy(&incoming);
	FilterOptions_Destroy(&outgoing);
end:
	return options;
}	
