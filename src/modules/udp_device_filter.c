#include <linux/init.h> 
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/sock.h>

#define MODULE_NAME "udp_device_filter"

#include "utils.h"

MODULE_LICENSE("GPL");

static struct packet_type pt;
static struct iphdr *ip_header;

int packet_interceptor(struct sk_buff *skb,
    struct net_device *dev,
    struct packet_type *pt,
    struct net_device *orig_dev) {

	ip_header = (struct iphdr *)skb_network_header(skb);
	if (!skb) { 
		return  0;
	}
	
	if (ip_header->protocol == IPPROTO_UDP) {
		klog_info("got udp packet in device\n");
	}
	return 0;
}

static int __init init_udp_device_filter_module(void) {
	
	pt.type = htons(ETH_P_ALL);
	pt.dev = NULL;
	pt.func = packet_interceptor;
	
	dev_add_pack(&pt);
	
	klog_info("udp_device_filter added\n");
	return 0;
}

static void __exit cleanup_udp_device_filter_module(void) {
	dev_remove_pack(&pt);
	klog_info("udp_device_filter removed\n");
}

module_init(init_udp_device_filter_module);
module_exit(cleanup_udp_device_filter_module);