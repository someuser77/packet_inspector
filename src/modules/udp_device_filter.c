#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/sock.h>

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
		printk(KERN_INFO "got udp packet in device\n");
	}
	return 0;
}

int init_module() {
	
	pt.type = htons(ETH_P_ALL);
	pt.dev = NULL;
	pt.func = packet_interceptor;
	
	dev_add_pack(&pt);
	printk(KERN_INFO "udp_device_filter added\n");
	
	return 0;
}

void cleanup_module() {
	dev_remove_pack(&pt);
	printk(KERN_INFO "udp_device_filter removed\n");
}