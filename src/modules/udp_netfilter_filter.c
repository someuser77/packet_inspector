#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");

static struct nf_hook_ops nfho;
static struct iphdr *ip_header;

unsigned int hook_func(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state) {
	ip_header = (struct iphdr *)skb_network_header(skb);
	if (!skb) { 
		return  NF_ACCEPT; 
	}
	
	if (ip_header->protocol == IPPROTO_UDP) {
		printk(KERN_INFO "got udp packet in netfilter\n");
		return NF_DROP;
	}
	
	return NF_ACCEPT;
}

int init_module() {
	nfho.hook = hook_func;
	nfho.hooknum = NF_INET_POST_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_LAST;
	
	nf_register_hook(&nfho);
	printk(KERN_INFO "udp_netfilter_filter hook added\n");
	
	return 0;
}

void cleanup_module() {
	nf_unregister_hook(&nfho);
	printk(KERN_INFO "udp_netfilter_filter hook removed\n");
}