#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/sock.h>

#define MODULE_NAME "udp_device_filter"

#include "utils.h"

#include "filter_options.h"


// http://stackoverflow.com/questions/27755246/netlink-socket-creation-returns-null
MODULE_LICENSE("GPL");

static struct packet_type pt;
static struct sock *nl_sk = NULL;
static int enabled = 0;
static int pid = -1;
static int device_was_added = 0;
static int socket_was_created = 0;

static FilterOptions *filter_options;

static void nl_recv_msg(struct sk_buff *skb);
static struct netlink_kernel_cfg netlink_cfg = {
   .groups  = 1,
   .input = nl_recv_msg,
};


// http://linux-development-for-fresher.blogspot.co.il/2012/05/understanding-netlink-socket.html
// http://binwaheed.blogspot.co.il/2010/08/after-reading-kernel-source-i-finally.html
static void nl_recv_msg(struct sk_buff *skb) {
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	char *response = "ok";
	size_t responseLength = strlen(response) + 1;
	int sendResult;
	
	nlh = (struct nlmsghdr *)skb->data;
	pid = nlh->nlmsg_pid;
	klog_info("got a message from PID %d.\nMessage Length: %d\nData Length: %d\n", pid, nlh->nlmsg_len, nlh->nlmsg_len - NLMSG_HDRLEN);
	
	
	filter_options = FilterOptions_Deserialize(NLMSG_DATA(nlh), NLMSG_PAYLOAD(nlh,0));
	
	klog_info("FilterOptions were: %s", filter_options->description(filter_options));
	
	skb_out = nlmsg_new(responseLength, 0);
	if (skb_out == NULL) {
		klog_error("Failed to allocate new skb");
        return;
	}
	
	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, responseLength, 0);
	
	//NETLINK_CB(skb_out).dst_group = 0;
	memcpy(nlmsg_data(nlh), response, responseLength);
	
	sendResult = nlmsg_unicast(nl_sk, skb_out, pid);
	
	if (sendResult < 0) {
		klog_error("Error sending message to client. Error: %d", sendResult);
	}
	
	//nlmsg_free(skb_out); // nlmsg_unicast frees skb_out on error. No need to free.
	
	//enabled = 1;
	
	//klog_info("Sending is now enabled!");
}

int packet_interceptor(struct sk_buff *skb,
    struct net_device *dev,
    struct packet_type *pt,
    struct net_device *orig_dev) {
	
	struct iphdr *ip_header;
	struct sk_buff *skb_out;
	int data_length;
	char *buffer;
	int res;
	struct nlmsghdr *nlh;
	
	if (!skb) {
		return 0;
	}
	
	if (!enabled) {
		return 0;
	}
	
	if (skb_is_nonlinear(skb)){
		klog_warn("Dropped nonlinear packet.");
		return 0;
	}
	
	ip_header = (struct iphdr *)skb_network_header(skb);
	if (!ip_header) {
		return 0;
	}
	
	data_length = skb_headlen(skb);
	klog_info("Got a packet in device. Data Length: %d", data_length);
	
	buffer = kmalloc(data_length, GFP_KERNEL);
	if (skb_copy_bits(skb, 0, buffer, data_length) != 0) {
		klog_error("Error copying skb data into buffer.");
		goto cleanup;
	}
	
	skb_out = nlmsg_new(data_length, GFP_KERNEL);
	if (skb_out == NULL) {
		klog_error("nlmsg_new() failed");
		goto cleanup;
	}
	
	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, data_length, 0);
	NETLINK_CB(skb_out).dst_group = 0;
	memcpy(NLMSG_DATA(nlh), buffer, data_length);
	klog_info("Protocol: 0x%04x", ((struct ethhdr *)buffer)->h_proto);
	res = nlmsg_unicast(nl_sk, skb_out, pid);
	
    if (res < 0) {
        klog_info("Error while sending data to user");
	}
cleanup:
	kfree(buffer);
	return 0;
}

static int __init init_udp_device_filter_module(void) {
	
	pt.type = htons(ETH_P_ALL);
	pt.dev = NULL;
	pt.func = packet_interceptor;
	
	nl_sk = netlink_kernel_create(&init_net, 31, &netlink_cfg);

    // nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, 0, hello_nl_recv_msg,
    //                              NULL, THIS_MODULE);
    if (nl_sk == NULL)
    {
        klog_error("Error creating socket.\n");
        return -ENOMEM;
    }
	
	socket_was_created = 1;
	
	dev_add_pack(&pt);
	device_was_added = 1;
	
	klog_info("udp_device_filter added\n");
	return 0;
}

static void __exit cleanup_udp_device_filter_module(void) {
	if (device_was_added) {
		dev_remove_pack(&pt);
	}
	if (socket_was_created) {
		netlink_kernel_release(nl_sk);
	}
	klog_info("udp_device_filter removed\n");
}

module_init(init_udp_device_filter_module);
module_exit(cleanup_udp_device_filter_module);