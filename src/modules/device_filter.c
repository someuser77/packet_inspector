#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <linux/if_arp.h>
#include <linux/mutex.h>

#define MODULE_NAME "udp_device_filter"

#include "utils.h"
#include "filter_executer.h"
#include "filter_options.h"


// http://stackoverflow.com/questions/27755246/netlink-socket-creation-returns-null
MODULE_LICENSE("GPL");

static struct packet_type pt;
static struct sock *nl_sk = NULL;
static bool enabled = false;
static int device_was_added = 0;
static int socket_was_created = 0;
static int pid;
DEFINE_MUTEX(initializationLock);
static FilterExecuter *executer = NULL;

static void nl_recv_msg(struct sk_buff *skb);
static struct netlink_kernel_cfg netlink_cfg = {
   .groups  = 1,
   .input = nl_recv_msg,
};

static int sendResponseToClient(int pid, char *response){
	size_t length = strlen(response);
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out = nlmsg_new(length, 0);
	
	if (skb_out == NULL) {
		klog_error("Failed to allocate new skb");
        return -1;
	}
	
	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, length, 0);
	
	memcpy(nlmsg_data(nlh), response, length);
	
	return nlmsg_unicast(nl_sk, skb_out, pid);	
}

static void DuplicateInitialization(int pid) {
	klog_info("Got initialization message but already initialized.");
	sendResponseToClient(pid, "Already Initialized");
}

// http://linux-development-for-fresher.blogspot.co.il/2012/05/understanding-netlink-socket.html
// http://binwaheed.blogspot.co.il/2010/08/after-reading-kernel-source-i-finally.html
static void nl_recv_msg(struct sk_buff *skb) {
	FilterOptions *filterOptions;
	struct nlmsghdr *nlh;
	int messagePid;
	
	int sendResult;
	
	nlh = (struct nlmsghdr *)skb->data;
	messagePid	= nlh->nlmsg_pid;
	klog_info("got a message from PID %d.\nMessage Length: %d\nData Length: %d\n", messagePid, nlh->nlmsg_len, nlh->nlmsg_len - NLMSG_HDRLEN);
	
	if (enabled) {
		DuplicateInitialization(messagePid);
		return;
	}
	
	mutex_lock(&initializationLock);
	
	if (enabled) {
		DuplicateInitialization(messagePid);
		mutex_unlock(&initializationLock);
		return;
	}
	
	pid = messagePid;
	
	filterOptions = FilterOptions_Deserialize(NLMSG_DATA(nlh), NLMSG_PAYLOAD(nlh,0));
	
	klog_info("FilterOptions were: %s", filterOptions->description(filterOptions));
	
	executer = FilterExecuter_Create(filterOptions);
	
	sendResult = sendResponseToClient(pid, "ok");
	
	if (sendResult < 0) {
		klog_error("Error sending message to client. Error: %d", sendResult);
	}
	
	//nlmsg_free(skb_out); // nlmsg_unicast frees skb_out on error. No need to free.
	
	klog_info("Sending is now enabled!");
	
	enabled = true;
	
	mutex_unlock(&initializationLock);
}

int packet_interceptor(struct sk_buff *skb,  struct net_device *dev,  struct packet_type *pt, struct net_device *orig_dev) {	
	struct sk_buff *skb_out;
	int length;
	char *buffer;
	int res;
	struct nlmsghdr *nlh;
	struct net_device *device;
	
	if (!enabled) {
		return 0;
	}
	
	if (!skb) {
		klog_warn("SKB was null. Packet Dropped!");
		return 0;
	}
	
	if (!skb->dev) {
		klog_warn("SKB->Dev was null, Packet Dropped!");
		return 0;
	}
	
	//klog_info("Got a packet from device %s", skb->dev->name);
	
	device = skb->dev;
	
	if (device->type != ARPHRD_ETHER) {
		klog_warn("Got a non-ethernet packet %d. Packet Dropped!", device->type);
		return 0;
	}
	
	/*
	if (skb_is_nonlinear(skb)){
		klog_warn("Dropped nonlinear packet.");
		return 0;
	}
	*/
	
	if (executer == NULL) {
		klog_info("Executer was null.");
		return 0;
	}
	
	if (executer->matchAll == NULL) {
		klog_info("Executer->matchAll was null.");
		return 0;		
	}
	
	if (!executer->matchAll(executer, skb)) {
		return 0;
	}
	
	length = skb->len;
	
	klog_info("Got a packet. Length: %d", length);
	return 0;
	if ((buffer = vmalloc(length)) == NULL) {
		klog_error("Unable to allocate space for user-space tarnsfer of %d bytes.", length);
		return 0;
	}
	if (skb_copy_bits(skb, 0, buffer, length) != 0) {
		klog_error("Error copying skb data into buffer.");
		goto cleanup;
	}
	
	skb_out = nlmsg_new(length, GFP_KERNEL);
	if (skb_out == NULL) {
		klog_error("nlmsg_new() failed");
		goto cleanup;
	}
	
	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, length, 0);
	NETLINK_CB(skb_out).dst_group = 0;
	memcpy(NLMSG_DATA(nlh), buffer, length);
	res = nlmsg_unicast(nl_sk, skb_out, pid);
	
    if (res < 0) {
        klog_info("Error while sending data to user");
	}
	
cleanup:
	vfree(buffer);
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
        return -1;
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