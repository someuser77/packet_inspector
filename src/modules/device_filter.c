#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <linux/if_arp.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

#define MODULE_NAME "packet_device_filter"

#include "utils.h"
#include "filter_executer.h"
#include "filter_options.h"


// http://stackoverflow.com/questions/27755246/netlink-socket-creation-returns-null
MODULE_LICENSE("GPL");

static const int NETLINK_USER = 31;

int packet_interceptor(struct sk_buff *skb,  struct net_device *dev,  struct packet_type *pt, struct net_device *orig_dev);

static struct packet_type pt = {
	.type = htons(ETH_P_ALL), // cannot use ETH_P_IP because then skb will not hold ETH header.
	.dev = NULL,
	.func = packet_interceptor
};
static struct sock *nl_sk = NULL;
static bool initialized = false;
static bool promiscuitySet = false;
DEFINE_SPINLOCK(packetProcessing);
static int pid;
DEFINE_MUTEX(initializationLock);
static FilterExecuter *executer = NULL;

static void nl_recv_msg(struct sk_buff *skb);
static struct netlink_kernel_cfg netlink_cfg = {
   .groups  = 1,
   .input = nl_recv_msg,
};

static void logContextInfo(void) __attribute__ ((unused));
static void logContextInfo(void) {
	klog_info("in_irq? %lu in_softirq? %lu in_interrupt? %lu in_serving_softirq? %lu", in_irq(), in_softirq(), in_interrupt(), in_serving_softirq());
}

static const char * const getPacketTypeDescription(unsigned char pktType) {
	static const char * const pktTypes[] = {
		"PACKET_HOST",
		"PACKET_BROADCAST",
		"PACKET_MULTICAST",
		"PACKET_OTHERHOST",
		"PACKET_OUTGOING",
		"PACKET_LOOPBACK",
		"PACKET_USER",
		"PACKET_KERNEL",
		"PACKET_FASTROUTE"
	};
	return pktTypes[pktType];
}

void print_ethernet_header(struct ethhdr *eth) __attribute__ ((unused));
void print_ethernet_header(struct ethhdr *eth)
{     
    printk(KERN_INFO "Ethernet Header:\n"
    "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n"
    "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n"
    "   |-Protocol            : %u \n",
	eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5],
	eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5],
	(unsigned short)eth->h_proto);
}

static struct net_device *getConfiguredNetDevice(struct FilterOptions *filterOptions) {
	struct net_device *device;
	char deviceName[IFNAMSIZ] = {0};
	int deviceNameLength;
		
	if (!filterOptions->isDeviceSet(filterOptions))
		return NULL;
	
	if ((deviceNameLength = filterOptions->getDevice(filterOptions, deviceName)) <= 0) {
		klog_error("Error reading device name from FilterOptions. Result was %d", deviceNameLength);
		return NULL;
	}
	
	device = dev_get_by_name(&init_net, deviceName);
	
	if (device == NULL) {
		klog_warn("No matching device with name %s was found.", deviceName);
		return NULL;
	}
	
	rtnl_lock();
	klog_info("Setting device %s to promiscuous mode.", device->name);
	if (dev_set_promiscuity(device, 1) != 0) {
		klog_warn("Failed setting device %s to promiscuous mode.", device->name);
		promiscuitySet = false;
	} else {
		promiscuitySet = true;
	}
	
	rtnl_unlock();
	
	return device;
}

static int sendResponseToClient(int pid, void *buffer, size_t length) {
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out = nlmsg_new(length, 0);
	
	if (skb_out == NULL) {
		klog_error("Failed to allocate new skb");
        return -1;
	}
	
	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, length, 0);
	NETLINK_CB(skb_out).dst_group = 0;
	memcpy(nlmsg_data(nlh), buffer, length);
	//klog_info("Sending %zu bytes of response to client...", length);
	return nlmsg_unicast(nl_sk, skb_out, pid);	
}

static int sendTextResponseToClient(int pid, char *response){
	int sendResult;
	
	klog_info("%s", response);
	
	sendResult = sendResponseToClient(pid, response, strlen(response));
	
	if (sendResult < 0) {
		klog_error("Error sending message '%s' to client %d. Error: %d", response, pid, sendResult);
	}
	
	return sendResult;
}

static void initialize(struct FilterOptions *filterOptions) {	
	executer = FilterExecuter_Create(filterOptions);
	//memset(&pt, 0, sizeof(struct packet_type));
	pt.dev = getConfiguredNetDevice(filterOptions);
	dev_add_pack(&pt);
	
	klog_info("packet_device_filter added\n");
	
	sendTextResponseToClient(pid, "ok");	
	klog_info("Sending is now enabled!");	
	initialized = true;
}

static void shutdown(void) {

	sendTextResponseToClient(pid, "shutdown");
	klog_info("Shutting down!");
	
	spin_lock(&packetProcessing);
	
	initialized = false;
	executer->destroy(executer);
	executer = NULL;
	
	spin_unlock(&packetProcessing);
	
	if (pt.dev != NULL) {
		
		if (promiscuitySet) {
			rtnl_lock();
			dev_set_promiscuity(pt.dev, -1);
			rtnl_unlock();
		}
		// dev_get_by_name was called so dev_put must be called.
		dev_put(pt.dev);
		
	}
	
	dev_remove_pack(&pt);
	
	klog_info("packet_device_filter removed\n");
	
}

static void uninitializedShutdown(int pid) {
	sendTextResponseToClient(pid, "Got shutdown message but wasn't initialized.");
}

static void duplicateInitialization(int pid) {
	sendTextResponseToClient(pid, "Got initialization message but already initialized.");
}

static bool handleEdgeCases(FilterOptions *filterOptions, int pid){
	
	if (!initialized && filterOptions->isShutdownSet(filterOptions)) {
		uninitializedShutdown(pid);
		return true;
	}
	
	if (initialized && !filterOptions->isShutdownSet(filterOptions)) {
		duplicateInitialization(pid);
		return true;
	}
	
	return false;
}

// http://linux-development-for-fresher.blogspot.co.il/2012/05/understanding-netlink-socket.html
// http://binwaheed.blogspot.co.il/2010/08/after-reading-kernel-source-i-finally.html
static void nl_recv_msg(struct sk_buff *skb) {
	FilterOptions *filterOptions;
	struct nlmsghdr *nlh;
	int messagePid;
	
	nlh = (struct nlmsghdr *)skb->data;
	messagePid	= nlh->nlmsg_pid;
	klog_info("got a message from Client: %d. Message Length: %d Data Length: %d.", messagePid, nlh->nlmsg_len, nlh->nlmsg_len - NLMSG_HDRLEN);
	
	//logContextInfo();
	
	filterOptions = FilterOptions_Deserialize(NLMSG_DATA(nlh), NLMSG_PAYLOAD(nlh,0));
	
	klog_info("FilterOptions were: %s", filterOptions->description(filterOptions));
	
	mutex_lock(&initializationLock);
	
	if (handleEdgeCases(filterOptions, messagePid))
		goto release;
	
	pid = messagePid;
	
	if (!filterOptions->isShutdownSet(filterOptions)) {
		
		initialize(filterOptions);
		
	} else {
		
		shutdown();
		
	}

release:
	vfree(filterOptions);
	
	// http://stackoverflow.com/questions/10138848/kernel-crash-when-trying-to-free-the-skb-with-nlmsg-freeskb-out
	//nlmsg_free(skb_out); // nlmsg_unicast frees skb_out on error. No need to free.
	
	mutex_unlock(&initializationLock);
}

int packet_interceptor(struct sk_buff *skb,  struct net_device *dev,  struct packet_type *pt, struct net_device *orig_dev) {	
	//struct sk_buff *skb_out;
	size_t length;
	unsigned char *buffer;
	int res;
	//struct nlmsghdr *nlh;
	struct net_device *device;
	bool match;
	
	if (!initialized) {
		klog_info("Dropped packet on device %s because we were not initialized.", skb->dev->name);
		goto free_skb;
	}
	
	if (!skb->dev) {
		klog_warn("SKB->Dev was null, Packet Dropped!");
		goto free_skb;
	}
	
	//klog_info("Got a packet from device %s", skb->dev->name);
	
	spin_lock(&packetProcessing);
	
	device = skb->dev;
	
	if (device->type != ARPHRD_ETHER) {
		klog_warn("Got a packet on non-ethernet device. %d. Packet Dropped!", device->type);
		goto unlock_and_free_skb;
	}
	
	if (skb->pkt_type == PACKET_LOOPBACK) {
		klog_info("Dropped loopback packet.");
		goto unlock_and_free_skb;
	}
	
	if (skb->pkt_type == PACKET_HOST) {
		// the ethernet header is missing on host packets.
	}
	
	if (skb->pkt_type == PACKET_OUTGOING) {
		//print_ethernet_header((struct ethhdr *)skb->data);
		//skb_push(skb, skb_network_offset(skb));
		//skb_push(skb, ETH_HLEN);
		
		// this fixed mac_len but everything else is still broken.
		skb_set_mac_header(skb, 0);
		skb_set_network_header(skb, ETH_HLEN);
		skb_reset_mac_len(skb);
		//skb_push(skb, ETH_HLEN);
		
		//skb_reset_mac_header(skb);
		//skb_reset_mac_len(skb);
		//skb_push(skb, ETH_HLEN);
		//skb_pull(skb, ETH_HLEN);
		//skb_reset_mac_header(skb);
	}
	
	if (skb_mac_header(skb) < skb->head) {
		klog_error("BAD MAC HDR: skb_mac_header(skb) < skb->head");
	} else
	if (skb_mac_header(skb) + ETH_HLEN > skb->data)
		klog_error("Bad mac header on %s mac_len: %d nohdr: %d skb_mac_header(skb) + ETH_HLEN > skb->data", getPacketTypeDescription(skb->pkt_type), skb->mac_len, skb->nohdr);
	
	//skb_reset_mac_header(skb);
	//print_ethernet_header(eth_hdr(skb));
	
	/*
	if (skb_is_nonlinear(skb)){
		klog_warn("Dropped nonlinear packet.");
		return 0;
	}
	*/
		
	// executer might be released while inside softirq?
	
	if (!initialized){
		goto unlock_and_free_skb;
	}
	
	match = executer->matchAll(executer, skb);
	//klog_info("Got a packet that %s.", match ? "matched" : "didn't match");
	
	
	if (!match) {
		klog_info("Didn't match %s packet size %d mac_len %d.",  getPacketTypeDescription(skb->pkt_type), skb->len, skb->mac_len);
		goto unlock_and_free_skb;
	}
	
	length = skb->len;

	klog_info(
		"Matched a %s packet going [%d:%s]. Length: %zu.", 
		skb_is_nonlinear(skb) ? "nonlinear" : "linear",
		skb->pkt_type, 
		getPacketTypeDescription(skb->pkt_type),
		length
	);
	
	//logContextInfo();
	
	// this handler runs in softirq context so we can't use vmalloc or kmalloc with GFP_KERNEL because
	// it may sleep locking up the kernel.
	if ((buffer = kmalloc(length, GFP_ATOMIC)) == NULL) {
		klog_error("Unable to allocate space for user-space tarnsfer of %zu bytes.", length);
		goto unlock_and_free_skb;
	}
	
	if (skb_copy_bits(skb, 0, buffer, length) != 0) {
		klog_error("Error copying skb data into buffer.");
		goto free_buffer_unlock_and_free_skb;
	}
	
	klog_info("First byte of data to client is: %02X", buffer[0]);
	
	res = sendResponseToClient(pid, buffer, length);
	
    if (res < 0) {
        klog_info("Error while sending data to user");
	}
	
free_buffer_unlock_and_free_skb:
	kfree(buffer);
	
unlock_and_free_skb:
	spin_unlock(&packetProcessing);
	
free_skb:
	kfree_skb(skb);
	
	return 0;
}

static int __init init_packet_device_filter_module(void) {
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &netlink_cfg);

    // nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, 0, hello_nl_recv_msg,
    //                              NULL, THIS_MODULE);
    if (nl_sk == NULL)
    {
        klog_error("Error creating socket.\n");
        return -1;
    }

	return 0;
}

static void __exit cleanup_packet_device_filter_module(void) {
	if (nl_sk != NULL) {
		netlink_kernel_release(nl_sk);
	}
}

module_init(init_packet_device_filter_module);
module_exit(cleanup_packet_device_filter_module);