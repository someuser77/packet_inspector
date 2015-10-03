#include <stdlib.h>
#include <stdio.h>
#include <linux/netlink.h>
#include <string.h>
#include <unistd.h>
#include "filter_client.h"

static const int NETLINK_USER = 31;

typedef struct FilterClientImpl {
	int socket_fd;
	struct sockaddr_nl destAddr;
	struct iovec iov;
} FilterClientImpl;

static inline FilterClientImpl *impl(FilterClient *fc) {
	return (FilterClientImpl *)fc->impl;
}

static int getSocket(struct FilterClient *self) {
	return impl(self)->socket_fd;
}

static bool buildSocket(struct FilterClient *self) {
	int socket_fd;
	socket_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (socket_fd < 0) {
		perror("socket(PF_NETLINK, SOCK_RAW, NETLINK_USER)");
        return false;
	}
	impl(self)->socket_fd = socket_fd;
	return true;
}

static bool bindToSourceAddress(struct FilterClient *self) {
	struct sockaddr_nl src_addr;
	memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    if (bind(getSocket(self), (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
		perror("bind()");
		return false;
	}
	return true;
}

static void fillDestinationAddress(struct FilterClient *self) {
	struct sockaddr_nl *destinationAddress = &impl(self)->destAddr;
	memset(destinationAddress, 0, sizeof(struct sockaddr_nl));
    destinationAddress->nl_family = AF_NETLINK;
    destinationAddress->nl_pid = 0; /* For Linux Kernel */
    destinationAddress->nl_groups = 0; /* unicast */
}

static size_t getPayloadSize(struct FilterOptions *filterOptions) {
	return filterOptions->serialize(filterOptions, NULL, 0);	
}

static struct nlmsghdr *createNetlinkMessageHeader(size_t payloadSize) {
	struct nlmsghdr *netlinkMessageHeader = (struct nlmsghdr *)malloc(NLMSG_SPACE(payloadSize));
    memset(netlinkMessageHeader, 0, NLMSG_SPACE(payloadSize));
    netlinkMessageHeader->nlmsg_len = NLMSG_SPACE(payloadSize);
    netlinkMessageHeader->nlmsg_pid = getpid();
    netlinkMessageHeader->nlmsg_flags = 0;
	return netlinkMessageHeader;
}

static bool setData(struct nlmsghdr *netlinkMessageHeader, struct FilterOptions *filterOptions) {
	size_t size = getPayloadSize(filterOptions);
	unsigned char *buffer = (unsigned char *)malloc(size);	
	if (filterOptions->serialize(filterOptions, buffer, size) < size) {
		free(buffer);
		return false;
	}
	memcpy(NLMSG_DATA(netlinkMessageHeader), buffer, size);
	free(buffer);
	return true;
}

static void fillIovc(struct FilterClient *self, struct nlmsghdr *nlh) {
	struct iovec *iov = &impl(self)->iov;
	memset(iov, 0, sizeof(struct iovec));
    iov->iov_base = (void *)nlh;
    iov->iov_len = nlh->nlmsg_len;
}

static void fillMsgHdr(struct FilterClient *self, struct msghdr *msg) {
	struct iovec *iov = &impl(self)->iov;
	struct sockaddr_nl *destinationAddress = &impl(self)->destAddr;
	memset(msg, 0, sizeof(struct msghdr));
    msg->msg_name = (void *)destinationAddress;
    msg->msg_namelen = sizeof(struct sockaddr_nl);
    msg->msg_iov = iov;
    msg->msg_iovlen = 1;
}

bool initialize(struct FilterClient *self, struct FilterOptions *filterOptions) {
	struct nlmsghdr *netlinkMessageHeader;
	const int MAX_RESPONSE_SIZE = 128;
	char *responseBuffer;
	ssize_t response_length;
	struct msghdr msg;
	
	if (!buildSocket(self))
		return false;
	
	if (!bindToSourceAddress(self))
		return false;
	
	fillDestinationAddress(self);
	
	netlinkMessageHeader = createNetlinkMessageHeader(getPayloadSize(filterOptions));
	
	setData(netlinkMessageHeader, filterOptions);
	
	fillIovc(self, netlinkMessageHeader);
	
	fillMsgHdr(self, &msg);
	printf("Sending Options...\n");
	if (sendmsg(getSocket(self), &msg, 0) < 0) {
        perror("sendmsg()");
		free(netlinkMessageHeader);
		return false;
    }
	
	free(netlinkMessageHeader);
	
	netlinkMessageHeader = createNetlinkMessageHeader(MAX_RESPONSE_SIZE);
	
	fillIovc(self, netlinkMessageHeader);
	printf("Waiting for response...\n");
    if ((response_length = recvmsg(getSocket(self), &msg, 0)) < 0) {
		perror("recvmsg()");
		free(netlinkMessageHeader);
		return false;
	}

	responseBuffer = (char *)malloc(MAX_RESPONSE_SIZE);
	memcpy(responseBuffer, NLMSG_DATA(netlinkMessageHeader), MAX_RESPONSE_SIZE);
	
	printf("Response: %s\n", responseBuffer);
	
	free(netlinkMessageHeader);
	free(responseBuffer);
	return true;
}

unsigned char *receive(struct FilterClient *self, size_t *size) {
	const size_t MAX_PAYLOAD = ETH_FRAME_LEN;
	struct nlmsghdr *netlinkMessageHeader;
	struct msghdr msg;
	unsigned char *buffer;
	ssize_t length;
	memset(&msg, 0, sizeof(struct msghdr));
	
	netlinkMessageHeader = createNetlinkMessageHeader(MAX_PAYLOAD);
	
	fillIovc(self, netlinkMessageHeader);
	
	memset(netlinkMessageHeader, 0, NLMSG_SPACE(MAX_PAYLOAD));
	
	fillMsgHdr(self, &msg);
	
	recvmsg(getSocket(self), &msg, 0);
	
	length = netlinkMessageHeader->nlmsg_len - NLMSG_HDRLEN;
	
	buffer = (unsigned char *)malloc(length);
	
	memcpy(buffer, NLMSG_DATA(netlinkMessageHeader), length);
	
	free(netlinkMessageHeader);
	
	*size = length;
	
	return buffer;
}

void destroy(struct FilterClient *self) {
	free(self->impl);
}

FilterClient *FilterClient_Create() {
	FilterClient *filterClient;
	filterClient = (FilterClient *)malloc(sizeof(FilterClient));
	filterClient->impl = (FilterClientImpl *)malloc(sizeof(FilterClientImpl));
	filterClient->initialize = initialize;
	filterClient->receive = receive;
	filterClient->destroy = destroy;
	
	return filterClient;
}
 
