#include <stdlib.h>
#include <stdio.h>
#include <linux/netlink.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <sys/signalfd.h>
#include "filter_client.h"

static const int NETLINK_USER = 31;
static const int SOCKET_FD_INDEX = 0;
static const int SIGNAL_FD_INDEX = 1;
	
typedef struct FilterClientImpl {
	int socket_fd;
	int signal_fd;
	int nfds;
	struct pollfd *pfds;
	struct sockaddr_nl destAddr;
	struct iovec iov;
} FilterClientImpl;

static inline FilterClientImpl *impl(FilterClient *self) {
	return (FilterClientImpl *)self->impl;
}

static int getSocket(struct FilterClient *self) {
	return impl(self)->socket_fd;
}

static struct pollfd *getSocketPollFd(FilterClient *self) {
	return &impl(self)->pfds[SOCKET_FD_INDEX];
}

static struct pollfd *getSignalPollFd(FilterClient *self) {
	return &impl(self)->pfds[SIGNAL_FD_INDEX];
}

static void buildPollDescriptors(struct FilterClient *self) {
	const int nfds = 2;
	
	struct pollfd *pfds;
	
	pfds = (struct pollfd *)malloc(sizeof(struct pollfd) * impl(self)->nfds);
	
	pfds[SOCKET_FD_INDEX].fd = impl(self)->socket_fd;
	pfds[SOCKET_FD_INDEX].events = POLLIN | POLLERR | POLLHUP;
	
	pfds[SIGNAL_FD_INDEX].fd = impl(self)->signal_fd;
	pfds[SIGNAL_FD_INDEX].events = POLLIN | POLLERR | POLLHUP;
	
	impl(self)->nfds = nfds;
	impl(self)->pfds = pfds;
}

static bool buildSignalHandler(struct FilterClient *self) {
	int signal_fd;
	unsigned int i;
	sigset_t sigset;
	int sigs[] = {SIGHUP, SIGINT, SIGTERM};
	
	if (sigemptyset(&sigset) != 0) {
		perror("sigemptyset()");
		return false;
	}
	
	for (i = 0; i < sizeof(sigs)/sizeof(sigs[0]); i++) {			
		if (sigaddset(&sigset, sigs[i]) != 0) {
			fprintf(stderr, "Error calling sigaddset for %s: %s\n", strsignal(sigs[i]), strerror(errno));
			return false;
		}
	}
	
	if (sigprocmask(SIG_BLOCK, &sigset, NULL) != 0) {
		perror("sigprocmask()");
		return false;
	}
	
	if ((signal_fd = signalfd(-1, &sigset, 0)) == -1) {
		perror("signalfd()");
		return false;
	}
	
	impl(self)->signal_fd = signal_fd;
	
	return true;
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

static size_t getPayloadSize(DirectionalFilterOptions *options) {
	return options->serialize(options, NULL, 0);	
}

static struct nlmsghdr *createNetlinkMessageHeader(size_t payloadSize) {
	struct nlmsghdr *netlinkMessageHeader = (struct nlmsghdr *)malloc(NLMSG_SPACE(payloadSize));
    memset(netlinkMessageHeader, 0, NLMSG_SPACE(payloadSize));
    netlinkMessageHeader->nlmsg_len = NLMSG_SPACE(payloadSize);
    netlinkMessageHeader->nlmsg_pid = getpid();
    netlinkMessageHeader->nlmsg_flags = 0;
	return netlinkMessageHeader;
}

static bool setData(struct nlmsghdr *netlinkMessageHeader, DirectionalFilterOptions *options) {
	size_t size = getPayloadSize(options);
	unsigned char *buffer = (unsigned char *)malloc(size);	
	if (options->serialize(options, buffer, size) < size) {
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

static bool sendFilterOptions(struct FilterClient *self, DirectionalFilterOptions *options) {
	struct nlmsghdr *netlinkMessageHeader;
	const int MAX_RESPONSE_SIZE = 128;
	char *responseBuffer;
	ssize_t response_length;
	struct msghdr msg;
	
	netlinkMessageHeader = createNetlinkMessageHeader(getPayloadSize(options));
	
	setData(netlinkMessageHeader, options);
	
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

bool initialize(FilterClient *self, DirectionalFilterOptions *options) {

	if (!buildSocket(self))
		return false;
	
	if (!buildSignalHandler(self))
		return false;
	
	if (!bindToSourceAddress(self))
		return false;
	
	buildPollDescriptors(self);
	
	fillDestinationAddress(self);
	
	return sendFilterOptions(self, options);
}

static bool isTerminationSignal(struct FilterClient *self) {
	struct signalfd_siginfo info;
	ssize_t bytes;
	bytes = read(impl(self)->signal_fd, &info, sizeof(struct signalfd_siginfo));
	if (bytes != sizeof(struct signalfd_siginfo)) {
		fprintf(stderr, "Error reading signal data. Got only %zu bytes instead of the expected %zu bytes.", bytes, sizeof(struct signalfd_siginfo));
		return false;
	}

	unsigned sig = info.ssi_signo;

	switch (sig) {
		case SIGINT:
		case SIGHUP:
		case SIGTERM:
			return true;
		default:
			return false;
	}
}

static unsigned char *handleIncomingPacket(struct FilterClient *self, size_t *size) {
	const size_t MAX_PAYLOAD = ETH_FRAME_LEN;
	struct nlmsghdr *netlinkMessageHeader;
	struct msghdr msg;
	unsigned char *buffer;
	ssize_t length;
	ssize_t received;
	
receive:
	memset(&msg, 0, sizeof(struct msghdr));
	
	netlinkMessageHeader = createNetlinkMessageHeader(MAX_PAYLOAD);
	
	fillIovc(self, netlinkMessageHeader);
	
	memset(netlinkMessageHeader, 0, NLMSG_SPACE(MAX_PAYLOAD));
	
	fillMsgHdr(self, &msg);
	
	received = recvmsg(getSocket(self), &msg, 0);
	
	if (received == -1) {
		perror("recvmsg()");
		goto receive;
	}
	
	if (received == 0) {
		// shutdown
		printf("Got 0 bytes. Quitting.");
		return NULL;
	}
	
	if (netlinkMessageHeader->nlmsg_len < NLMSG_HDRLEN) {
		printf("Message length %zd was shorter than NLMSG_HDRLEN %zd.\n", netlinkMessageHeader->nlmsg_len, NLMSG_HDRLEN);
		goto receive;
	}
	
	length =  netlinkMessageHeader->nlmsg_len - NLMSG_HDRLEN;
	
	printf("\nTrying to read %zd bytes...\n", length);
	
	buffer = (unsigned char *)malloc(length);
	if (!buffer) {
		printf("Error allocating %zd bytes for incoming packet.", length);
		return NULL;
	}
	
	memcpy(buffer, NLMSG_DATA(netlinkMessageHeader), length);
	
	free(netlinkMessageHeader);
	
	*size = length;
	
	return buffer;
}

unsigned char *receive(struct FilterClient *self, size_t *size) {
	struct pollfd *pfd;
	int pollResult;
	while (true) {
		pollResult = poll(impl(self)->pfds, impl(self)->nfds, -1);
		
		if (pollResult < 0) {
			perror("poll()");
			return NULL;
		}
		
		pfd = getSocketPollFd(self);
		
		if (pfd->revents & POLLIN) {
			return handleIncomingPacket(self, size);
		}
		
		if (pfd->revents & POLLHUP) {
			printf("Disconnected.\n");
			return NULL;
		}
		
		if (pfd->revents & POLLERR) {
			printf("Error.\n");
			return NULL;
		}
		
		pfd = getSignalPollFd(self);
		
		if (pfd->revents & POLLIN) {
			if (isTerminationSignal(self))
				return NULL;
		}
		
		if (pfd->revents & POLLERR) {
			printf("Error.\n");
			return NULL;
		}

		if (pfd->revents & POLLHUP){
			printf("Disconnected.\n");
			return NULL;
		}
		
		printf("Error. Poll returned nothing useful.");
	}
}

void destroy(struct FilterClient *self) {
	DirectionalFilterOptions *options = DirectionalFilterOptions_Create();
	FilterOptions *filterOptions = FilterOptions_Create();
	filterOptions->setShutdown(filterOptions);
	
	options->setIncomingFilterOptions(options, filterOptions);
	options->setOutgoingFilterOptions(options, filterOptions);
	
	sendFilterOptions(self, options);
	
	DirectionalFilterOptions_Destroy(&options);
	free(impl(self)->pfds);
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
 
