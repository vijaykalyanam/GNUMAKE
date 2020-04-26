#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <getopt.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <libgen.h>
#include <locale.h>
#include <errno.h>            // errno, perror()


#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <netdb.h>            // struct addrinfo
#include <netinet/in.h>       // IPPROTO_RAW, INET_ADDRSTRLEN
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806
#include <linux/ip.h> 
#include <linux/udp.h>
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

/* ARP protocol opcodes. */
#define ARPOP_REQUEST   1               /* ARP request                  */
#define ARPOP_REPLY     2               /* ARP reply                    */
#define ARPOP_RREQUEST  3               /* RARP request                 */
#define ARPOP_RREPLY    4               /* RARP reply                   */
#define ARPOP_InREQUEST 8               /* InARP request                */
#define ARPOP_InREPLY   9               /* InARP reply                  */
#define ARPOP_NAK       10              /* (ATM)ARP NAK                 */

/* The sockaddr_ll is a device independent physical layer address. */
#if 0
struct sockaddr_ll {
	unsigned short sll_family;   /* Always AF_PACKET */
	unsigned short sll_protocol; /* Physical layer protocol */
	int            sll_ifindex;  /* Interface number */
	unsigned short sll_hatype;   /* ARP hardware type */
	unsigned char  sll_pkttype;  /* Packet type */
	unsigned char  sll_halen;    /* Length of address */
	unsigned char  sll_addr[8];  /* Physical layer address */
};
#endif


/*
 *      This structure defines an ethernet arp header.
 */

struct arphdr {
        __be16          ar_hrd;         /* format of hardware address   */
        __be16          ar_pro;         /* format of protocol address   */
        unsigned char   ar_hln;         /* length of hardware address   */
        unsigned char   ar_pln;         /* length of protocol address   */
        __be16          ar_op;          /* ARP opcode (command)         */

	/* This section is commented out in default header file */
#if 1 
         /*
          *      Ethernet looks like this : This bit is variable sized however...
          */
        unsigned char           ar_sha[ETH_ALEN];       /* sender hardware address      */
        unsigned char           ar_sip[4];              /* sender IP address            */
        unsigned char           ar_tha[ETH_ALEN];       /* target hardware address      */
        unsigned char           ar_tip[4];              /* target IP address            */
#endif
} __attribute__((packed));

struct arp_packet {
	/* ETHHDR */
	struct ethhdr ethh;
	/*ARP HDR */
	struct arphdr arph;
	unsigned char padding[32];
} __attribute__((packed));

#if 0
#define ETH_P_IP        0x0800          /* Internet Protocol packet     */
#define ETH_P_ARP       0x0806          /* Address Resolution packet    */
struct ethhdr {
        unsigned char   h_dest[ETH_ALEN];       /* destination eth addr */
        unsigned char   h_source[ETH_ALEN];     /* source ether addr    */
        __be16          h_proto;                /* packet type ID field */
} __attribute__((packed));

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8    ihl:4,
                version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
        __u8    version:4,
                ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
        __u8    tos;
        __be16  tot_len;
        __be16  id;
        __be16  frag_off;
        __u8    ttl;
        __u8    protocol;
        __sum16 check;
        __be32  saddr;
        __be32  daddr;
        /*The options start here. */
};

struct udphdr {
        __be16  source;
        __be16  dest;
        __be16  len;
        __sum16 check;
};
#endif

#define NUM_FRAMES 2048 
struct ethernet_frame {
	struct ethhdr ethh;
	struct iphdr iph;
	struct udphdr udph;
} __attribute__((packed));

struct udp_packets {
	unsigned char *buffer;
	unsigned int packet_len;
	unsigned int total_packets;
	struct sockaddr_ll src_dev;
	struct ethernet_frame *frames[NUM_FRAMES];
};

struct thread_context { 
	pthread_t pt;
#if defined(USE_PTHREAD_RWLOCK)
	pthread_rwlockattr_t rwattr;
	pthread_rwlock_t rwlock;
#elif defined(USE_PTHREAD_MUTEX)
	pthread_mutex_t mtxlock;
	pthread_mutexattr_t mattr;
#elif defined(USE_PTHREAD_SPINLOCK)
	pthread_spinlock_t slock;
#endif
	unsigned long tx_packets;
	unsigned long prev_tx_packets;
	struct udp_packets pkts;
};

#if defined(USE_PTHREAD_COMMON_RWLOCK)
pthread_rwlockattr_t rwattr;
pthread_rwlock_t rwlock;
#elif defined(USE_PTHREAD_COMMON_MUTEX)
pthread_mutex_t mtxlock;
pthread_mutexattr_t mattr;
#elif defined(USE_PTHREAD_COMMON_SPINLOCK)
pthread_spinlock_t slock;
#endif
static struct thread_context *ctx;
pthread_t pt;
struct udp_packets pkts;

static void *buffer;
static unsigned int frame_len = 1024;
static unsigned int num_threads = 1; 
static unsigned int runtime;

static unsigned long prev_time;
static unsigned long tx_packets;
static unsigned long prev_tx_packets;
static unsigned long total_tx_packets;

static const char *dst_addr = NULL;
static const char *if_name = NULL;
#define ARP_PACKET_LEN	64

static struct option long_options[] = {
	{"dst-ip", required_argument, 0, 'd'},
	{"interface", required_argument, 0, 'i'},
	{"frame-len", required_argument, 0, 'l'},
	{"interval", required_argument, 0, 'n'},
	{"runtime", required_argument, 0, 'r'},
	{"threads", required_argument, 0, 't'},
	{"zero-copy", no_argument, 0, 'z'},
	{0, 0, 0, 0}
};

static void usage(const char *prog)
{
	const char *str =
		"  Usage: %s [OPTIONS]\n"
		"  Options:\n"
		"  -d, --dst-ip		destination ip address\n"
		"  -i, --interface=n	Run on interface n\n"
		"  -l, --frame-len	Datagram length\n"
		"  -n, --interval=n	Specify statistics update interval (default 1 sec).\n"
		"  -r, --runtime=n	runtime of data traffic\n"
		"  -t, --threads=t	Number of threads (default 1).\n"
		"  -z, --zero-copy      Force zero-copy mode.\n"
		"\n";
	fprintf(stderr, str, prog, 1024);
	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv)
{
	int option_index, c;
	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv, "dilnrz",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			dst_addr = optarg;
			if (dst_addr)
				printf("DST_addr: %s\n", dst_addr);
			break;
		case 'i':
			if_name = optarg;
			printf("if_name: %s\n", if_name);
			break;
		case 'l':
			frame_len = atoi(optarg);
			if (frame_len < 60  || frame_len > 65536) {
				printf("Invalid Frame length [%u], setting to 1024 default\n", frame_len);
				frame_len = 1024;
			}
			break;
		case 'n':
			break;
		case 't':
			num_threads = atoi(optarg);
			if (num_threads < 0 || num_threads > 16) {
				printf("Invalid number of threads, setting to 1 (default)\n");
				num_threads = 1;
			}
			break;
		case 'r':
			runtime = atoi(optarg);
			if (runtime < 0) {
				printf("Invalid number of threads, setting to 1 (default)\n");
				runtime = 0;
			}
		case 'z':
			break;
		default:
			usage(basename(argv[0]));
		}
	}

}

static int prepare_apr_header(struct arp_packet *p,
		struct sockaddr_in *src, struct sockaddr_in *dst)
{
	struct ethhdr *ethh; 
	struct arphdr *arph;

	if (!p)
		return -EINVAL;

	ethh = &p->ethh;
	arph = &p->arph;

	for (int i=0; i<ETH_ALEN; i++)
		ethh->h_dest[i] = 0xff;
	ethh->h_proto = htons(ETH_P_ARP);

	arph->ar_hrd = htons(1);
	arph->ar_pro = htons(ETH_P_IP);
	arph->ar_hln = ETH_ALEN;
	arph->ar_pln = 4;
	arph->ar_op = htons(ARPOP_REQUEST);

	for (int i=0; i<ETH_ALEN; i++) {
		arph->ar_sha[i] = ethh->h_source[i];
		arph->ar_tha[i] = 0; 
	}

	*(struct in_addr *)arph->ar_sip = src->sin_addr; 
	*(struct in_addr *)arph->ar_tip = dst->sin_addr; 

	return 0;
}

static int waitforresponse(int s, int no_of_secs) {
	int ret, max_sd;
	fd_set rx_set;
	struct timeval timeout;

	FD_ZERO(&rx_set);
	FD_SET(s, &rx_set);
	max_sd = s+1;

	timeout.tv_sec = no_of_secs;
	timeout.tv_usec = 20000;

	ret = select(max_sd, &rx_set, NULL, NULL, &timeout);
	return ret;
}

static int process_arp_request(struct sockaddr_ll *src_dev, 
		struct arp_packet *req, struct arp_packet *resp)
{
	unsigned int sip;
	unsigned char *data;
	struct ethhdr *ethh; 
	struct arphdr *arph;
	int attempts;
	int sock;
	int rc;
	
	if (!resp)
		return -EINVAL;
	else
		data = (unsigned char *)resp;

	attempts = 0;
	arph = &req->arph;
	sip = *(unsigned int *)arph->ar_sip;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sock < 0) {
		perror ("socket creation with AF_INET SOCK_RAW ETH_P_ARP failed ");
		return sock;
	}

	arph = &resp->arph;
	ethh = &resp->ethh;

	while(1) {
		rc = sendto(sock, (const void *)req, sizeof(struct arp_packet), 0,
				(struct sockaddr *)src_dev, sizeof(struct sockaddr_ll));
		if (rc < 0) {
			perror ("sendto failed\n");
			return rc;
		}

		do {
			rc = waitforresponse(sock, 2);
			if (rc) {
				rc = read(sock, resp, sizeof(struct arp_packet));
				if (rc < 0) {
					attempts = -1;
					break;
				}
#if 0
				for (int i = 0; i < 48; i++)
					printf("%02x:", *((unsigned char *)resp + i));
				printf("\n");
#endif
				if ((ethh->h_proto != htons(ETH_P_ARP)) ||
						(arph->ar_op != ntohs(ARPOP_REPLY))
				   ) {
					printf("Not an ARP PACKET, retry...\n");
					attempts++;
				} else if ( sip == *(unsigned int *)arph->ar_tip) {
					printf("Target MAC :");
					for (int i = 0; i < ETH_ALEN; i++)
						printf("%2x:", arph->ar_sha[i]);
					printf("\n");
					rc = 0;
					attempts = -1;
					break;
				}
			} else {
				attempts++;
				if (attempts == 5)
					printf("Max Attempts reached, could not get response\n");
				break;
			}
		} while(attempts <= 5);

		if (attempts == 5) {
			rc = -1;
			break;
		}

		if (attempts == -1)
			break;
	}

	close(sock);
	
	return rc;
}

static unsigned long get_nsecs(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

static void pthread_atexit(void)
{
	struct udp_packets *pkts;
	int ret;
	int i;
	unsigned long long tx_pkts;

	if (ctx == NULL)
		return;

	tx_pkts = 0;
	for (i = 0; i < num_threads; i++) {

		/* Cancell All the active Threads */
		ret = pthread_cancel(ctx[i].pt);
		if (ret != 0) {
			printf("Pthread_cancel returned non zero : %d\n", ret);
		}
	}

	for (i = 0; i < num_threads; i++) {
		pkts = &ctx[i].pkts;
		if (pkts) {
			if (pkts->buffer)
				munmap(buffer, frame_len * NUM_FRAMES);
		}
		tx_pkts += ctx[i].tx_packets;
	}
	free(ctx);

	printf("Total Number of Datagrams Transferred: [%llu]\n", tx_pkts);
}

static int pthread_lock(struct thread_context *ctx)
{
	int rc;

#if defined(USE_PTHREAD_MUTEX) 
	if (rc = pthread_mutex_lock(&ctx->mtxlock))
#elif defined(USE_PTHREAD_SPINLOCK)
	if (rc = pthread_spin_lock(&ctx->slock))
#elif defined(USE_PTHREAD_RWLOCK)
	if (rc = pthread_rwlock_wrlock(&ctx->rwlock))
#elif defined(USE_PTHREAD_COMMON_MUTEX) 
	if (pthread_mutex_lock(&mtxlock))
#elif defined(USE_PTHREAD_COMMON_SPINLOCK)
	if (pthread_spin_lock(&slock))
#elif defined(USE_PTHREAD_COMMON_RWLOCK)
	if (pthread_rwlock_lock(&rwlock))
#else
	if (0)
#endif
	{
		printf("Failed to get Lock in Thread, RET: %d\n", rc);
		return rc;
	}

	return 0;
}

static int pthread_unlock(struct thread_context *ctx)
{
	int rc;

#if defined(USE_PTHREAD_MUTEX) 
	if (rc = pthread_mutex_unlock(&ctx->mtxlock))
#elif defined(USE_PTHREAD_SPINLOCK)
	if (rc = pthread_spin_unlock(&ctx->slock))
#elif defined(USE_PTHREAD_RWLOCK)
	if (rc = pthread_rwlock_unwrlock(&ctx->rwlock))
#elif defined(USE_PTHREAD_COMMON_MUTEX) 
	if (pthread_mutex_unlock(&mtxlock))
#elif defined(USE_PTHREAD_COMMON_SPINLOCK)
	if (pthread_spin_unlock(&slock))
#elif defined(USE_PTHREAD_COMMON_RWLOCK)
	if (pthread_rwlock_unlock(&rwlock))
#else
	if (0)
#endif
	{
		printf("Failed to get Lock in Thread, RET: %d\n", rc);
		return rc;
	}

	return 0;
}

static void *pthread_poller(void *data)
{
	struct thread_context *ctx;
	unsigned long prev_time;
	unsigned long long tx_packets;
	unsigned long _tx_pps;
	double tx_pps;
	char *fmt;
	unsigned long now;
	unsigned int ticks;
	long dt;
	int rc;
	int i;

	ctx = (struct thread_context *)data;
	if (!ctx) {
		printf("DATA IS NULL\n");
		exit(1);
	}
	tx_packets = 0;
	fmt = "%-15s %'-11.0f %'-11lu\n";
	prev_time = get_nsecs();

	for (;;) {
		tx_pps = 0;
		sleep(1);
		now = get_nsecs();
		dt = now - prev_time;
		prev_time = now;

#if defined(USE_PTHREAD_COMMON_MUTEX) || defined(USE_PTHREAD_COMMON_SPINLOCK) || defined(USE_PTHREAD_COMMON_RWLOCK)
		if (pthread_lock(ctx))
			exit(1);
#endif
		for (i = 0; i < num_threads; i++) {
#if defined(USE_PTHREAD_MUTEX) || defined(USE_PTHREAD_SPINLOCK) || defined(USE_PTHREAD_RWLOCK)
			if (pthread_lock(ctx+i))
				exit(1);
#endif
			tx_pps += (ctx[i].tx_packets - ctx[i].prev_tx_packets);
			tx_packets += (ctx[i].tx_packets - ctx[i].prev_tx_packets); 
			ctx[i].prev_tx_packets = ctx[i].tx_packets;
#if defined(USE_PTHREAD_MUTEX) || defined(USE_PTHREAD_SPINLOCK) || defined(USE_PTHREAD_RWLOCK)
			if (pthread_unlock(ctx+i))
				exit(1);
#endif
		}
#if defined(USE_PTHREAD_COMMON_MUTEX) || defined(USE_PTHREAD_COMMON_SPINLOCK) || defined(USE_PTHREAD_COMMON_RWLOCK)
		if (pthread_unlock(ctx))
			exit(1);
#endif
		tx_pps = tx_pps *
			1000000000. / dt;

		printf("\n");
		printf("%-15s %-11s %-11s %-11.2f\n", "", "pps", "pkts",
				dt / 1000000000.);
		printf(fmt, "tx", tx_pps, tx_packets);

		++ticks;
		if (runtime && runtime == ticks)
			break;
	}

	return NULL;
}

static void *poller(void *arg)
{
	struct thread_context *ctx;
	(void)arg;
	for (;;) {
		sleep(1);

		unsigned long now = get_nsecs();
		long dt = now - prev_time;
		int i;

		prev_time = now;

		char *fmt = "%-15s %'-11.0f %'-11lu\n";
		double tx_pps;

		tx_pps = (tx_packets - prev_tx_packets) *
			1000000000. / dt;

		printf("\n");
		printf("%-15s %-11s %-11s %-11.2f\n", "", "pps", "pkts",
				dt / 1000000000.);
		printf(fmt, "tx", tx_pps, tx_packets);

		prev_tx_packets = tx_packets;
	}
	return NULL;
}

static int _prepare_udp_frames(struct udp_packets *pkts,
		struct sockaddr_ll *src, struct sockaddr_ll *dst,
		struct sockaddr_in *src_ip, struct sockaddr_in *dst_ip,
		unsigned int sport, unsigned int dport)
{
	struct ethernet_frame *frame;
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct udphdr *udph;
	unsigned int frame_len;	
	unsigned int index;	
	unsigned int i;	

	if (!pkts || !pkts->buffer || !pkts->packet_len || !pkts->total_packets)
		return -EINVAL;

	frame_len = pkts->packet_len;

	for (index = 0; index < pkts->total_packets; index++) {
		frame =	(struct ethernet_frame *)(pkts->buffer +
				pkts->packet_len * index); 
		pkts->frames[index] = frame;

		memcpy(&pkts->src_dev, src, sizeof(struct sockaddr_ll));
		ethh = &frame->ethh;

		/* Prepare Ethernet Header */
		memcpy(frame->ethh.h_dest, dst->sll_addr, ETH_ALEN);
		memcpy(frame->ethh.h_source, src->sll_addr, ETH_ALEN);
		frame->ethh.h_proto = htons(ETH_P_IP); 

		/* Prepare IP Header */
		frame->iph.ihl = 5;
		frame->iph.version = 4;
		frame->iph.tos = 1;
		frame->iph.tot_len = ntohs(frame_len - sizeof(struct ethhdr));
		frame->iph.id = ntohs(0x1234 + index);
		frame->iph.protocol = IPPROTO_UDP;
		frame->iph.saddr = src_ip->sin_addr.s_addr;
		frame->iph.daddr = dst_ip->sin_addr.s_addr;

		/* Prepare IP Header */
		frame->udph.source = htons(sport);
		frame->udph.dest = htons(dport);
		frame->udph.len = ntohs(frame_len - 
				(sizeof(struct ethhdr) + sizeof(struct iphdr)));   
		frame->udph.check = ntohs(0);
	}

#if 0
	unsigned char *data;
	for ( index = 0; index < pkts->total_packets; index++) {
		printf("FRAME: [%04d]\n", index);
		frame = pkts->frames[index];
		data = (unsigned char *) frame;
		for (i = 0; i < 48; i++) {
			printf("%02x:", data[i]);
		}
		printf("\n");

		sleep(2);
	}
#endif

	return 0;
}

static int pthread_init_lock(struct thread_context *ctx)
{
	int rc;

#if defined(USE_PTHREAD_MUTEX)
	rc = pthread_mutexattr_init(&ctx->mattr);
	if (rc != 0) {
		printf("Pthreads mutex attr init failed\n");
		return rc;
	}

	rc = pthread_mutexattr_settype(&ctx->mattr, PTHREAD_MUTEX_ERRORCHECK);
	if (rc != 0) {
		printf("Pthreads mutex attr setup failed\n");
		return rc;
	}

	rc = pthread_mutex_init(&ctx->mtxlock, &ctx->mattr);
	if (rc != 0) {
		printf("Pthreads mutex INIT failed\n");
		return rc;
	}

	rc = pthread_mutexattr_destroy(&ctx->mattr);
	if (rc != 0) {
		printf("Pthread Mutex Attr Destroy Failed\n");
	}
#elif defined(USE_PTHREAD_SPINLOCK)
	rc = pthread_spin_init(&ctx->slock, PTHREAD_PROCESS_PRIVATE);
	if (rc != 0) {
		printf("Pthreads SPIN LOCK INIT failed\n");
		return rc;
	}
#elif defined(USE_PTHREAD_RWLOCK)
	rc = pthread_rwlockattr_init(&ctx->rwattr);
	if (rc != 0) {
		printf("Pthreads RW ATTR INIT failed\n");
		return rc;
	}

	rc = pthread_rwlock_init(&ctx->rwlock, &ctx->rwattr);
	if (rc != 0) {
		printf("Pthreads RW LOCK INIT failed\n");
		return rc;
	}
#elif defined(USE_PTHREAD_COMMON_MUTEX)
	(void)ctx;
	rc = pthread_mutexattr_init(&mattr);
	if (rc != 0) {
		printf("Pthreads mutex attr init failed\n");
		return rc;
	}

	rc = pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_ERRORCHECK);
	if (rc != 0) {
		printf("Pthreads mutex attr setup failed\n");
		return rc;
	}

	rc = pthread_mutex_init(&mtxlock, &mattr);
	if (rc != 0) {
		printf("Pthreads mutex INIT failed\n");
		return rc;
	}

	rc = pthread_mutexattr_destroy(&mattr);
	if (rc != 0) {
		printf("Pthread Mutex Attr Destroy Failed\n");
	}
#elif defined(USE_PTHREAD_COMMON_SPINLOCK)
	(void)ctx;
	rc = pthread_spin_init(&slock, PTHREAD_PROCESS_PRIVATE);
	if (rc != 0) {
		printf("Pthreads SPIN LOCK INIT failed\n");
		return rc;
	}
#elif defined(USE_PTHREAD_COMMON_RWLOCK)
	(void)ctx;
	rc = pthread_rwlockattr_init(&rwattr);
	if (rc != 0) {
		printf("Pthreads RW ATTR INIT failed\n");
		return rc;
	}

	rc = pthread_rwlock_init(&rwlock, &rwattr);
	if (rc != 0) {
		printf("Pthreads RW LOCK INIT failed\n");
		return rc;
	}
#endif

	return 0;
}

static int pthread_prepare_threads(struct thread_context *ctx, int num_threads,
		struct sockaddr_ll *src, struct sockaddr_ll *dst,
		struct sockaddr_in *src_ip, struct sockaddr_in *dst_ip)

{
	struct udp_packets *pkts;
	int i;
	int rc;

#if defined(USE_PTHREAD_COMMON_MUTEX) || defined(USE_PTHREAD_COMMON_SPINLOCK) || defined(USE_PTHREAD_COMMON_RWLOCK)
	rc = pthread_init_lock(ctx);
	if (rc != 0) {
		fprintf(stderr, "ERROR: Failed to init LockUSE_PTHREAD_RWLOCK\"%s\"\n",
				strerror(errno));
		return rc;
	}
#endif
	for (i = 0; i < num_threads; i++) {
#if defined(USE_PTHREAD_MUTEX) || defined(USE_PTHREAD_SPINLOCK) || defined(USE_PTHREAD_RWLOCK)
		rc = pthread_init_lock(ctx + i);
#endif
		pkts = &ctx[i].pkts;
		if (pkts) {
			pkts->packet_len = frame_len;
			pkts->total_packets = NUM_FRAMES;
			pkts->buffer = mmap(NULL, pkts->total_packets * pkts->packet_len, 
					PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (!pkts->buffer) {
				printf("MMAP Failed\n");
				return -ENOMEM;
			}
			rc = _prepare_udp_frames(pkts, src, dst, src_ip, dst_ip,
					i * 10 + 123, i * 20 + 1234);
			if (rc < 0) {
				printf("prepare UDP Frames failed\n");
				return rc;
			}
		} else {
			printf("INvalid Memory\n");
			return -EINVAL;
		}
	}

	return 0;
}

static void *pthread_process_udp_transfers(void *data)
{
	struct thread_context *ctx;
	struct udp_packets *pkts;
	struct sockaddr_ll *src_dev;
	int sock;
	int rc;
	int i;

	ctx = (struct thread_context *)data;
	if (!ctx) {
		printf("Pthread Error, Invalid Data\n");
		return NULL;
	}

	pkts = &ctx->pkts;
	if (!pkts) {
		printf("Pthread Error, Invalid pkts\n");
		return NULL;
	}

	src_dev = &pkts->src_dev;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (sock < 0) {
		perror ("Pthread socket creation with AF_INET SOCK_RAW ETH_P_ARP failed\n");
		return NULL;
	}

	while (1) {
		for (i = 0; i < pkts->total_packets; i++) {
			rc = sendto(sock, pkts->frames[i], pkts->packet_len, 0,
					(struct sockaddr *)src_dev, sizeof(struct sockaddr_ll));
			if (rc <= 0) {
				printf("RETURN :%d\n", rc);
				perror ("sendto failed\n");
			//	goto failure;
			} else {
				if (pthread_lock(ctx))
					pthread_exit(NULL);
				++ctx->tx_packets;
				if (pthread_unlock(ctx))
					pthread_exit(NULL);
			}
		}
	}

failure:
	close(sock);
	return 0;
}

static int process_udp_transfers(struct udp_packets *pkts, struct sockaddr_ll *src_dev)
{
	int sock;
	int rc;
	int i;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (sock < 0) {
		perror ("socket creation with AF_INET SOCK_RAW ETH_P_ARP failed\n");
		return sock;
	}

	while (1) {
		for (i = 0; i < pkts->total_packets; i++) {
			rc = sendto(sock, pkts->frames[i], pkts->packet_len, 0,
					(struct sockaddr *)src_dev, sizeof(struct sockaddr_ll));
			if (rc <= 0) {
				printf("RETURN :%d\n", rc);
				perror ("sendto failed\n");
				goto failure;
			}
			++tx_packets;
		}
	}

failure:
	close(sock);

	return rc;
}

static int send_udp_traffic(struct sockaddr_ll *src, struct sockaddr_ll *dst,
		struct sockaddr_in *src_ip, struct sockaddr_in *dst_ip)
{

	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	int upd_socket;
	int ret;

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	buffer = mmap(NULL, NUM_FRAMES * frame_len,
		    PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buffer == MAP_FAILED) {
		printf("ERROR: mmap failed\n");
		exit(EXIT_FAILURE);
	}
	printf("Buffer Allocated to accomodate NUM_FRAMES Frames\n");	

	pkts.buffer = buffer;
	pkts.packet_len = frame_len;
	pkts.total_packets = NUM_FRAMES;

	//signal(SIGINT, int_exit);
	//signal(SIGTERM, int_exit);
	//signal(SIGABRT, int_exit);
	atexit(pthread_atexit);

	setlocale(LC_ALL, "");

	ret = _prepare_udp_frames(&pkts, src, dst, src_ip, dst_ip, 1234, 12345);
	if (ret) {
		printf("Failed to setup UDP Packets\n");
		return ret;
	}

	prev_time = get_nsecs();
	ret = pthread_create(&pt, NULL, poller, NULL);
	if (ret) {
		printf("Failed to setup Thread");
	}

	ret = process_udp_transfers(&pkts, src);
	if (ret < 0) {
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct arp_packet *req; 
	struct arp_packet *resp; 
	struct arphdr *arph;
	struct ethhdr *ethh; 
	struct iphdr *iph; 
	struct ifreq ifr;
	struct sockaddr *saddr;
	struct sockaddr_in *sin;
	struct sockaddr_in src_ip; 
	struct sockaddr_in dst_ip; 
  	struct sockaddr_ll src_dev;
  	struct sockaddr_ll dst_dev;
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	int sock;
	int rc;

	parse_command_line(argc, argv);

	if (!dst_addr || !if_name)
		usage(basename(argv[0]));

	req = malloc(ARP_PACKET_LEN);
	resp = malloc(ARP_PACKET_LEN);
	
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	setlocale(LC_ALL, "");

	sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0) {
		perror ("socket() failed to get socket descriptor for using ioctl() ");
		exit (EXIT_FAILURE);
	}

	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", if_name);
	rc = ioctl(sock, SIOCGIFHWADDR, &ifr);
	if (rc < 0) {
		perror ("ioctl() failed to get source MAC address ");
		return (EXIT_FAILURE);
	}

	ethh = &req->ethh;
	memcpy(ethh->h_source, ifr.ifr_hwaddr.sa_data, ETH_ALEN * sizeof (uint8_t));
	printf("MAC address for interface %s is ", if_name);
	for (int i=0; i<ETH_ALEN; i++) {
		printf ("%02x:", ethh->h_source[i]);
	}
	printf("\n");

	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", if_name);
	rc = ioctl(sock, SIOCGIFADDR, &ifr);
	if (rc < 0) {
		perror ("ioctl() failed to get source MAC address ");
		return (EXIT_FAILURE);
	}
	close(sock);
	src_ip.sin_family = AF_INET;
	src_ip.sin_port = htons(0);
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	src_ip.sin_addr = sin->sin_addr; 

	printf("SRC IP ADDR: [%s]\n", inet_ntoa(src_ip.sin_addr));

	dst_ip.sin_family = AF_INET;
	dst_ip.sin_port = htons(0);
	rc = inet_aton(dst_addr, &dst_ip.sin_addr);
	if (rc < 0) {
		perror ("inet_aton failed to get source MAC address ");
		return (EXIT_FAILURE);
	}
	printf("DST IP ADDR: [%s]\n", inet_ntoa(dst_ip.sin_addr));

	rc = prepare_apr_header(req, &src_ip, &dst_ip);
	if (rc < 0) {
		perror ("inet_aton failed to get source MAC address ");
		goto failure;	
	}

	memset(&src_dev, 0, sizeof(struct sockaddr_ll));
	src_dev.sll_ifindex = if_nametoindex(if_name);
	if (src_dev.sll_ifindex < 0) {
		perror ("if_nametoindex() failed to obtain interface index ");
		goto failure;	
	}

	src_dev.sll_family = AF_PACKET;
	memcpy(src_dev.sll_addr, ethh->h_source, ETH_ALEN);
	src_dev.sll_halen = ETH_ALEN;

	rc = process_arp_request(&src_dev, req, resp);
	if (!rc) {
		arph = &resp->arph;
		memset(&dst_dev, 0, sizeof(struct sockaddr_ll));
		dst_dev.sll_family = AF_PACKET;
		memcpy(dst_dev.sll_addr, arph->ar_sha, ETH_ALEN);
		dst_dev.sll_halen = ETH_ALEN;

		printf("MAC Address of NIC with IP: %s is :",
				inet_ntoa(dst_ip.sin_addr));
		for (int i = 0; i < ETH_ALEN; i++) 
			printf("%02X%c", arph->ar_sha[i],
					(i + 1 == ETH_ALEN) ? '\0' : (':'));
		printf("\n");
	} else
		goto failure;
	
	atexit(pthread_atexit);
	if (num_threads > 0) {
		ctx = (struct thread_context *)calloc(1, sizeof(struct thread_context) * num_threads);
		if (ctx == NULL) {
			printf("No Mem\n");
			goto failure;
		}

		rc = pthread_prepare_threads(ctx, num_threads, &src_dev, &dst_dev, &src_ip, &dst_ip);	
		if (rc < 0) {
			printf("Failed to prepare Threads\n");
			exit(rc);
		}

		for (int i = 0; i < num_threads; i++) {
			rc = pthread_create(&ctx[i].pt, NULL, pthread_process_udp_transfers, &ctx[i]);
			if (rc) {
				printf("Failed to setup Thread");
				exit(1);
			}
		}

		pthread_poller(ctx);
	}

failure:
	if (req) {
		free(req);
		req = NULL;
	}

	if (resp) {
		free(resp);
		resp = NULL;
	}

	return rc;
}
