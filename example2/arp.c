#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <errno.h>            // errno, perror()


#include <sys/socket.h>       // needed for socket()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <netdb.h>            // struct addrinfo
#include <netinet/in.h>       // IPPROTO_RAW, INET_ADDRSTRLEN
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806
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

#define ARP_PACKET_LEN	64
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

static int __process_arp_request(struct arp_packet *req,
		struct arp_packet *resp,
		struct sockaddr_ll *src_dev)
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
		if (rc < 0)
			return rc;

		do {
			rc = waitforresponse(sock, 2);
			if (rc) {
				rc = read(sock, resp, sizeof(struct arp_packet));
				if (rc < 0) {
					attempts = -1;
					break;
				}

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

static int __prepare_arp_header(struct arp_packet *p,
		struct sockaddr_ll *src_dev,
		struct sockaddr_in *src,
		struct sockaddr_in *dst, unsigned short int opcode)
{
	struct ethhdr *ethh;
	struct arphdr *arph;

	if (!p)
		return -EINVAL;

	memset(p, 0, sizeof(struct arp_packet));
	ethh = &p->ethh;
	arph = &p->arph;

	memcpy(ethh->h_source, src_dev->sll_addr, ETH_ALEN * sizeof (uint8_t));
	for (int i=0; i<ETH_ALEN; i++)
		ethh->h_dest[i] = 0xff;
	ethh->h_proto = htons(ETH_P_ARP);

	arph->ar_hrd = htons(1);
	arph->ar_pro = htons(ETH_P_IP);
	arph->ar_hln = ETH_ALEN;
	arph->ar_pln = 4;
	arph->ar_op = htons(opcode);

	for (int i=0; i<ETH_ALEN; i++) {
		arph->ar_sha[i] = ethh->h_source[i];
		arph->ar_tha[i] = 0; 
	}

	*(struct in_addr *)arph->ar_sip = src->sin_addr; 
	*(struct in_addr *)arph->ar_tip = dst->sin_addr; 

	return 0;
}

int __resolve_arp(struct sockaddr_ll *src_dev, struct sockaddr_ll *dst_dev,
		struct sockaddr_in *src_ip, struct sockaddr_in *dst_ip)
{
	struct arp_packet req; 
	struct arp_packet resp; 
	struct arphdr *arph;
	struct ifreq ifr;
	int ret;

	if (!src_dev || !dst_dev || !src_ip || !dst_ip)
		return -EINVAL;

	if ((dst_dev->sll_halen != ETH_ALEN) ||
			(src_dev->sll_halen != ETH_ALEN)
	   ) {
		printf("Invalid HW address length\n");
		return -EINVAL;
	}

	ret = __prepare_arp_header(&req, src_dev, src_ip, dst_ip, ARPOP_REQUEST);
	if (ret < 0)
		return ret;

	ret = __process_arp_request(&req, &resp, src_dev);
	if (ret < 0)
		return ret;
	
	arph = &resp.arph;
	memcpy(dst_dev->sll_addr, arph->ar_sha, sizeof(ETH_ALEN));
 
	return 0; 
}

