/*
 * CapProbe revised version for Linux 4.1
 *
 * by Amar Chandole, amar.chandole@cs.ucla.edu,
 *	  Yuanzhi Gao, yuanzhi@cs.ucla.edu,
 * 	  Ameya Kabre, akabre@cs.ucla.edu
 *
 */
#include <net/ip.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/ipconfig.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/neighbour.h>
#include <linux/socket.h>
#include <linux/inetdevice.h>

#define CapProbe_DIR "net/capprobe"

#define MAX_BURST_SIZE 500
#define CAP_SAMPLES 120

#define CAP_SAME 20
#define CAP_SAME_MAX 100
#define CAP_SAMPLES_MAX 500

#define CAP_SIZE_MAX 1500
#define CAP_SIZE_MIN 500
#define INIT_SIZE_1  1200
#define INIT_SIZE_2  900
#define TOO_LARGE_DELAY 10000000000
#define INFINITE 10000000000

#define CAP_PHASE_1 1
#define CAP_PHASE_2 2
#define CAP_PHASE_3 3
#define SEC_TO_USEC 1000000

#ifndef CAP_PROBE_
#define CAP_PROBE_

//CapProbe function prototypes

void process_capprobe(struct sk_buff *skb, struct net_device *dev, const struct iphdr *iph);
void capprobe_main(unsigned long);
//int get_dest_mac(__u32 *ip, struct arpreq *r, struct net_device *dev);
//unsigned int arp_state_to_flags(struct neighbour *neigh);

extern __u32 all_gateways[10];

#endif