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
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/neighbour.h>

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

#define MAX_NUM_PATH 2

typedef struct
{
    //CapProbe round trip time variables
long cap_RTT1;
long cap_RTT2;
long cap_RTT_SUM;
unsigned long rtt1, rtt2, rtt, disp;

//CapProbe book keeping arrays, variables for send-receive time, serial nos.
long cap_recv_num;
long cap_serialnum[MAX_BURST_SIZE];
long cap_send_sec[MAX_BURST_SIZE];
long cap_send_usec[MAX_BURST_SIZE];
long cap_recv1_sec[MAX_BURST_SIZE];
long cap_recv1_usec[MAX_BURST_SIZE];
long cap_recv2_sec[MAX_BURST_SIZE];
long cap_recv2_usec[MAX_BURST_SIZE];
int cap_phase;
int cap_run; // need init
long cap_id;
long cap_size;
int cap_index; // need init
int cap_icmp_serialnum; // need init
long CAP_INIT_SIZE_1;
long CAP_INIT_SIZE_2;

//CapProbe necessary struct declarations
struct sk_buff *cap_skb ;
struct net_device *cap_dev;
struct timer_list tl;
//static char *dirname = "capprobe";

//CapProbe timing related variables
struct timeval cap_time_start;
struct timeval cap_time_end;
long burst_size;            //default value. changed as per user input into /sys/capprobe/device later
long burst_interval;   //default value. changed as per user input into /sys/capprobe/device later

//CapProbe route capacity related variables
int cap_C_same;
int cap_C_same2;
int cap_variance;
long cap_C_results[3];          
long cap_C;                 
long cap_C_max;             
long cap_C_min;

__u32 cap_dst;           //Ultimate destination to which capacity is to be tested
char cap_device[100];           //to copy device name from userspace

unsigned long packet_pairs_sent;

} capprobe_param; 

#ifndef CAP_PROBE_
#define CAP_PROBE_

//CapProbe function prototypes

void process_capprobe(struct sk_buff *skb, struct net_device *dev, const struct iphdr *iph);
void capprobe_main(int num_path);
//int get_dest_mac(__u32 *ip, struct arpreq *r, struct net_device *dev);
//unsigned int arp_state_to_flags(struct neighbour *neigh);

#endif