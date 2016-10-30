/* MPTCP
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) module.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *
 *
 * Fixes:
 *		Alan Cox	:	Commented a couple of minor bits of surplus code
 *		Alan Cox	:	Undefining IP_FORWARD doesn't include the code
 *					(just stops a compiler warning).
 *		Alan Cox	:	Frames with >=MAX_ROUTE record routes, strict routes or loose routes
 *					are junked rather than corrupting things.
 *		Alan Cox	:	Frames to bad broadcast subnets are dumped
 *					We used to process them non broadcast and
 *					boy could that cause havoc.
 *		Alan Cox	:	ip_forward sets the free flag on the
 *					new frame it queues. Still crap because
 *					it copies the frame but at least it
 *					doesn't eat memory too.
 *		Alan Cox	:	Generic queue code and memory fixes.
 *		Fred Van Kempen :	IP fragment support (borrowed from NET2E)
 *		Gerhard Koerting:	Forward fragmented frames correctly.
 *		Gerhard Koerting: 	Fixes to my fix of the above 8-).
 *		Gerhard Koerting:	IP interface addressing fix.
 *		Linus Torvalds	:	More robustness checks
 *		Alan Cox	:	Even more checks: Still not as robust as it ought to be
 *		Alan Cox	:	Save IP header pointer for later
 *		Alan Cox	:	ip option setting
 *		Alan Cox	:	Use ip_tos/ip_ttl settings
 *		Alan Cox	:	Fragmentation bogosity removed
 *					(Thanks to Mark.Bush@prg.ox.ac.uk)
 *		Dmitry Gorodchanin :	Send of a raw packet crash fix.
 *		Alan Cox	:	Silly ip bug when an overlength
 *					fragment turns up. Now frees the
 *					queue.
 *		Linus Torvalds/ :	Memory leakage on fragmentation
 *		Alan Cox	:	handling.
 *		Gerhard Koerting:	Forwarding uses IP priority hints
 *		Teemu Rantanen	:	Fragment problems.
 *		Alan Cox	:	General cleanup, comments and reformat
 *		Alan Cox	:	SNMP statistics
 *		Alan Cox	:	BSD address rule semantics. Also see
 *					UDP as there is a nasty checksum issue
 *					if you do things the wrong way.
 *		Alan Cox	:	Always defrag, moved IP_FORWARD to the config.in file
 *		Alan Cox	: 	IP options adjust sk->priority.
 *		Pedro Roque	:	Fix mtu/length error in ip_forward.
 *		Alan Cox	:	Avoid ip_chk_addr when possible.
 *	Richard Underwood	:	IP multicasting.
 *		Alan Cox	:	Cleaned up multicast handlers.
 *		Alan Cox	:	RAW sockets demultiplex in the BSD style.
 *		Gunther Mayer	:	Fix the SNMP reporting typo
 *		Alan Cox	:	Always in group 224.0.0.1
 *	Pauline Middelink	:	Fast ip_checksum update when forwarding
 *					Masquerading support.
 *		Alan Cox	:	Multicast loopback error for 224.0.0.1
 *		Alan Cox	:	IP_MULTICAST_LOOP option.
 *		Alan Cox	:	Use notifiers.
 *		Bjorn Ekwall	:	Removed ip_csum (from slhc.c too)
 *		Bjorn Ekwall	:	Moved ip_fast_csum to ip.h (inline!)
 *		Stefan Becker   :       Send out ICMP HOST REDIRECT
 *	Arnt Gulbrandsen	:	ip_build_xmit
 *		Alan Cox	:	Per socket routing cache
 *		Alan Cox	:	Fixed routing cache, added header cache.
 *		Alan Cox	:	Loopback didn't work right in original ip_build_xmit - fixed it.
 *		Alan Cox	:	Only send ICMP_REDIRECT if src/dest are the same net.
 *		Alan Cox	:	Incoming IP option handling.
 *		Alan Cox	:	Set saddr on raw output frames as per BSD.
 *		Alan Cox	:	Stopped broadcast source route explosions.
 *		Alan Cox	:	Can disable source routing
 *		Takeshi Sone    :	Masquerading didn't work.
 *	Dave Bonn,Alan Cox	:	Faster IP forwarding whenever possible.
 *		Alan Cox	:	Memory leaks, tramples, misc debugging.
 *		Alan Cox	:	Fixed multicast (by popular demand 8))
 *		Alan Cox	:	Fixed forwarding (by even more popular demand 8))
 *		Alan Cox	:	Fixed SNMP statistics [I think]
 *	Gerhard Koerting	:	IP fragmentation forwarding fix
 *		Alan Cox	:	Device lock against page fault.
 *		Alan Cox	:	IP_HDRINCL facility.
 *	Werner Almesberger	:	Zero fragment bug
 *		Alan Cox	:	RAW IP frame length bug
 *		Alan Cox	:	Outgoing firewall on build_xmit
 *		A.N.Kuznetsov	:	IP_OPTIONS support throughout the kernel
 *		Alan Cox	:	Multicast routing hooks
 *		Jos Vos		:	Do accounting *before* call_in_firewall
 *	Willy Konynenberg	:	Transparent proxying support
 *
 *
 *
 * To Fix:
 *		IP fragmentation wants rewriting cleanly. The RFC815 algorithm is much more efficient
 *		and could be made very efficient with the addition of some virtual memory hacks to permit
 *		the allocation of a buffer that can then be 'grown' by twiddling page tables.
 *		Output fragmentation wants updating along with the buffer management to use a single
 *		interleaved copy algorithm so that fragmenting has a one copy overhead. Actual packet
 *		output should probably do its own fragmentation at the UDP/RAW layer. TCP shouldn't cause
 *		fragmentation anyway.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) "IPv4: " fmt

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <net/inet_ecn.h>
#include <linux/netfilter_ipv4.h>
#include <net/xfrm.h>
#include <linux/mroute.h>
#include <linux/netlink.h>

#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <net/capprobe.h>
#include <net/net_namespace.h>

//cs218 
static int cap_icmp_sn = 0;
static int cap_index = 0;
static int burst_size = 100;

extern long cap_sn[CLJ_MAX];
extern long cap_send_sec[CLJ_MAX];
extern long cap_send_usec[CLJ_MAX];
extern long cap_recv1_sec[CLJ_MAX];
extern long cap_recv1_usec[CLJ_MAX];
extern long cap_recv2_sec[CLJ_MAX];
extern long cap_recv2_usec[CLJ_MAX];
extern long cap_size;
extern long cap_id;
extern long cap_C;		//cs218_prob
extern long cap_RTT_SUM;
extern long cap_RTT1;
extern long cap_RTT2;

static __u32 cap_src;
static __u32 cap_dst;
struct sk_buff *cap_skb = NULL;
static struct timer_list tl;
static struct net_device *cap_dev;

//cs218 end

void process_capprobe(struct sk_buff *skb, struct net_device *dev, struct iphdr *iph);
/*
 *	Process Router Attention IP option (RFC 2113)
 */
bool ip_call_ra_chain(struct sk_buff *skb)
{
	struct ip_ra_chain *ra;
	u8 protocol = ip_hdr(skb)->protocol;
	struct sock *last = NULL;
	struct net_device *dev = skb->dev; 

	for (ra = rcu_dereference(ip_ra_chain); ra; ra = rcu_dereference(ra->next)) {
		struct sock *sk = ra->sk;

		/* If socket is bound to an interface, only report
		 * the packet if it came  from that interface.
		 */
		if (sk && inet_sk(sk)->inet_num == protocol &&
		    (!sk->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == dev->ifindex) &&
		    net_eq(sock_net(sk), dev_net(dev))) {
			if (ip_is_fragment(ip_hdr(skb))) {
				if (ip_defrag(skb, IP_DEFRAG_CALL_RA_CHAIN))
					return true;
			}
			if (last) {
				struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);
				if (skb2)
					raw_rcv(last, skb2);
			}
			last = sk;
		}
	}

	if (last) {
		raw_rcv(last, skb);
		return true;
	}
	return false;
}

static int ip_local_deliver_finish(struct sock *sk, struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);

	__skb_pull(skb, skb_network_header_len(skb));

	rcu_read_lock();
	{
		int protocol = ip_hdr(skb)->protocol;
		const struct net_protocol *ipprot;
		int raw;

	resubmit:
		raw = raw_local_deliver(skb, protocol);

		ipprot = rcu_dereference(inet_protos[protocol]);
		if (ipprot) {
			int ret;

			if (!ipprot->no_policy) {
				if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					kfree_skb(skb);
					goto out;
				}
				nf_reset(skb);
			}
			ret = ipprot->handler(skb);
			if (ret < 0) {
				protocol = -ret;
				goto resubmit;
			}
			IP_INC_STATS_BH(net, IPSTATS_MIB_INDELIVERS);
		} else {
			if (!raw) {
				if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					IP_INC_STATS_BH(net, IPSTATS_MIB_INUNKNOWNPROTOS);
					icmp_send(skb, ICMP_DEST_UNREACH,
						  ICMP_PROT_UNREACH, 0);
				}
				kfree_skb(skb);
			} else {
				IP_INC_STATS_BH(net, IPSTATS_MIB_INDELIVERS);
				consume_skb(skb);
			}
		}
	}
 out:
	rcu_read_unlock();

	return 0;
}

/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
int ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */

	if (ip_is_fragment(ip_hdr(skb))) {
		if (ip_defrag(skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}

	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN, NULL, skb,
		       skb->dev, NULL,
		       ip_local_deliver_finish);
}

static inline bool ip_rcv_options(struct sk_buff *skb)
{
	struct ip_options *opt;
	const struct iphdr *iph;
	struct net_device *dev = skb->dev;

	/* It looks as overkill, because not all
	   IP options require packet mangling.
	   But it is the easiest for now, especially taking
	   into account that combination of IP options
	   and running sniffer is extremely rare condition.
					      --ANK (980813)
	*/
	if (skb_cow(skb, skb_headroom(skb))) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	iph = ip_hdr(skb);
	opt = &(IPCB(skb)->opt);
	opt->optlen = iph->ihl*4 - sizeof(struct iphdr);

	if (ip_options_compile(dev_net(dev), opt, skb)) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
		goto drop;
	}

	if (unlikely(opt->srr)) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		if (in_dev) {
			if (!IN_DEV_SOURCE_ROUTE(in_dev)) {
				if (IN_DEV_LOG_MARTIANS(in_dev))
					net_info_ratelimited("source route option %pI4 -> %pI4\n",
							     &iph->saddr,
							     &iph->daddr);
				goto drop;
			}
		}

		if (ip_options_rcv_srr(skb))
			goto drop;
	}

	return false;
drop:
	return true;
}

int sysctl_ip_early_demux __read_mostly = 1;
EXPORT_SYMBOL(sysctl_ip_early_demux);

static int ip_rcv_finish(struct sock *sk, struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;

	if (sysctl_ip_early_demux && !skb_dst(skb) && !skb->sk) {
		const struct net_protocol *ipprot;
		int protocol = iph->protocol;

		ipprot = rcu_dereference(inet_protos[protocol]);
		if (ipprot && ipprot->early_demux) {
			ipprot->early_demux(skb);
			/* must reload iph, skb->head might have changed */
			iph = ip_hdr(skb);
		}
	}

	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */
	if (!skb_dst(skb)) {
		int err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
					       iph->tos, skb->dev);
		if (unlikely(err)) {
			if (err == -EXDEV)
				NET_INC_STATS_BH(dev_net(skb->dev),
						 LINUX_MIB_IPRPFILTER);
			goto drop;
		}
	}

#ifdef CONFIG_IP_ROUTE_CLASSID
	if (unlikely(skb_dst(skb)->tclassid)) {
		struct ip_rt_acct *st = this_cpu_ptr(ip_rt_acct);
		u32 idx = skb_dst(skb)->tclassid;
		st[idx&0xFF].o_packets++;
		st[idx&0xFF].o_bytes += skb->len;
		st[(idx>>16)&0xFF].i_packets++;
		st[(idx>>16)&0xFF].i_bytes += skb->len;
	}
#endif

	if (iph->ihl > 5 && ip_rcv_options(skb))
		goto drop;

	rt = skb_rtable(skb);
	if (rt->rt_type == RTN_MULTICAST) {
		IP_UPD_PO_STATS_BH(dev_net(rt->dst.dev), IPSTATS_MIB_INMCAST,
				skb->len);
	} else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS_BH(dev_net(rt->dst.dev), IPSTATS_MIB_INBCAST,
				skb->len);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

/*
 * 	Main IP Receive routine.
 */
unsigned long rtt1, rtt2, rtt, disp;

int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	const struct iphdr *iph;
	u32 len;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;


	IP_UPD_PO_STATS_BH(dev_net(dev), IPSTATS_MIB_IN, skb->len);

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto out;
	}

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;

	iph = ip_hdr(skb);

	/*
	 *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */

	if (iph->ihl < 5 || iph->version != 4)
		goto inhdr_error;

	BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
	BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
	BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
	IP_ADD_STATS_BH(dev_net(dev),
			IPSTATS_MIB_NOECTPKTS + (iph->tos & INET_ECN_MASK),
			max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

	if (!pskb_may_pull(skb, iph->ihl*4))
		goto inhdr_error;

	iph = ip_hdr(skb);

	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto csum_error;

	len = ntohs(iph->tot_len);
	if (skb->len < len) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	} else if (len < (iph->ihl*4))
		goto inhdr_error;

	/* Our transport medium may have padded the buffer out. Now we know it
	 * is IP we can trim to the true length of the frame.
	 * Note this now means skb->len holds ntohs(iph->tot_len).
	 */
	if (pskb_trim_rcsum(skb, len)) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	skb->transport_header = skb->network_header + iph->ihl*4;

	/* Remove any debris in the socket control block */
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));

	/* Must drop socket now because of tproxy. */
	skb_orphan(skb);

	//cs218
	if (iph->protocol == IPPROTO_ICMP)
	 	process_capprobe(skb, dev, iph);

	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING, NULL, skb,
		       dev, NULL,
		       ip_rcv_finish);

csum_error:
	IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_CSUMERRORS);
inhdr_error:
	IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;
}

void capprobe_main(unsigned long packet_pairs_sent) 
{
    int i, last_ok;
    struct timeval tv;

    do_gettimeofday(&tv);

    if (packet_pairs_sent>burst_size) 
    	return;

    if (packet_pairs_sent == 1) 
    	do_gettimeofday(&cap_time_start);

    if (cap_size <= 0) 
    	return;

    if (cap_size < 100)
    	cap_size = CAP_INIT_SIZE_1; //CAP_INIT_SIZE_1 = 1200

    cap_icmp_sn ++;
    cap_icmp_sn %= 128;
    cap_sn[cap_index] = cap_icmp_sn;
    cap_send_sec[cap_index] = tv.tv_sec;
    cap_send_usec[cap_index] = tv.tv_usec;
    cap_recv1_sec[cap_index] = -1;
    cap_recv1_usec[cap_index] = -1;
    cap_recv2_sec[cap_index] = -1;
    cap_recv2_usec[cap_index] = -1;
    cap_index++;
    cap_index %= CLJ_MAX;	//50

    last_ok = 1;
    for(i=0; i<2; i++) {
        if (last_ok) {
            //if (cap_skb) kfree_skb(cap_skb);
            fill_packet();
        } else {
            i--;
        }

        /*spin_lock_bh(&cap_dev->tx_global_lock);*/
        __netif_tx_lock_bh(cap_dev->_tx);
        if (!netif_queue_stopped(cap_dev)) {
            atomic_inc(&cap_skb->users);

            int *ret_val;
            cap_skb = dev_hard_start_xmit(cap_skb,cap_dev,cap_dev->_tx,ret_val);
            if (*ret_val) {
                atomic_dec(&cap_skb->users);
                if (net_ratelimit()) {
                    printk(KERN_INFO "Hard xmit error\n");
                }
                last_ok = 0;
            } else last_ok = 1;
        } else last_ok = 0;

        if (last_ok&&i==0) {
            cap_icmp_sn ++;
            cap_icmp_sn %= 128;
        }
        __netif_tx_unlock_bh(cap_dev->_tx);
        /*spin_unlock_bh(&cap_dev->tx_global_lock);*/
    }

    if (cap_recv_num < 5) {
        if (cap_RTT2 >= 10000000000)
        	mod_timer(&tl, jiffies + msecs_to_jiffies(500));
            /*tl.expires = jiffies + 0.5 * HZ; // 0.5 second //cs218_prob*/
        else {
            if (rtt2 < 5*cap_RTT2)
				mod_timer(&tl, usecs_to_jiffies(rtt2) + msecs_to_jiffies(25*rtt2/1000));	//cs218_prob..some precision lost
                //tl.expires = jiffies + (rtt2 * 1.25 / 1000000) *HZ; // cap_RTT2 second (double removed)
            else
            	mod_timer(&tl, jiffies + msecs_to_jiffies(500));
                /*tl.expires = jiffies + 0.5 *HZ;	*/
        }
    } else {
        long send_rate = cap_C * 5 / 100; // Mbps; 5% of capacity //cs218_prob
        long pp_interval = cap_size * 8 / send_rate / 1000000; // ms  //double replaced by int here //cs218_prob

        mod_timer(&tl, jiffies + pp_interval);
        tl.expires = jiffies + pp_interval *HZ;		//cs218_prob
//		printk (KERN_ERR "send rate: %ld.%03ld Mbps, pp_interval: %ld.%03ld msec\n",
//			(long)(send_rate * 100)/100, (long)(send_rate * 1000) % 1000,
//			(long)(pp_interval * 10000) / 10, (long)(pp_interval * 1000000) % 1000);

    }
    tl.data = (unsigned long) packet_pairs_sent+1;
    
    return;
}

void process_capprobe(struct sk_buff *skb, struct net_device *dev, struct iphdr *iph)
{
	//cs218
	struct icmphdr *icmph;
    u8 *tmphdr;
    u8 sn1,sn2,sn;
    u8 id1,id2;
    int id;
    int clj;
    int i,kk;
    struct timeval tv;
    double C;
    __u32 pksize;

    cap_dev = dev;

    do_gettimeofday(&tv);
	//cs218 end

    //icmph = skb->h.icmph; 		//cs218_prob

    tmphdr = (void *)skb->data;
    tmphdr += 20; // now tmphdr point to the icmp packet

    sn = *(u8*)tmphdr;

    if (sn==0) { // ICMP reply
        sn1 = *(u8*)(tmphdr+6);
        sn2 = *(u8*)(tmphdr+7);

        id1 = *(u8*)(tmphdr+4);
        id2 = *(u8*)(tmphdr+5);

        id = id2*256+id1;

        clj = sn1*256+sn2;
        //printk (KERN_ERR "%ld %ld ICMP RECV ID_%d sn= %d  (sec,usec)= %ld %ld\n",cap_size, cap_id, id,clj,tv.tv_sec, tv.tv_usec);

        // check id and packet size
        //pksize = cap_size; // need to change here!!
        pksize = ntohs(iph->tot_len);
        pksize += 14;   // ethernet header

        if (pksize>0&&pksize==cap_size&&id==cap_id) {
            for (kk=0; kk<CLJ_MAX; kk++) {
                if (clj==cap_sn[kk]) { // 1st packet of the packet pair
                    cap_recv1_sec[kk] = tv.tv_sec;
                    cap_recv1_usec[kk] = tv.tv_usec;
                    break;
                } else if (clj==cap_sn[kk]+1) { // 2nd packet of the packet pair
                    cap_recv2_sec[kk] = tv.tv_sec;
                    cap_recv2_usec[kk] = tv.tv_usec;
                    if (cap_recv1_sec[kk]>0 && cap_recv1_usec[kk]>0) {
                        disp = 1000000 * (cap_recv2_sec[kk] - cap_recv1_sec[kk]) + (cap_recv2_usec[kk] - cap_recv1_usec[kk]);
                        rtt1 = 1000000 * (cap_recv1_sec[kk] - cap_send_sec[kk]) + (cap_recv1_usec[kk] - cap_send_usec[kk]);
                        rtt2 = 1000000 * (cap_recv2_sec[kk] - cap_send_sec[kk]) + (cap_recv2_usec[kk] - cap_send_usec[kk]);
                        rtt = rtt1 + rtt2;
                        if (disp>0&&rtt1>0&&rtt2>0&&rtt>0&&rtt<100000000) {
                            C = 8 * pksize / (double)disp;	// Mbps			//cs218_prob
                            if (C > cap_C_max) cap_C_max = C;
                            if (C < cap_C_min) cap_C_min = C;
                            if (rtt<cap_RTT_SUM) {
                                double diff_c = cap_C - C;
                                if (diff_c<0) diff_c = 0 - diff_c;		//cs218_prob

                                cap_RTT_SUM = rtt;
                                cap_C = C;
                                cap_C_same = 0;
                                if (diff_c<0.02*cap_C) cap_C_same2++;
                                else cap_C_same2 = 0;
                            } else {
                                cap_C_same++;
                                cap_C_same2++;
                            }
                            if (rtt1<cap_RTT1) cap_RTT1 = rtt1;
                            if (rtt2<cap_RTT2) cap_RTT2 = rtt2;

                            cap_recv_num++;

                            //printk (KERN_ERR "ICMP RECV %u bytes from %s ID_%d sn= %d  c=( %ld.%03ld , %ld.%03ld ) %ld.%03ld  %ld.%03ld\n",
                            long mds = cap_RTT1 + cap_RTT2;
                            long msd = cap_RTT_SUM;
                            double mm = (double)(msd - mds)/(double)msd;	//cs218_prob
                            if (cap_recv_num%1==0) {
                                printk (KERN_ERR "%d, %d  c=( %ld.%03ld , %ld.%03ld ) %ld.%03ld  %ld.%03ld %ld.%03ld %ld.%03ld %ld.%05ld %ld %ld %ld\n",
                                        cap_recv_num, cap_C_same, ((long)(C*10))/10, (long)(C*1000)%1000,
                                        ((long)(cap_C*10))/10, (long)(cap_C*1000)%1000,
                                        ((long)(rtt1))/1000000, (long)(rtt1)%1000000,
                                        ((long)(rtt2))/1000000, (long)(rtt2)%1000000,
                                        ((long)(mds))/1000000, (long)(mds)%1000000,
                                        ((long)(msd))/1000000, (long)(msd)%1000000,
                                        ((long)(mm*10000))/100, ((long)(mm*10000000))%100000,
                                        cap_RTT1, cap_RTT2, cap_RTT_SUM);		//cs218_prob
                            }
                        } else {
                            // disp = 0, ignore it!!
                        }
                    } else {
                        // disorder, ignore it!
                    }
                    break;
                } else continue;
            }
            if (cap_C_same2>=CAP_SAME_MAX||(cap_recv_num>=CAP_SAMPLES&&kk<CLJ_MAX&&cap_C_same>=CAP_SAME)) {

                double diff_cap_RTT_SUM = cap_RTT_SUM - cap_RTT1 - cap_RTT2;
                diff_cap_RTT_SUM /= cap_RTT_SUM;

                // check convergence
                if (cap_C_same2>=CAP_SAME_MAX||diff_cap_RTT_SUM < 0.01) {
                    long total_time;
                    double diff_c, avg_c;

                    printk(	KERN_ERR "rtt1: %ld.%03ld, rtt2: %ld.%03ld, diff_cap_RTT_SUM: %ld.%03ld # of samples: %d pksize: %ld bytes\n",
                            (long)(cap_RTT1*100), (long)(cap_RTT1*10000) % 100,
                            (long)(cap_RTT2*100), (long)(cap_RTT2*10000) % 100,
                            (long)(diff_cap_RTT_SUM*100), (long)(diff_cap_RTT_SUM*10000) % 100,
                            cap_recv_num, cap_size); 	//cs218_prob
                    do_gettimeofday(&cap_time_end);
                    //del_timer(&tl);
                    total_time = 1000000 * (cap_time_end.tv_sec - cap_time_start.tv_sec) +
                                 (cap_time_end.tv_usec - cap_time_start.tv_usec);

                    // calculate variance
                    if ((cap_C_max / cap_C_min)> 5) cap_var++;
                    else cap_var--;
                    printk(KERN_ERR "%ld.%03ld cap_same: %d cap_var: %d   cap_C_min|max: %ld.%03ld  %ld.%03ld\n",
                           (long)(100*cap_C_max/cap_C_min)/100, (long)(1000*cap_C_max/cap_C_min)%1000,
                           cap_C_same, cap_var, ((long)(cap_C_min*10))/10, (long)(cap_C_min*1000)%1000,
                           ((long)(cap_C_max*10))/10, (long)(cap_C_max*1000)%1000);

                    //cap_C = 8 * pksize / (double)(cap_RTT2 - cap_RTT1);	// Mbps
                    printk(KERN_ERR "CapProbe PHASE: %d-%d  time = %ld.%06ld sec C = %ld.%03ld\n",
                           cap_run, cap_phase, total_time/1000000, total_time % 1000000,
                           ((long)(cap_C*10))/10, (long)(cap_C*1000)%1000);

                    cap_size = 0;
                    if (cap_C_same2>=CAP_SAME_MAX) {
                        del_timer(&tl);
                        cap_size = 0;
                        printk(KERN_ERR "Stable CapProbe Finished! Total time = %ld.%06ld sec C = %ld.%03ld\n",
                               total_time/1000000, total_time % 1000000,
                               ((long)(cap_C*10))/10, (long)(cap_C*1000)%1000);
                    } else if (cap_phase==CAP_PHASE_1) {
                        cap_C_results[0] = cap_C;
                        cap_phase = CAP_PHASE_2;
                        cap_size = CAP_INIT_SIZE_2;
                    } else if (cap_phase==CAP_PHASE_2) {
                        cap_C_results[1] = cap_C;
                        diff_c = (cap_C_results[0] - cap_C_results[1])/2;
                        avg_c = (cap_C_results[0] + cap_C_results[1])/2;

                        if (diff_c<0) diff_c = (0 - diff_c) / avg_c;
                        else diff_c = diff_c / avg_c;

                        if (diff_c<0.05) {
                            del_timer(&tl);
                            cap_size = 0;
                            printk(KERN_ERR "CapProbe Finished! Total time = %ld.%06ld sec C = %ld.%03ld\n",
                                   total_time/1000000, total_time % 1000000,
                                   ((long)(avg_c*10))/10, (long)(avg_c*1000)%1000);
                        } else {
                            printk(KERN_ERR "... Restart CapProbe ...\n");
                            if (cap_run%2==0) {
                                // adjust packet size
                                if (cap_var>0) {
                                    CAP_INIT_SIZE_1 += (long)(CAP_INIT_SIZE_1 * 0.2);
                                    CAP_INIT_SIZE_2 += (long)(CAP_INIT_SIZE_2 * 0.2);
                                } else if (cap_var<0) {
                                    CAP_INIT_SIZE_1 -= (long)(CAP_INIT_SIZE_1 * 0.2);
                                    CAP_INIT_SIZE_2 -= (long)(CAP_INIT_SIZE_2 * 0.2);
                                }
                                if (CAP_INIT_SIZE_1>CAP_SIZE_MAX) CAP_INIT_SIZE_1 = CAP_SIZE_MAX;
                                if (CAP_INIT_SIZE_2>CAP_SIZE_MAX) CAP_INIT_SIZE_2 = CAP_SIZE_MAX;
                                if (CAP_INIT_SIZE_1<CAP_SIZE_MIN) CAP_INIT_SIZE_1 = CAP_SIZE_MIN;
                                if (CAP_INIT_SIZE_2<CAP_SIZE_MIN) CAP_INIT_SIZE_2 = CAP_SIZE_MIN;
                                cap_var = 0;
                            }
                            cap_run++;
                            cap_phase = CAP_PHASE_1;
                            cap_size = CAP_INIT_SIZE_1;
                        }
                    } else if (cap_phase==CAP_PHASE_3) {

                    } else {
                        printk(KERN_ERR "CAP_PHASE error!\n");
                    }
                    // re-initialize
                    cap_id++;
                    cap_RTT_SUM = 10000000000;
                    cap_RTT1 = 10000000000;
                    cap_RTT2 = 10000000000;
                    cap_C_min = 100000000;
                    cap_C_max = 0;
                    cap_C_same = 0;
                    cap_C_same2 = 0;
                    cap_C = 0;
                    cap_recv_num = 0;
                    for (i=0; i<CLJ_MAX; i++) {
                        cap_sn[i] = -1;
                        cap_send_sec[i] = -1;
                        cap_send_usec[i] = -1;
                    }
                } else {
                    if (cap_recv_num<CAP_SAMPLES_MAX) {
                        if (cap_phase==CAP_PHASE_1) cap_size = CAP_INIT_SIZE_1;
                        else cap_size = CAP_INIT_SIZE_2;
                    } else {
                        printk(KERN_ERR "C = %ld.%03ld\n",
                               ((long)(cap_C*10))/10, (long)(cap_C*1000)%1000);
                        if (cap_phase==CAP_PHASE_1) cap_size = CAP_INIT_SIZE_1;
                        else cap_size = CAP_INIT_SIZE_2;
                        // re-initialize

                        cap_id++;
                        cap_RTT_SUM = 10000000000;
                        cap_RTT1 = 10000000000;
                        cap_RTT2 = 10000000000;
                        cap_C_min = 100000000;
                        cap_C_max = 0;
                        cap_C = 0;
                        cap_recv_num = 0;
                        for (i=0; i<CLJ_MAX; i++) {
                            cap_sn[i] = -1;
                            cap_send_sec[i] = -1;
                            cap_send_usec[i] = -1;
                        }
                    }
                }
            }
        }
    }
}

/*static int fill_packet()
{
    return 0;
}
*/

static int fill_packet()
{
    __u8 *eth;
    int datalen, iplen, icmp_len;
    struct iphdr *iph;
    struct icmphdr *icmph;
    int ii;

    u_short *w;
    int len ;
    int sum ;
    int nleft ;
    u_short answer ;


    if (cap_skb) {
        kfree_skb(cap_skb);
    }
    cap_skb = alloc_skb(cap_size+64+16,GFP_ATOMIC);
    if (!cap_skb) {
        printk(KERN_ERR "No memory");
        return 0;
    }
    skb_reserve(cap_skb,16);

    /*  Reserve for ethernet and IP header  */
    eth = (__u8 *) skb_push(cap_skb, 14);
    iph = (struct iphdr *)skb_put(cap_skb, sizeof(struct iphdr));
    icmph = (struct icmphdr *)skb_put(cap_skb, sizeof(struct icmphdr));

    memcpy(eth+6, (const void *)cap_dev->dev_addr,6);
    eth[0] = 0x00;
    eth[1] = 0x00;
    eth[2] = 0x0C;
    eth[3] = 0x07;
    eth[4] = 0xAC;
    eth[5] = 0x88;
    eth[12] = 0x08;
    eth[13] = 0x00;
    /*
    	printk(KERN_ERR "%ld %ld %d, eth: ",cap_size, cap_id, cap_icmp_sn);
    	for(ii=0;ii<14;ii++) printk(KERN_ERR "%d ",eth[ii]);
    	printk(KERN_ERR "\n");
    */
    datalen = cap_size - 14 - 20 - 8; /* Eth + IPh + ICMPh*/

    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->un.echo.id = cap_id;
    icmph->un.echo.sequence = htons(cap_icmp_sn);
    icmp_len = datalen + 8;

    iph->ihl = 5;
    iph->version = 4;
    iph->ttl = 64;
    iph->tos = 0;
    iph->protocol = IPPROTO_ICMP; /* ICMP */
    iph->saddr = cap_src;
    iph->daddr = cap_dst;
    /*
    	printk(KERN_ERR "iph_src: ");
    	for(ii=12;ii<16;ii++) printk(KERN_ERR "%d ",(__u8)*((__u8 *)iph+ii));
    	printk(KERN_ERR "\n");
    	printk(KERN_ERR "iph_dst: ");
    	for(ii=16;ii<20;ii++) printk(KERN_ERR "%d ",(__u8)*((__u8 *)iph+ii));
    	printk(KERN_ERR "\n");
    */
    iph->frag_off = 0x0040;
    iplen = 20 + 8 + datalen;
    //The htons() function converts the unsigned short integer hostshort from host byte order to network byte order.
    iph->tot_len = htons(iplen);
    iph->check = 0;
    iph->check = ip_fast_csum((void *) iph, iph->ihl);
    cap_skb->protocol = __constant_htons(ETH_P_IP);
    cap_skb->mac_header = ((u8 *)iph) - 14;		//.raw removed cs218_prob
    cap_skb->dev = cap_dev;
    cap_skb->pkt_type = PACKET_HOST;
    skb_put(cap_skb, datalen);

    icmph->checksum = 0;
//=======================================
    w = (u_short *)icmph;
    len = icmp_len;
    sum = 0;
    nleft = len;
    answer = 0;
    /*
     *
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1)
        sum += htons(*(u_char *)w << 8);

    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);                     /* add carry */
    answer = ~sum;                          /* truncate to 16 bits */
    icmph->checksum = answer;
//=======================================

    return 1;
}

static int read_proc_capprobe_if(char *buf, char **start, off_t offset, int count, int *eof, void *priv)
{
	int k;
    
    k = sprintf(buf,"%s",cap_device);
    return k;
}
static int write_proc_capprobe_if(struct file* file, const char* buffer, unsigned long count, void* data)
{
	int k = count;
	char buf[1000];

    //MOD_INC_USE_COUNT;
	
	memset(buf,0,1000);
	copy_from_user(cap_device, buffer, count);
	cap_device[count-1] = '\0';
    
    ////MOD_DEC_USE_COUNT;
	return k;
}

char *in_ntoa(__u32 in)
{
    static char buff[18];
    char *p;

    p = (char *) &in;
    sprintf(buff, "%d.%d.%d.%d",
            (p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));
    return(buff);
}

static int read_proc_capprobe(char *buf, char **start, off_t offset, int count, int *eof, void *priv)
{
	int k;
    k = sprintf(buf,"%s",in_ntoa(cap_dst));
    return k;
}

static int write_proc_capprobe(struct file* file, const char* buffer, unsigned long count, void* data)
{
	char dest_ip[1000];					//stores destination ip address in kernel space as received from user space buffer, temporarily
	int start_capprobe_after = 500;		//start capprobe after this time period (in ms)

	CAP_INIT_SIZE_1 = INIT_SIZE_1;
	CAP_INIT_SIZE_2 = INIT_SIZE_2;
	cap_size = CAP_INIT_SIZE_1;
	cap_phase = CAP_PHASE_1;
	cap_id = 101;
	cap_icmp_sn = 0;
	cap_RTT_SUM = 10000000000;
	cap_RTT1 = 10000000000;
	cap_RTT2 = 10000000000;
	cap_C_min = 100000000;
	cap_C_max = 0;
	cap_C = 0;
	cap_run = 1;
	cap_var = 0;
	cap_recv_num = 0;

	for (i=0;i<CLJ_MAX;i++) {
		cap_sn[i] = -1;
		cap_send_sec[i] = -1;
		cap_send_usec[i] = -1;
	}

    //get the destination machine's ip address from the buffer and store it as cap_dst
	del_timer(&tl);		//clear timer, if exists

	memset(dest_ip, 0, 1000);
	copy_from_user(dest_ip, buffer, count);
	dest_ip[count-1] = '\0';
	cap_dst = in_aton(dest_ip);

	if (cap_dst==0) {			
		return count;			//error condition, no ip address received from user space
	}

	//get a pointer to the device by its name (here, eth0)
	rtnl_lock();
	cap_dev = __dev_get_by_name(&init_net, cap_device);			
	dev_hold(cap_dev);
	rtnl_unlock();

	//get the host machine's ip address from the device and store it as cap_src
	cap_src = 0;
	if (cap_dev->ip_ptr) {
		struct in_device *in_dev = cap_dev->ip_ptr;
		cap_src = in_dev->ifa_list->ifa_address;
	}

	printk(KERN_ERR "\n\n Start CapProbe to %s\n",dest_ip);

	setup_timer(&tl, capprobe_main, (unsigned long) 1);						//initialize timer to trigger capprobe_main
	mod_timer(&tl, jiffies + msecs_to_jiffies(start_capprobe_after));		//set expire time to 

    return k;
}

static struct proc_dir_entry *proc_capprobe;
static struct proc_dir_entry *proc_capprobe_if;
static char *dirname = "capprobe";

static const struct file_operations proc_file_fops_capprobe = {
	.owner = THIS_MODULE,
	.read  = read_proc_capprobe,
	.write  = write_proc_capprobe,
};

static const struct file_operations proc_file_fops_capprobe_if = {
	.owner = THIS_MODULE,
	.read  = read_proc_capprobe_if,
	.write  = write_proc_capprobe_if,
};

/*static inline struct proc_dir_entry *proc_create(
        const char *name, umode_t mode, struct proc_dir_entry *parent,
        const struct file_operations *proc_fops)
 {
        return proc_create_data(name, mode, parent, proc_fops, NULL);
 }

struct proc_dir_entry *proc_file_entry;


int __init init_module(void){
  proc_file_entry = proc_create("proc_file_name", 0, NULL, &proc_file_fops);
  if(proc_file_entry == NULL)
   return -ENOMEM;
  return 0;
}

 */

int remove_proc_dir(void)
{
    proc_remove(proc_capprobe);
    return 1;
}

int create_proc_dir(void)
{
	proc_capprobe = proc_mkdir(dirname, NULL);	//make dir capprobe in /proc
	if(proc_capprobe == NULL)
		return -ENOMEM;

	return 1;
}

static int __init capprobe_init(void)
{
	char buf[255];

	cap_size = CAP_INIT_SIZE_1;
	cap_phase = CAP_PHASE_1;
	cap_id = 101;
	strcpy(cap_device,"eth0");
	create_proc_dir();

    proc_create("probe_info", 0, proc_capprobe, &proc_file_fops_capprobe);
    proc_create("device", 0, proc_capprobe, &proc_file_fops_capprobe_if);

	/*sprintf(buf,"sys/capprobe/CapProbe");
	proc_capprobe = create_proc_entry(buf,0644,0);
	proc_capprobe->read_proc = read_proc_capprobe;
	proc_capprobe->write_proc = write_proc_capprobe;
	proc_capprobe->owner = THIS_MODULE;

	sprintf(buf,"capprobe/device");
	proc_capprobe_if = create_proc_entry(buf,0644,0);
	proc_capprobe_if->read_proc = read_proc_capprobe_if;
	proc_capprobe_if->write_proc = write_proc_capprobe_if;
	proc_capprobe_if->owner = THIS_MODULE;*/

	return 0;
}

static void __exit capprobe_cleanup(void)
{
        remove_proc_entry("capprobe/probe_info", NULL);
        remove_proc_entry("capprobe/device", NULL);
        proc_remove(proc_capprobe);
}

module_init(capprobe_init);
module_exit(capprobe_cleanup);