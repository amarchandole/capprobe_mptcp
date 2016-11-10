/*
 * CapProbe revised version for Linux 4.1
 *
 * by Amar Chandole, amar.chandole@cs.ucla.edu,
 *    Yuanzhi Gao, yuanzhi@cs.ucla.edu,
 *    Ameya Kabre, akabre@cs.ucla.edu
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <net/net_namespace.h>
#include <linux/kernel.h>
#include "capprobe.h"

//CapProbe round trip time variables
long cap_RTT1    = TOO_LARGE_DELAY;
long cap_RTT2    = TOO_LARGE_DELAY;
long cap_RTT_SUM = TOO_LARGE_DELAY;
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
int cap_run = 0;
long cap_id = -1;
long cap_size = -1;
static int cap_index = 0;
static int cap_icmp_serialnum = 0;
long CAP_INIT_SIZE_1 = INIT_SIZE_1;
long CAP_INIT_SIZE_2 = INIT_SIZE_2;

//CapProbe necessary struct declarations
struct sk_buff *cap_skb = NULL;
static struct net_device *cap_dev;
static struct timer_list tl;
static struct proc_dir_entry *proc_capprobe;
static struct proc_dir_entry *proc_capprobe_if;
//static char *dirname = "capprobe";

//CapProbe timing related variables
struct timeval cap_time_start;
struct timeval cap_time_end;
static long burst_size = 10;            //default value. changed as per user input into /sys/capprobe/device later
static long burst_interval = 500;   //default value. changed as per user input into /sys/capprobe/device later

//CapProbe route capacity related variables
int cap_C_same = 0;
int cap_C_same2 = 0;
int cap_variance = 0;
long cap_C_results[3];          
long cap_C = 0;                 
long cap_C_max = 0;             
long cap_C_min = INFINITE;      

//CapProbe src,dest mac & ip related variables
static __u32 cap_src;           //Own computer IP
static __u32 cap_dst;           //Ultimate destination to which capacity is to be tested
char cap_device[100];           //to copy device name from userspace

static int fill_packet(void);

void capprobe_main(unsigned long packet_pairs_sent) 
{
    int cpu;
    int i, last_ok;
    int ret_val = 0;
    struct timeval tv;

    do_gettimeofday(&tv);

    if (packet_pairs_sent > burst_size) 
        return;

    //get start time for capprobe if this is the first call to capprobe_main()
    if (packet_pairs_sent == 1) 
        do_gettimeofday(&cap_time_start);

    if (cap_size <= 0) 
        return;

    if (cap_size < 100)                                 //cs218_prob
        cap_size = CAP_INIT_SIZE_1;                     //CAP_INIT_SIZE_1 = 1200

    cap_icmp_serialnum ++;
    cap_icmp_serialnum %= 128;                          //cs218_prob unknown

    cap_serialnum[cap_index] = cap_icmp_serialnum;

    //timing for sent packet pair
    cap_send_sec[cap_index] = tv.tv_sec;
    cap_send_usec[cap_index] = tv.tv_usec;

    //timing for received packet pair
    cap_recv1_sec[cap_index] = -1;
    cap_recv1_usec[cap_index] = -1;
    cap_recv2_sec[cap_index] = -1;
    cap_recv2_usec[cap_index] = -1;

    cap_index++;
    cap_index %= burst_size;                

    //status of last packet transmission
    last_ok = 1;

    //send packet pair
    for(i=0; i<2; i++) 
    {
        if (last_ok)                                    //if last tx ok: send next packet 
        {
            //if (cap_skb) kfree_skb(cap_skb);          //remove while testing if not needed
            fill_packet();
        } 
        else 
        {
            i--;
        }

        cpu = smp_processor_id(); /* ok because BHs are off */

        if (cap_dev->_tx->xmit_lock_owner != cpu) 
        {

            HARD_TX_LOCK(cap_dev, cap_dev->_tx, cpu);
            if (!netif_xmit_stopped(cap_dev->_tx)) 
            {
                __this_cpu_inc(xmit_recursion);
                cap_skb = dev_hard_start_xmit(cap_skb, cap_dev, cap_dev->_tx, &ret_val);
                __this_cpu_dec(xmit_recursion);

                if (dev_xmit_complete(ret_val)) 
                {
                    last_ok = 1;
                    printk(KERN_INFO "CS218 : Hard transmit success\n");
                    HARD_TX_UNLOCK(cap_dev, cap_dev->_tx);
                    goto out;
                }
                else
                {
                    printk(KERN_INFO "CS218 : Hard transmit failed");
                }
            }

            HARD_TX_UNLOCK(cap_dev, cap_dev->_tx);
            printk(KERN_INFO "CS218 : netif_xmit_stopped!");
            net_crit_ratelimited("CS218 : Virtual device %s asks to queue packet!\n",cap_dev->name);
            last_ok = 0;
        } 
        else 
        {
            last_ok = 0;
            printk(KERN_INFO "CS218 : CPU Owner");
        }

        out:

        if (last_ok && i==0)            //if first packet in packet pair is sent properly, inc the cap_icmp_serialnum
        {
            cap_icmp_serialnum ++;
            cap_icmp_serialnum %= 128;
        }
    }

     if (cap_recv_num<5) 
    {
        if (cap_RTT2>=TOO_LARGE_DELAY)
        {
                mod_timer(&tl, jiffies + msecs_to_jiffies(burst_interval));
        }
        else
        {
            if (rtt2 < 5 * cap_RTT2)
            {
                    mod_timer(&tl, jiffies + msecs_to_jiffies(((rtt2 * 10/8) / SEC_TO_USEC) * 1000));
            }
            else
            {
                    mod_timer(&tl, jiffies + msecs_to_jiffies(burst_interval));
            }
        }
    } 
    else 
    {
        long send_rate = cap_C / 20; // Mbps; 5% of capacity
        long pp_interval = SEC_TO_USEC * cap_size * 8 / send_rate; //
        mod_timer(&tl, jiffies + msecs_to_jiffies(pp_interval / 1000));

    }

    if (cap_recv_num<5) 
    {
        if (cap_RTT2>=TOO_LARGE_DELAY)
        {
                mod_timer(&tl, jiffies + msecs_to_jiffies(burst_interval));
        }
        else
        {
            if (rtt2 < 5 * cap_RTT2)
            {
                    mod_timer(&tl, jiffies + msecs_to_jiffies(((rtt2 * 10/8) / SEC_TO_USEC) * 1000));
            }
            else
            {
                    mod_timer(&tl, jiffies + msecs_to_jiffies(burst_interval));
            }
        }
    } 
    else 
    {
        long send_rate = cap_C / 20; // Mbps; 5% of capacity
        long pp_interval = SEC_TO_USEC * cap_size * 8 / send_rate; //
        mod_timer(&tl, jiffies + msecs_to_jiffies(pp_interval / 1000));

    }
    //modify the timer_list expiry time with a new time that is current time + burst_interval
    //mod_timer(&tl, jiffies + msecs_to_jiffies(burst_interval));
    //increment packet_pairs_sent by 1 and update the timer_list data
    tl.data = (unsigned long) packet_pairs_sent+1;
    return;
}

void process_capprobe(struct sk_buff *skb, struct net_device *dev, const struct iphdr *iph)
{
    long C;
    u8 *tmphdr;
    u8 serialnum1, serialnum2, serialnum;
    u8 id1,id2;

    int id;
    int tmpvar;
    int i, j;
    struct timeval tv;
    __u32 pksize;
    cap_dev = dev;
    do_gettimeofday(&tv);

    //icmph = skb->h.icmph;     //cs218_prob    not being used anywhere right now. Commented as 4.1 has no skb->h.icmph

    tmphdr = (void *)skb->data;
    tmphdr += 20;               // now tmphdr point to the icmp packet

    serialnum = *(u8*)tmphdr;

    if (serialnum == 0) 
    {   
        // ICMP reply
        serialnum1 = *(u8*)(tmphdr+6);
        serialnum2 = *(u8*)(tmphdr+7);

        id1 = *(u8*)(tmphdr+4);
        id2 = *(u8*)(tmphdr+5);

        id = id2*256 + id1;

        tmpvar = serialnum1*256 + serialnum2;
        //printk (KERN_INFO "CS218 : %ld %ld ICMP RECV ID_%d serialnum= %d  (sec,usec)= %ld %ld\n",cap_size, cap_id, id,tmpvar,tv.tv_sec, tv.tv_usec);

        //check id and packet size
        //pksize = cap_size;                                        //cs218_prob : need to change here!!
        pksize = ntohs(iph->tot_len);
        pksize += 14;                                               //ethernet header

        if (pksize > 0 && pksize == cap_size && id == cap_id) 
        {
            //printk(KERN_INFO "CS218 : CapProbe packet received by processCapprobe\n");
            for (j = 0; j < MAX_BURST_SIZE; j++) 
            {
                //printk(KERN_INFO "CS218 : CapProbe packet serial number: temp value: %u, serial 1st: %u, serial 2nd: %u", tmpvar, cap_serialnum[j], cap_serialnum[j] + 1);
                if (tmpvar == cap_serialnum[j])                     //1st packet of the packet pair found
                { 
                    //store receive time for this packet in the array
                    cap_recv1_sec[j] = tv.tv_sec;
                    cap_recv1_usec[j] = tv.tv_usec;
                    printk(KERN_INFO "CS218 : CapProbe first packet received\n");
                    break;
                } 
                else if (tmpvar == cap_serialnum[j]+1)              //2nd packet of the packet pair found
                {   
                    //store receive time for this packet in the array
                    cap_recv2_sec[j] = tv.tv_sec;
                    cap_recv2_usec[j] = tv.tv_usec;
                    printk(KERN_INFO "CS218 : CapProbe second packet received\n");

                    if (cap_recv1_sec[j]>0 && cap_recv1_usec[j]>0) 
                    {
                        //remove SEC_TO_USEC
                        disp = SEC_TO_USEC * (cap_recv2_sec[j] - cap_recv1_sec[j]) + (cap_recv2_usec[j] - cap_recv1_usec[j]);
                        rtt1 = SEC_TO_USEC * (cap_recv1_sec[j] - cap_send_sec[j]) + (cap_recv1_usec[j] - cap_send_usec[j]);
                        rtt2 = SEC_TO_USEC * (cap_recv2_sec[j] - cap_send_sec[j]) + (cap_recv2_usec[j] - cap_send_usec[j]);
                        rtt = rtt1 + rtt2;

                        if (disp>0 && rtt1>0 && rtt2>0 && rtt>0 && rtt<TOO_LARGE_DELAY) 
                        {
                            C = 8 * pksize * SEC_TO_USEC / disp;    // bits per sec             //cs218_prob
                            if (C > cap_C_max) 
                                cap_C_max = C;
                            if (C < cap_C_min) 
                                cap_C_min = C;
                            if (rtt<cap_RTT_SUM) 
                            {
                                long diff_c = cap_C - C;
                                if (diff_c<0) 
                                    diff_c = 0 - diff_c;            //cs218_prob

                                cap_RTT_SUM = rtt;
                                cap_C = C;
                                cap_C_same = 0;

                                if (diff_c < cap_C/50)              //if diff_c < 2% of cap_C
                                    cap_C_same2++;
                                else 
                                    cap_C_same2 = 0;
                            } 
                            else 
                            {
                                cap_C_same++;
                                cap_C_same2++;
                            }

                            if (rtt1<cap_RTT1) 
                                cap_RTT1 = rtt1;
                            if (rtt2<cap_RTT2) 
                                cap_RTT2 = rtt2;

                            cap_recv_num++;
                            printk(KERN_INFO "CS218 : Getting minimum delay value RTT1: %ld, RTT2: %ld, cap_receive number: %ld", cap_RTT1, cap_RTT2, cap_recv_num);
                            //cs218 large printk section removed, verify if needed later
                        } 
                        else 
                        {
                            // disp = 0, ignore it!!
                            printk(KERN_INFO "disp = 0");
                        }
                    } 
                    else 
                    {
                        // disorder, ignore it!
                        printk(KERN_INFO "CS218 : Packet pair sent in disorder, ignore it");
                    }
                    break;
                } 
                else 
                {
                    continue;
                }
            }

            if (cap_C_same2 >= CAP_SAME_MAX || (cap_recv_num >= CAP_SAMPLES && j < MAX_BURST_SIZE && cap_C_same >= CAP_SAME) ) 
            {
                long diff_cap_RTT_SUM;
                printk(KERN_INFO "CS218 : Further calculate difference of RTT\n");
                diff_cap_RTT_SUM = cap_RTT_SUM - cap_RTT1 - cap_RTT2;
                diff_cap_RTT_SUM *= 1000;           //to maintain precision
                diff_cap_RTT_SUM /= cap_RTT_SUM;

                // check convergence
                if (cap_C_same2>=CAP_SAME_MAX||diff_cap_RTT_SUM < 10)           //previously 0.01, changed to 10 because ---> diff_cap_RTT_SUM *= 1000;         //to maintain precision
                {
                    long total_time;
                    long diff_c, avg_c;

                    //cs218 large printk section removed, verify if needed later
                    printk(KERN_INFO "CS218 : Algorithm converged check\n");

                    do_gettimeofday(&cap_time_end);

                    //del_timer(&tl);
                    total_time = SEC_TO_USEC * (cap_time_end.tv_sec - cap_time_start.tv_sec) +
                    (cap_time_end.tv_usec - cap_time_start.tv_usec);

                    // calculate variance
                    if ((cap_C_max / cap_C_min)> 5) 
                    { 
                        cap_variance++;
                    }
                    else 
                    {
                        cap_variance--;
                    }

                    //cs218 large printk section removed, verify if needed later

                    //moving towards capprobe finish stage
                    cap_size = 0;
                    if (cap_C_same2 >= CAP_SAME_MAX) 
                    {
                        del_timer(&tl);
                        cap_size = 0;
                        printk(KERN_INFO "CS218 : Stable CapProbe Finished! Total time = %ld.%06ld sec C = %ld.%03ld\n",
                            total_time/1000000, total_time % 1000000,
                            ((long)(cap_C*10))/10, (long)(cap_C*1000)%1000);
                    } 
                    else if (cap_phase == CAP_PHASE_1) 
                    {
                        cap_C_results[0] = cap_C;
                        cap_phase = CAP_PHASE_2;
                        cap_size = CAP_INIT_SIZE_2;
                        printk(KERN_INFO "CS218 : CapProbe phase 1");
                    } 
                    else if (cap_phase == CAP_PHASE_2) 
                    {
                        printk(KERN_INFO "CS218 : CapProbe phase 2");
                        cap_C_results[1] = cap_C;
                        diff_c = (cap_C_results[0] - cap_C_results[1])/2;
                        avg_c = (cap_C_results[0] + cap_C_results[1])/2;

                        if (diff_c<0) 
                        {
                            diff_c = (1000 * (0 - diff_c)) / avg_c;     //maintain precision
                        }
                        else 
                        {
                            diff_c = 1000 * diff_c / avg_c;             //maintain precision
                        }   

                        if (diff_c < 50)            //cs218, check if error, maintaining precision
                        {
                            del_timer(&tl);
                            cap_size = 0;
                            printk(KERN_INFO "CS218 : CapProbe Finished! Total time = %ld.%06ld sec C = %ld.%03ld\n",
                                total_time/1000000, total_time % 1000000,
                                ((long)(avg_c*10))/10, (long)(avg_c*1000)%1000);
                        } 
                        else 
                        {
                            printk(KERN_INFO "CS218 :  Restart CapProbe... \n");
                            if (cap_run%2==0) 
                            {
                                // adjust packet size
                                if (cap_variance>0) 
                                {
                                    CAP_INIT_SIZE_1 += CAP_INIT_SIZE_1/5;
                                    CAP_INIT_SIZE_2 += CAP_INIT_SIZE_2/5;
                                } 
                                else if (cap_variance<0) 
                                {
                                    CAP_INIT_SIZE_1 -= CAP_INIT_SIZE_1/5;
                                    CAP_INIT_SIZE_2 -= CAP_INIT_SIZE_2 /5;
                                }

                                if (CAP_INIT_SIZE_1>CAP_SIZE_MAX) 
                                    CAP_INIT_SIZE_1 = CAP_SIZE_MAX;
                                if (CAP_INIT_SIZE_2>CAP_SIZE_MAX) 
                                    CAP_INIT_SIZE_2 = CAP_SIZE_MAX;
                                if (CAP_INIT_SIZE_1<CAP_SIZE_MIN) 
                                    CAP_INIT_SIZE_1 = CAP_SIZE_MIN;
                                if (CAP_INIT_SIZE_2<CAP_SIZE_MIN) 
                                    CAP_INIT_SIZE_2 = CAP_SIZE_MIN;
                                cap_variance = 0;
                            }
                            cap_run++;
                            cap_phase = CAP_PHASE_1;
                            cap_size = CAP_INIT_SIZE_1;
                        }
                    } 
                    else if (cap_phase==CAP_PHASE_3) 
                    {
                        //cs218     add if needed, no plans for now
                        printk(KERN_INFO "CS218 : CapProbe phase 3");
                    } 
                    else 
                    {
                        printk(KERN_INFO "CS218 : CAP_PHASE error!\n");
                    }
                    
                    // re-initialize
                    cap_id++;
                    cap_RTT_SUM = TOO_LARGE_DELAY;
                    cap_RTT1 = TOO_LARGE_DELAY;
                    cap_RTT2 = TOO_LARGE_DELAY;
                    cap_C_min = TOO_LARGE_DELAY;
                    cap_C_max = 0;
                    cap_C_same = 0;
                    cap_C_same2 = 0;
                    cap_C = 0;
                    cap_recv_num = 0;

                    for (i=0; i<MAX_BURST_SIZE; i++) 
                    {
                        cap_serialnum[i] = -1;
                        cap_send_sec[i] = -1;
                        cap_send_usec[i] = -1;
                    }
                } 
                else 
                {
                    if (cap_recv_num<CAP_SAMPLES_MAX) 
                    {
                        printk(KERN_INFO "CS218 : CapProbe serial num < sample MAX");
                        if (cap_phase==CAP_PHASE_1) 
                        {
                            cap_size = CAP_INIT_SIZE_1;
                        }
                        else 
                        {
                            cap_size = CAP_INIT_SIZE_2;
                        }
                    } 
                    else 
                    {
                        printk(KERN_INFO "CS218 : C = %ld.%03ld\n", ((long)(cap_C*10))/10, (long)(cap_C*1000)%1000);
                        if (cap_phase==CAP_PHASE_1)
                        {
                            cap_size = CAP_INIT_SIZE_1;
                        }
                        else 
                        {
                            cap_size = CAP_INIT_SIZE_2;
                        }
                        // re-initialize

                        cap_id++;
                        cap_RTT_SUM = TOO_LARGE_DELAY;
                        cap_RTT1 = TOO_LARGE_DELAY;
                        cap_RTT2 = TOO_LARGE_DELAY;
                        cap_C_min = 100000000;
                        cap_C_max = 0;
                        cap_C = 0;
                        cap_recv_num = 0;

                        for (i=0; i<MAX_BURST_SIZE; i++) 
                        {
                            cap_serialnum[i] = -1;
                            cap_send_sec[i] = -1;
                            cap_send_usec[i] = -1;
                        }
                    }
                }
            }
            else
            {
                printk(KERN_INFO "CS218 : CapProbe not converged!\n");
            }
        }
    }
}

static int fill_packet()
{
    int datalen, iplen, icmp_len;

    __u8 *eth;
    struct iphdr *iph;
    struct icmphdr *icmph;


    u_short *w;
    int len ;
    int sum ;
    int nleft ;
    u_short answer ;

    //if capprobe socket_buffer is not NULL, free it
    if (cap_skb) 
    {
        kfree_skb(cap_skb);
    }

    //allocate memory for capprobe socket_buffer
    cap_skb = alloc_skb(cap_size + 64+16,GFP_ATOMIC);

    //error check
    if (!cap_skb) 
    {
        printk(KERN_INFO "CS218 : No memory");
        return 0;
    }

    //reverse 16 blocks memory for cap_skb          - cs218 reason not known yet
    skb_reserve(cap_skb, 16);
    //skb_reset_network_header(cap_skb);

    /*  Reserve for ethernet and IP header  */
    eth = (__u8 *) skb_push(cap_skb, 14);
    iph = (struct iphdr *)skb_put(cap_skb, sizeof(struct iphdr));
    //icmph = (struct icmphdr *)skb_put(cap_skb, sizeof(struct icmphdr));

    //ethernet device address info captured and added to cap_skb        cs218: do we need to modify it to wireless interface?
    memcpy(eth+6, (const void *)cap_dev->dev_addr, 6);
    eth[0] = 0x40;
    eth[1] = 0x5D;
    eth[2] = 0x82;
    eth[3] = 0xF1;
    eth[4] = 0x99;
    eth[5] = 0xAA;
    eth[12] = 0x08;
    eth[13] = 0x00;

    datalen = cap_size - 14 - 20 - 8; /* Eth + IPh + ICMPh*/
    iph->ihl = 5;
    iph->version = 4;
    iph->ttl = 64;
    iph->tos = 0;
    iph->protocol = IPPROTO_ICMP; /* ICMP */
    iph->saddr = cap_src;
    iph->daddr = cap_dst;
    iph->frag_off = 0x0040;
    iplen = 20 + 8 + datalen;
    iph->tot_len = htons(iplen);
    iph->check = 0;
    iph->check = ip_fast_csum((void *) iph, iph->ihl);
    icmph = (struct icmphdr *)skb_put(cap_skb, sizeof(struct icmphdr));
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->un.echo.id = cap_id;
    icmph->un.echo.sequence = htons(cap_icmp_serialnum);
    icmp_len = datalen + 8;
    icmph->checksum = 0;

    cap_skb->protocol = __constant_htons(ETH_P_IP);
    //cap_skb->mac_header = ((__u16 *)iph) - 14;
    //cap_skb->network_header = ((__u16 *)iph);
    cap_skb->dev = cap_dev;
    cap_skb->pkt_type = PACKET_HOST;
    skb_put(cap_skb, datalen);


//============================================================================== cs218 needs review!

    w = (u_short *)icmph;
    len = icmp_len;
    sum = 0;
    nleft = len;
    answer = 0;
    /*
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */

    while (nleft > 1)  
    {
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
//==============================================================================

    return 1;
}

//CapProbe proc file related code


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

static void initialise_capprobe_variables(int id)
{
    CAP_INIT_SIZE_1 = INIT_SIZE_1;
    CAP_INIT_SIZE_2 = INIT_SIZE_2;
    cap_size = CAP_INIT_SIZE_1;
    cap_phase = CAP_PHASE_1;
    cap_id = id;
    cap_icmp_serialnum = 0;
    cap_RTT_SUM = TOO_LARGE_DELAY;
    cap_RTT1 = TOO_LARGE_DELAY;
    cap_RTT2 = TOO_LARGE_DELAY;
    cap_C_min = TOO_LARGE_DELAY;
    cap_C_max = 0;
    cap_C = 0;
    cap_run = 1;
    cap_variance = 0;
    cap_recv_num = 0;
}

static unsigned int arp_state_to_flags(struct neighbour *neigh)
{
    if (neigh->nud_state&NUD_PERMANENT)
        return ATF_PERM | ATF_COM;
    else if (neigh->nud_state&NUD_VALID)
        return ATF_COM;
    else
        return 0;
}

static int get_dest_mac(__u32 *ip, struct arpreq *r, struct net_device *dev)
{
    struct neighbour *neigh;
    int err = -ENXIO;

    neigh = neigh_lookup(&arp_tbl, ip, dev);
    if (neigh) 
    {
        if (!(neigh->nud_state & NUD_NOARP)) 
        {
            read_lock_bh(&neigh->lock);
            memcpy(r->arp_ha.sa_data, neigh->ha, dev->addr_len);
            r->arp_flags = arp_state_to_flags(neigh);
            read_unlock_bh(&neigh->lock);
            r->arp_ha.sa_family = dev->type;
            strlcpy(r->arp_dev, dev->name, sizeof(r->arp_dev));
            err = 0;
        }
        neigh_release(neigh);
    }
    return err;
}

static int write_proc_capprobe(struct file* file, const char* buffer, unsigned long count, void* data)
{
    int i;
    struct arpreq r;
    int start_capprobe_after = 500;     //start capprobe after this time period (in ms)
    
    char dest_ip[200];                  //stores destination ip address in kernel space as received from user space buffer, temporarily
    char burst_size_buff[100];          //number of packet pairs in a burst (capprobe run)
    unsigned char dest_mac[200];
    unsigned char src_mac[200];

    initialise_capprobe_variables(101);

    //initialising arrays that will store capprobee send timings
    for (i=0; i<MAX_BURST_SIZE; i++) {
        cap_serialnum[i] = -1;
        cap_send_sec[i] = -1;
        cap_send_usec[i] = -1;
    }

    //get the destination machine's ip address and burst size from the buffer and store it as cap_dst
    del_timer(&tl);     //clear timer, if exists

    memset(burst_size_buff, 0, 100);
    memset(dest_ip, 0, 200);

    copy_from_user(dest_ip, buffer, count);
    dest_ip[count-1] = '\0';

    //calculate burst size and seperate it from destination ip
    for (i=0; dest_ip[i]!='\0'; i++) 
    {
        if (dest_ip[i] == ';') 
        {
            strncpy(burst_size_buff, dest_ip+i+1, strlen(dest_ip)-1-i);
            burst_size_buff[strlen(dest_ip)-1-i] = '\0';
            dest_ip[i] = '\0';
        }
    }

    printk(KERN_INFO "CS218 : The IP address parsed is %s", dest_ip);

    cap_dst = in_aton(dest_ip);                 //Convert an ASCII string to binary IP.
    kstrtol(burst_size_buff, 10, &burst_size);  //get burst_size in int

    //validation for upper limit of burst_size
    if (burst_size > MAX_BURST_SIZE)
        burst_size = MAX_BURST_SIZE;

    if (cap_dst==0) {           
        return count;           //error condition, no ip address received from user space
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

    //need to get dest_mac here 

    /*void arp_send(int type, int ptype, __be32 dest_ip,
            struct net_device *dev, __be32 src_ip,
            const unsigned char *dest_hw, const unsigned char *src_hw,
            const unsigned char *target_hw)*/
    memcpy(src_mac, (const void *)cap_dev->dev_addr, 6);

    arp_send(1, 0x0800, cap_dst, cap_dev, cap_src, NULL, src_mac, NULL);

    //__u32 *ip, struct arpreq *r, struct net_device *dev
    get_dest_mac(&cap_dst, &r, cap_dev);
    memcpy(dest_mac, (const void *)r.arp_ha.sa_data, 6);

    printk(KERN_INFO "CS218 : MAC Addr for %s: %02X:%02X:%02X:%02X:%02X:%02X\n", dest_ip, dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);
    printk(KERN_INFO "\n\nCS218 : Start CapProbe to %s\n",dest_ip);

    //set the first timer tl, this is when CapProbe main is triggered the first time
    setup_timer(&tl, capprobe_main, (unsigned long) 1);                     //initialize timer to trigger capprobe_main
    mod_timer(&tl, jiffies + msecs_to_jiffies(start_capprobe_after));       //set expire time to 

    return count;
}

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

static int __init capprobe_init(void)
{
    cap_size = CAP_INIT_SIZE_1;
    cap_phase = CAP_PHASE_1;
    cap_id = 101;
    //strcpy(cap_device,"eth0");
    printk(KERN_INFO "CS218 : capprobe_init called! \n");
    proc_capprobe = proc_create("probe_info", 0644, NULL, &proc_file_fops_capprobe);
    proc_capprobe_if = proc_create("device", 0644, NULL, &proc_file_fops_capprobe_if);

    return 0;
}

static void __exit capprobe_cleanup(void)
{
    remove_proc_entry("probe_info", NULL);
    remove_proc_entry("device", NULL);
}

module_init(capprobe_init);
module_exit(capprobe_cleanup);