/*
 * CapProbe revised version for Linux 4.1
 *
 * by Amar Chandole, amar.chandole@cs.ucla.edu,
 *    Yuanzhi Gao, yuanzhi@cs.ucla.edu,
 *    Ameya Kabre, akabre@cs.ucla.edu
 *
 */

#include "capprobe.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <net/net_namespace.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/inetdevice.h>
#include <linux/ioctl.h>
#include <linux/if.h>
#include <linux/net.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <asm/spinlock.h>
#include <linux/delay.h>

static struct proc_dir_entry *proc_capprobe;
static struct proc_dir_entry *proc_capprobe_if;

//CapProbe src,dest mac & ip related variables
static __u32 cap_src;           //Own computer IP
static __u32 error_ip;
spinlock_t capprobe_spinlock;

static capprobe_param cap_paramp[MAX_NUM_PATH];
int max_interface = MAX_NUM_PATH;

static int fill_packet(int num_path);
static void logging_results(int num_path, long capacity);
static unsigned int arp_state_to_flags(struct neighbour *neigh);
static int get_dest_mac(__u32 *ip, struct arpreq *r, struct net_device *dev);
static int is_same_subnet(int num_path,__u32 dest_ip);
static void set_gateway_mac(int num_path, __u32* ifa_gateway, __u32 src_ip);

void capprobe_main(int num_path) 
{
    int cpu;
    int i, last_ok;
    int ret_val = 0;
    struct timeval tv;

    do_gettimeofday(&tv);

    // if (cap_paramp[num_path].packet_pairs_sent > MAX_BURST_SIZE) 
    //     return;

    //get start time for capprobe if this is the first call to capprobe_main()
    if (cap_paramp[num_path].packet_pairs_sent == 1) 
        do_gettimeofday(&(cap_paramp[num_path].cap_time_start));

    if (cap_paramp[num_path].cap_size <= 0) 
        return;

    if (cap_paramp[num_path].cap_size < 100)                                 //cs218_prob
        cap_paramp[num_path].cap_size = cap_paramp[num_path].CAP_INIT_SIZE_1;                     //CAP_INIT_SIZE_1 = 1200

    cap_paramp[num_path].cap_icmp_serialnum ++;
    cap_paramp[num_path].cap_icmp_serialnum %= 128;                          //cs218_prob unknown

    cap_paramp[num_path].cap_serialnum[cap_paramp[num_path].cap_index] = cap_paramp[num_path].cap_icmp_serialnum;

    //timing for sent packet pair
    cap_paramp[num_path].cap_send_sec[cap_paramp[num_path].cap_index] = tv.tv_sec;
    cap_paramp[num_path].cap_send_usec[cap_paramp[num_path].cap_index] = tv.tv_usec;

    //timing for received packet pair
    cap_paramp[num_path].cap_recv1_sec[cap_paramp[num_path].cap_index] = -1;
    cap_paramp[num_path].cap_recv1_usec[cap_paramp[num_path].cap_index] = -1;
    cap_paramp[num_path].cap_recv2_sec[cap_paramp[num_path].cap_index] = -1;
    cap_paramp[num_path].cap_recv2_usec[cap_paramp[num_path].cap_index] = -1;

    cap_paramp[num_path].cap_index++;
    cap_paramp[num_path].cap_index %= MAX_BURST_SIZE;                

    //status of last packet transmission
    last_ok = 1;

    //send packet pair
    for(i=0; i<2; i++) 
    {
        if (last_ok)                                    //if last tx ok: send next packet 
        {
            //if (cap_skb) kfree_skb(cap_skb);          //remove while testing if not needed
            fill_packet(num_path);
        } 
        else 
        {
            i--;
        }

        cpu = smp_processor_id(); /* ok because BHs are off */

        if (cap_paramp[num_path].cap_dev->_tx->xmit_lock_owner != cpu) 
        {

            HARD_TX_LOCK(cap_paramp[num_path].cap_dev, cap_paramp[num_path].cap_dev->_tx, cpu);
            if (!netif_xmit_stopped(cap_paramp[num_path].cap_dev->_tx)) 
            {
                __this_cpu_inc(xmit_recursion);
                cap_paramp[num_path].cap_skb = dev_hard_start_xmit(cap_paramp[num_path].cap_skb, cap_paramp[num_path].cap_dev, cap_paramp[num_path].cap_dev->_tx, &ret_val);
                __this_cpu_dec(xmit_recursion);

                if (dev_xmit_complete(ret_val)) 
                {
                    last_ok = 1;
                    HARD_TX_UNLOCK(cap_paramp[num_path].cap_dev, cap_paramp[num_path].cap_dev->_tx);
                    goto out;
                }
                else
                {
                    printk(KERN_INFO "CS218 : Hard transmit failed");
                }
            }

            HARD_TX_UNLOCK(cap_paramp[num_path].cap_dev, cap_paramp[num_path].cap_dev->_tx);
            printk(KERN_INFO "CS218 : netif_xmit_stopped!");
            net_crit_ratelimited("CS218 : Virtual device %s asks to queue packet!\n",cap_paramp[num_path].cap_dev->name);
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
            cap_paramp[num_path].cap_icmp_serialnum ++;
            cap_paramp[num_path].cap_icmp_serialnum %= 128;
        }
    }

    if (cap_paramp[num_path].cap_recv_num<5) 
    {
        if (cap_paramp[num_path].cap_RTT2>=TOO_LARGE_DELAY)
        {
                mod_timer(&(cap_paramp[num_path].tl), jiffies + msecs_to_jiffies(500));
        }
        else
        {
            if (cap_paramp[num_path].rtt2 < 5 * cap_paramp[num_path].cap_RTT2)
            {
                    mod_timer(&(cap_paramp[num_path].tl), jiffies + msecs_to_jiffies(((cap_paramp[num_path].rtt2 * 10/8) / SEC_TO_USEC) * 1000));
            }
            else
            {
                    mod_timer(&(cap_paramp[num_path].tl), jiffies + msecs_to_jiffies(500));
            }
        }
    } 
    else 
    {
        long send_rate = cap_paramp[num_path].cap_C / 20; // Mbps; 5% of capacity
        long pp_interval = SEC_TO_USEC * cap_paramp[num_path].cap_size * 8 / send_rate; //
        mod_timer(&(cap_paramp[num_path].tl), jiffies + msecs_to_jiffies(pp_interval / 1000));

    }

    //modify the timer_list expiry time with a new time that is current time + burst_interval
    //mod_timer(&tl, jiffies + msecs_to_jiffies(burst_interval));
    //increment packet_pairs_sent by 1 and update the timer_list data
    cap_paramp[num_path].packet_pairs_sent ++;
    cap_paramp[num_path].tl.data = num_path;
    return;
}

static void logging_results(int num_path, long capacity)
{
    struct file *f;
    char buf[128];
    struct in_addr addr;
    mm_segment_t fs;

    memset(buf, 0, 128);

    f = filp_open("/tmp/CapProbe_Log", O_RDWR|O_CREAT|O_APPEND, 0644);
    if(f == NULL)
        printk(KERN_ALERT "filp_open error!!.\n");
    else{
        // Get current segment descriptor
        fs = get_fs();
        // Set segment descriptor associated to kernel space
        set_fs(KERNEL_DS);
        // Write to the file

        sprintf(buf, "On Path %u : the capacity for interface %s is %ldbps\n", num_path + 1, cap_paramp[num_path].cap_device, capacity);

        vfs_write(f, buf, sizeof(buf), &f->f_pos);
        //f->f_op->write(f, (char*)buf, 8, &f->f_pos);
        set_fs(fs);
        // See what we read from file
        printk(KERN_INFO "buf:%s\n",buf);
    }
    filp_close(f,NULL);
}

void process_capprobe(struct sk_buff *skb, struct net_device *dev, const struct iphdr *iph)
{
    long C;
    u8 *tmphdr;
    u8 serialnum1, serialnum2, serialnum;
    u8 id1,id2;
    int num_path;
    bool matched = false;

    int id;
    int tmpvar;
    int i, j;
    struct timeval tv;
    __u32 pksize;
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

        for (num_path = 0; num_path < MAX_NUM_PATH; num_path ++)
        {
            if (id == cap_paramp[num_path].cap_id)
            {
                matched = true;
                break;
            }
        }

        if (!matched)
            return;


        tmpvar = serialnum1*256 + serialnum2;
        //printk (KERN_INFO "CS218 : %ld %ld ICMP RECV ID_%d serialnum= %d  (sec,usec)= %ld %ld\n",cap_size, cap_id, id,tmpvar,tv.tv_sec, tv.tv_usec);

        //check id and packet size
        //pksize = cap_size;                                        //cs218_prob : need to change here!!
        pksize = ntohs(iph->tot_len);
        pksize += 14;                                               //ethernet header

        if (pksize > 0 && pksize == cap_paramp[num_path].cap_size && id == cap_paramp[num_path].cap_id) 
        {
            //printk(KERN_INFO "CS218 : CapProbe packet received by processCapprobe\n");
            for (j = 0; j < MAX_BURST_SIZE; j++) 
            {
                //printk(KERN_INFO "CS218 : CapProbe packet serial number: temp value: %u, serial 1st: %u, serial 2nd: %u", tmpvar, cap_serialnum[j], cap_serialnum[j] + 1);
                if (tmpvar == cap_paramp[num_path].cap_serialnum[j])                     //1st packet of the packet pair found
                { 
                    //store receive time for this packet in the array
                    cap_paramp[num_path].cap_recv1_sec[j] = tv.tv_sec;
                    cap_paramp[num_path].cap_recv1_usec[j] = tv.tv_usec;
                    //printk(KERN_INFO "CS218 : CapProbe first packet received\n");
                    break;
                } 
                else if (tmpvar == cap_paramp[num_path].cap_serialnum[j]+1)              //2nd packet of the packet pair found
                {   
                    //store receive time for this packet in the array
                    cap_paramp[num_path].cap_recv2_sec[j] = tv.tv_sec;
                    cap_paramp[num_path].cap_recv2_usec[j] = tv.tv_usec;
                    //printk(KERN_INFO "CS218 : CapProbe second packet received\n");

                    if (cap_paramp[num_path].cap_recv1_sec[j]>0 && cap_paramp[num_path].cap_recv1_usec[j]>0) 
                    {
                        //remove SEC_TO_USEC
                        cap_paramp[num_path].disp = SEC_TO_USEC * (cap_paramp[num_path].cap_recv2_sec[j] - cap_paramp[num_path].cap_recv1_sec[j]) + (cap_paramp[num_path].cap_recv2_usec[j] - cap_paramp[num_path].cap_recv1_usec[j]);
                        cap_paramp[num_path].rtt1 = SEC_TO_USEC * (cap_paramp[num_path].cap_recv1_sec[j] - cap_paramp[num_path].cap_send_sec[j]) + (cap_paramp[num_path].cap_recv1_usec[j] - cap_paramp[num_path].cap_send_usec[j]);
                        cap_paramp[num_path].rtt2 = SEC_TO_USEC * (cap_paramp[num_path].cap_recv2_sec[j] - cap_paramp[num_path].cap_send_sec[j]) + (cap_paramp[num_path].cap_recv2_usec[j] - cap_paramp[num_path].cap_send_usec[j]);
                        cap_paramp[num_path].rtt = cap_paramp[num_path].rtt1 + cap_paramp[num_path].rtt2;

                        if (cap_paramp[num_path].disp>0 && cap_paramp[num_path].rtt1>0 && cap_paramp[num_path].rtt2>0 && cap_paramp[num_path].rtt>0 && cap_paramp[num_path].rtt<TOO_LARGE_DELAY) 
                        {
                            C = 8 * pksize * SEC_TO_USEC / cap_paramp[num_path].disp;    // bits per sec             //cs218_prob
                            if (C > cap_paramp[num_path].cap_C_max) 
                                cap_paramp[num_path].cap_C_max = C;
                            if (C < cap_paramp[num_path].cap_C_min) 
                                cap_paramp[num_path].cap_C_min = C;
                            if (cap_paramp[num_path].rtt<cap_paramp[num_path].cap_RTT_SUM) 
                            {
                                long diff_c = cap_paramp[num_path].cap_C - C;
                                if (diff_c<0) 
                                    diff_c = 0 - diff_c;            //cs218_prob

                                cap_paramp[num_path].cap_RTT_SUM = cap_paramp[num_path].rtt;
                                cap_paramp[num_path].cap_C = C;
                                cap_paramp[num_path].cap_C_same = 0;

                                if (diff_c < cap_paramp[num_path].cap_C/50)              //if diff_c < 2% of cap_C
                                    cap_paramp[num_path].cap_C_same2++;
                                else 
                                    cap_paramp[num_path].cap_C_same2 = 0;
                            } 
                            else 
                            {
                                cap_paramp[num_path].cap_C_same++;
                                cap_paramp[num_path].cap_C_same2++;
                            }

                            if (cap_paramp[num_path].rtt1<cap_paramp[num_path].cap_RTT1) 
                                cap_paramp[num_path].cap_RTT1 = cap_paramp[num_path].rtt1;
                            if (cap_paramp[num_path].rtt2<cap_paramp[num_path].cap_RTT2) 
                                cap_paramp[num_path].cap_RTT2 = cap_paramp[num_path].rtt2;

                            cap_paramp[num_path].cap_recv_num++;
                            //printk(KERN_INFO "CS218 : Getting minimum delay value RTT1: %ld, RTT2: %ld, cap_receive number: %ld", cap_paramp[num_path].cap_RTT1, cap_paramp[num_path].cap_RTT2, cap_paramp[num_path].cap_recv_num);
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

            if (cap_paramp[num_path].cap_C_same2 >= CAP_SAME_MAX || (cap_paramp[num_path].cap_recv_num >= CAP_SAMPLES && j < MAX_BURST_SIZE && cap_paramp[num_path].cap_C_same >= CAP_SAME) ) 
            {
                long diff_cap_RTT_SUM;
                //printk(KERN_INFO "CS218 : Further calculate difference of RTT\n");
                diff_cap_RTT_SUM = cap_paramp[num_path].cap_RTT_SUM - cap_paramp[num_path].cap_RTT1 - cap_paramp[num_path].cap_RTT2;
                diff_cap_RTT_SUM *= 1000;           //to maintain precision
                diff_cap_RTT_SUM /= cap_paramp[num_path].cap_RTT_SUM;

                // check convergence
                if (cap_paramp[num_path].cap_C_same2>=CAP_SAME_MAX||diff_cap_RTT_SUM < 10)           //previously 0.01, changed to 10 because ---> diff_cap_RTT_SUM *= 1000;         //to maintain precision
                {
                    long total_time;
                    long diff_c, avg_c;

                    //cs218 large printk section removed, verify if needed later
                    //printk(KERN_INFO "CS218 : Algorithm converged check\n");

                    do_gettimeofday(&(cap_paramp[num_path].cap_time_end));

                    //del_timer(&tl);
                    total_time = SEC_TO_USEC * (cap_paramp[num_path].cap_time_end.tv_sec - cap_paramp[num_path].cap_time_start.tv_sec) +
                    (cap_paramp[num_path].cap_time_end.tv_usec - cap_paramp[num_path].cap_time_start.tv_usec);

                    // calculate variance
                    if ((cap_paramp[num_path].cap_C_max / cap_paramp[num_path].cap_C_min)> 5) 
                    { 
                        cap_paramp[num_path].cap_variance++;
                    }
                    else 
                    {
                        cap_paramp[num_path].cap_variance--;
                    }

                    //cs218 large printk section removed, verify if needed later

                    //moving towards capprobe finish stage
                    cap_paramp[num_path].cap_size = 0;
                    if (cap_paramp[num_path].cap_C_same2 >= CAP_SAME_MAX) 
                    {
                        cap_paramp[num_path].cap_size = 0;
                        printk(KERN_INFO "CS218 : Stable CapProbe for path: %u Finished! Total time = %ld.%06ld sec C = %ld.%03ld\n", num_path + 1,
                            total_time/1000000, total_time % 1000000,
                            ((long)(cap_paramp[num_path].cap_C*10))/10, (long)(cap_paramp[num_path].cap_C*1000)%1000);

                        logging_results(num_path, cap_paramp[num_path].cap_C);

                        cap_paramp[num_path].CAP_INIT_SIZE_1 = INIT_SIZE_1;
                        cap_paramp[num_path].CAP_INIT_SIZE_2 = INIT_SIZE_2;
                        cap_paramp[num_path].cap_size = cap_paramp[num_path].CAP_INIT_SIZE_1;
                        cap_paramp[num_path].cap_phase = CAP_PHASE_1;
                        cap_paramp[num_path].cap_icmp_serialnum = 0;
                        cap_paramp[num_path].cap_RTT_SUM = TOO_LARGE_DELAY;
                        cap_paramp[num_path].cap_RTT1 = TOO_LARGE_DELAY;
                        cap_paramp[num_path].cap_RTT2 = TOO_LARGE_DELAY;
                        cap_paramp[num_path].cap_C_min = TOO_LARGE_DELAY;
                        cap_paramp[num_path].cap_C_max = 0;
                        cap_paramp[num_path].cap_C = 0;
                        cap_paramp[num_path].cap_run = 1;
                        cap_paramp[num_path].cap_variance = 0;
                        cap_paramp[num_path].cap_recv_num = 0;
                        cap_paramp[num_path].packet_pairs_sent = 1;
                    } 
                    else if (cap_paramp[num_path].cap_phase == CAP_PHASE_1) 
                    {
                        cap_paramp[num_path].cap_C_results[0] = cap_paramp[num_path].cap_C;
                        cap_paramp[num_path].cap_phase = CAP_PHASE_2;
                        cap_paramp[num_path].cap_size = cap_paramp[num_path].CAP_INIT_SIZE_2;
                        //printk(KERN_INFO "CS218 : CapProbe phase 1");
                    } 
                    else if (cap_paramp[num_path].cap_phase == CAP_PHASE_2) 
                    {
                        //printk(KERN_INFO "CS218 : CapProbe phase 2");
                        cap_paramp[num_path].cap_C_results[1] = cap_paramp[num_path].cap_C;
                        diff_c = (cap_paramp[num_path].cap_C_results[0] - cap_paramp[num_path].cap_C_results[1])/2;
                        avg_c = (cap_paramp[num_path].cap_C_results[0] + cap_paramp[num_path].cap_C_results[1])/2;

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
                            //del_timer(&(cap_paramp[num_path].tl));
                            cap_paramp[num_path].cap_size = 0;
                            printk(KERN_INFO "CS218 : CapProbe Finished! Total time = %ld.%06ld sec C = %ld.%03ld\n",
                                total_time/1000000, total_time % 1000000,
                                ((long)(avg_c*10))/10, (long)(avg_c*1000)%1000);

                            logging_results(num_path, cap_paramp[num_path].cap_C);

                            cap_paramp[num_path].CAP_INIT_SIZE_1 = INIT_SIZE_1;
                            cap_paramp[num_path].CAP_INIT_SIZE_2 = INIT_SIZE_2;
                            cap_paramp[num_path].cap_size = cap_paramp[num_path].CAP_INIT_SIZE_1;
                            cap_paramp[num_path].cap_phase = CAP_PHASE_1;
                            cap_paramp[num_path].cap_icmp_serialnum = 0;
                            cap_paramp[num_path].cap_RTT_SUM = TOO_LARGE_DELAY;
                            cap_paramp[num_path].cap_RTT1 = TOO_LARGE_DELAY;
                            cap_paramp[num_path].cap_RTT2 = TOO_LARGE_DELAY;
                            cap_paramp[num_path].cap_C_min = TOO_LARGE_DELAY;
                            cap_paramp[num_path].cap_C_max = 0;
                            cap_paramp[num_path].cap_C = 0;
                            cap_paramp[num_path].cap_run = 1;
                            cap_paramp[num_path].cap_variance = 0;
                            cap_paramp[num_path].cap_recv_num = 0;
                            cap_paramp[num_path].packet_pairs_sent = 1;


                        } 
                        else 
                        {
                            printk(KERN_INFO "CS218 :  Restart CapProbe... \n");
                            if (cap_paramp[num_path].cap_run%2==0) 
                            {
                                // adjust packet size
                                if (cap_paramp[num_path].cap_variance>0) 
                                {
                                    cap_paramp[num_path].CAP_INIT_SIZE_1 += cap_paramp[num_path].CAP_INIT_SIZE_1/5;
                                    cap_paramp[num_path].CAP_INIT_SIZE_2 += cap_paramp[num_path].CAP_INIT_SIZE_2/5;
                                } 
                                else if (cap_paramp[num_path].cap_variance<0) 
                                {
                                    cap_paramp[num_path].CAP_INIT_SIZE_1 -= cap_paramp[num_path].CAP_INIT_SIZE_1/5;
                                    cap_paramp[num_path].CAP_INIT_SIZE_2 -= cap_paramp[num_path].CAP_INIT_SIZE_2 /5;
                                }

                                if (cap_paramp[num_path].CAP_INIT_SIZE_1>CAP_SIZE_MAX) 
                                    cap_paramp[num_path].CAP_INIT_SIZE_1 = CAP_SIZE_MAX;
                                if (cap_paramp[num_path].CAP_INIT_SIZE_2>CAP_SIZE_MAX) 
                                    cap_paramp[num_path].CAP_INIT_SIZE_2 = CAP_SIZE_MAX;
                                if (cap_paramp[num_path].CAP_INIT_SIZE_1<CAP_SIZE_MIN) 
                                    cap_paramp[num_path].CAP_INIT_SIZE_1 = CAP_SIZE_MIN;
                                if (cap_paramp[num_path].CAP_INIT_SIZE_2<CAP_SIZE_MIN) 
                                    cap_paramp[num_path].CAP_INIT_SIZE_2 = CAP_SIZE_MIN;
                                cap_paramp[num_path].cap_variance = 0;
                            }
                            cap_paramp[num_path].cap_run++;
                            cap_paramp[num_path].cap_phase = CAP_PHASE_1;
                            cap_paramp[num_path].cap_size = cap_paramp[num_path].CAP_INIT_SIZE_1;
                        }
                    } 
                    else if (cap_paramp[num_path].cap_phase==CAP_PHASE_3) 
                    {
                        //cs218     add if needed, no plans for now
                        printk(KERN_INFO "CS218 : CapProbe phase 3");
                    } 
                    else 
                    {
                        printk(KERN_INFO "CS218 : CAP_PHASE error!\n");
                    }
                    
                    // re-initialize
                    //cap_paramp[num_path].cap_id++;
                    cap_paramp[num_path].cap_RTT_SUM = TOO_LARGE_DELAY;
                    cap_paramp[num_path].cap_RTT1 = TOO_LARGE_DELAY;
                    cap_paramp[num_path].cap_RTT2 = TOO_LARGE_DELAY;
                    cap_paramp[num_path].cap_C_min = TOO_LARGE_DELAY;
                    cap_paramp[num_path].cap_C_max = 0;
                    cap_paramp[num_path].cap_C_same = 0;
                    cap_paramp[num_path].cap_C_same2 = 0;
                    cap_paramp[num_path].cap_C = 0;
                    cap_paramp[num_path].cap_recv_num = 0;

                    for (i=0; i<MAX_BURST_SIZE; i++) 
                    {
                        cap_paramp[num_path].cap_serialnum[i] = -1;
                        cap_paramp[num_path].cap_send_sec[i] = -1;
                        cap_paramp[num_path].cap_send_usec[i] = -1;
                    }
                } 
                else 
                {
                    if (cap_paramp[num_path].cap_recv_num<CAP_SAMPLES_MAX) 
                    {
                        //printk(KERN_INFO "CS218 : CapProbe serial num < sample MAX");
                        if (cap_paramp[num_path].cap_phase==CAP_PHASE_1) 
                        {
                            cap_paramp[num_path].cap_size = cap_paramp[num_path].CAP_INIT_SIZE_1;
                        }
                        else 
                        {
                            cap_paramp[num_path].cap_size = cap_paramp[num_path].CAP_INIT_SIZE_2;
                        }
                    } 
                    else 
                    {
                        printk(KERN_INFO "CS218 : C = %ld.%03ld\n", ((long)(cap_paramp[num_path].cap_C*10))/10, (long)(cap_paramp[num_path].cap_C*1000)%1000);
                        if (cap_paramp[num_path].cap_phase==CAP_PHASE_1)
                        {
                            cap_paramp[num_path].cap_size = cap_paramp[num_path].CAP_INIT_SIZE_1;
                        }
                        else 
                        {
                            cap_paramp[num_path].cap_size = cap_paramp[num_path].CAP_INIT_SIZE_2;
                        }
                        // re-initialize

                        //cap_paramp[num_path].cap_id++;
                        cap_paramp[num_path].cap_RTT_SUM = TOO_LARGE_DELAY;
                        cap_paramp[num_path].cap_RTT1 = TOO_LARGE_DELAY;
                        cap_paramp[num_path].cap_RTT2 = TOO_LARGE_DELAY;
                        cap_paramp[num_path].cap_C_min = TOO_LARGE_DELAY;
                        cap_paramp[num_path].cap_C_max = 0;
                        cap_paramp[num_path].cap_C = 0;
                        cap_paramp[num_path].cap_recv_num = 0;

                        for (i=0; i<MAX_BURST_SIZE; i++) 
                        {
                            cap_paramp[num_path].cap_serialnum[i] = -1;
                            cap_paramp[num_path].cap_send_sec[i] = -1;
                            cap_paramp[num_path].cap_send_usec[i] = -1;
                        }
                    }
                }
            }
            else
            {
                //printk(KERN_INFO "CS218 : CapProbe not converged!\n");
            }
        }
    }
}

static int fill_packet(int num_path)
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
    if (cap_paramp[num_path].cap_skb) 
    {
        kfree_skb(cap_paramp[num_path].cap_skb);
    }

    //allocate memory for capprobe socket_buffer
    cap_paramp[num_path].cap_skb = alloc_skb(cap_paramp[num_path].cap_size + 64+16,GFP_ATOMIC);

    //error check
    if (!cap_paramp[num_path].cap_skb) 
    {
        printk(KERN_INFO "CS218 : No memory");
        return 0;
    }

    //reverse 16 blocks memory for cap_skb          - cs218 reason not known yet
    skb_reserve(cap_paramp[num_path].cap_skb, 16);
    //skb_reset_network_header(cap_skb);

    /*  Reserve for ethernet and IP header  */
    eth = (__u8 *) skb_push(cap_paramp[num_path].cap_skb, 14);
    iph = (struct iphdr *)skb_put(cap_paramp[num_path].cap_skb, sizeof(struct iphdr));
    //icmph = (struct icmphdr *)skb_put(cap_skb, sizeof(struct icmphdr));

    //ethernet device address info captured and added to cap_skb        cs218: do we need to modify it to wireless interface?
    memcpy(eth,cap_paramp[num_path].dest_mac, 6);
    memcpy(eth+6, (const void *)(cap_paramp[num_path].cap_dev)->dev_addr, 6);
    // eth[0] = 0x28;
    // eth[1] = 0xD2;
    // eth[2] = 0x44;
    // eth[3] = 0x2B;
    // eth[4] = 0x77;
    // eth[5] = 0x55;
    eth[12] = 0x08;
    eth[13] = 0x00;

    datalen = cap_paramp[num_path].cap_size - 14 - 20 - 8; /* Eth + IPh + ICMPh*/
    iph->ihl = 5;
    iph->version = 4;
    iph->ttl = 64;
    iph->tos = 0;
    iph->protocol = IPPROTO_ICMP; /* ICMP */
    iph->saddr = cap_src;
    iph->daddr = cap_paramp[num_path].cap_dst;
    iph->frag_off = 0x0040;
    iplen = 20 + 8 + datalen;
    iph->tot_len = htons(iplen);
    iph->check = 0;
    iph->check = ip_fast_csum((void *) iph, iph->ihl);
    icmph = (struct icmphdr *)skb_put(cap_paramp[num_path].cap_skb, sizeof(struct icmphdr));
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->un.echo.id = cap_paramp[num_path].cap_id;
    icmph->un.echo.sequence = htons(cap_paramp[num_path].cap_icmp_serialnum);
    icmp_len = datalen + 8;
    icmph->checksum = 0;

    cap_paramp[num_path].cap_skb->protocol = __constant_htons(ETH_P_IP);
    //cap_skb->mac_header = ((__u16 *)iph) - 14;
    //cap_skb->network_header = ((__u16 *)iph);
    cap_paramp[num_path].cap_skb->dev = cap_paramp[num_path].cap_dev;
    cap_paramp[num_path].cap_skb->pkt_type = PACKET_HOST;
    skb_put(cap_paramp[num_path].cap_skb, datalen);


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

    return 1;
}

//CapProbe proc file related code


static int read_proc_capprobe_if(char *buf, char **start, off_t offset, int count, int *eof, void *priv)
{
    char cap_device[100];
    int k;    
    k = sprintf(buf,"%s",cap_device);
    return k;
}

static int write_proc_capprobe_if(struct file* file, const char* buffer, unsigned long count, void* data)
{
    int k = count;

    //MOD_INC_USE_COUNT;
    char cap_device[100];

    memset(cap_device,0,100);
    copy_from_user(cap_device, buffer, count);
    cap_device[count-1] = '\0';

    if (strncmp(cap_device, "stop", 4) == 0)
    {
        int i;
        for (i = 0; i < MAX_NUM_PATH; i ++)
        {
            del_timer(&(cap_paramp[i].tl));
        }

        return count;
    }

    int i;
    int j;
    int num_path;
    num_path = 0;
    j = 0;
    for (i = 0; cap_device[i] != '\0'; i ++)
    {
        
        if (cap_device[i] == ';')
        {
            cap_paramp[num_path].cap_device[j] = '\0';
            j = 0;
            num_path ++;
            continue;
        }
        cap_paramp[num_path].cap_device[j] = cap_device[i];
        j ++;
    }

    max_interface = num_path;

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
    char cap_dst[200];
    int k;
    k = sprintf(buf,"%s",in_ntoa(cap_dst));
    return k;
}

static void initialise_capprobe_variables(int id)
{

    int num_path;

    for (num_path = 0; num_path < max_interface; num_path ++)
    {
        cap_paramp[num_path].CAP_INIT_SIZE_1 = INIT_SIZE_1;
        cap_paramp[num_path].CAP_INIT_SIZE_2 = INIT_SIZE_2;
        cap_paramp[num_path].cap_size = cap_paramp[num_path].CAP_INIT_SIZE_1;
        cap_paramp[num_path].cap_phase = CAP_PHASE_1;
        cap_paramp[num_path].cap_id = id + num_path;
        cap_paramp[num_path].cap_icmp_serialnum = 0;
        cap_paramp[num_path].cap_RTT_SUM = TOO_LARGE_DELAY;
        cap_paramp[num_path].cap_RTT1 = TOO_LARGE_DELAY;
        cap_paramp[num_path].cap_RTT2 = TOO_LARGE_DELAY;
        cap_paramp[num_path].cap_C_min = TOO_LARGE_DELAY;
        cap_paramp[num_path].cap_C_max = 0;
        cap_paramp[num_path].cap_C = 0;
        cap_paramp[num_path].cap_run = 1;
        cap_paramp[num_path].cap_variance = 0;
        cap_paramp[num_path].cap_recv_num = 0;
        cap_paramp[num_path].packet_pairs_sent = 1;
    }
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

static int is_same_subnet(int num_path,__u32 dest_ip)
{
    if((cap_src & cap_paramp[num_path].ifa_mask) == (dest_ip & cap_paramp[num_path].ifa_mask))
        return 1;
    else
        return 0;
}

static void set_gateway_mac(int num_path, __u32* ifa_gateway, __u32 src_ip)
{
    int i=0;
    spin_lock_init(&capprobe_spinlock);
    spin_lock(&capprobe_spinlock);
        //access gateway table and use mask to find needed gateway.
        for(;i<10;i++)
        {
            if((all_gateways[i] & cap_paramp[num_path].ifa_mask) == (src_ip & cap_paramp[num_path].ifa_mask))
                cap_paramp[num_path].ifa_gateway = all_gateways[i];
                break;
        }
    spin_unlock(&capprobe_spinlock);
    return;
}

static int write_proc_capprobe(struct file* file, const char* buffer, unsigned long count, void* data)
{
    int i;
    int num_path;
    struct arpreq gw_mac_req, dest_mac_req;
    int start_capprobe_after = 1000;     //start capprobe after this time period (in ms)
    
    char dest_ip[200];                  //stores destination ip address in kernel space as received from user space buffer, temporarily
    //char burst_size_buff[100];          //number of packet pairs in a burst (capprobe run)
    unsigned char dest_mac[200];
    unsigned char src_mac[200];
    char error_mac[8];       //00:00:00:00:00:00
    memset(error_mac, 0, 8);
    char error_ip_char[10] = "0.0.0.0"; //0.0.0.0
    error_ip = in_aton(error_ip_char);

    initialise_capprobe_variables(101);
    // strncpy(cap_paramp[0].cap_device, "eth0", 4);
    // strncpy(cap_paramp[1].cap_device, "eth0", 4);


    // // CS218: reading from proc/net/route file -----------------------------------------------------

    // struct file *f;
    // char buf[1024];
    // struct in_addr addr;
    // mm_segment_t fs;

    // memset(buf, 0, 1024);

    // f = filp_open("/proc/net/route", O_RDONLY, 0);
    // if(f == NULL)
    //     printk(KERN_ALERT "filp_open error!!.\n");
    // else{
    //     // Get current segment descriptor
    //     fs = get_fs();
    //     // Set segment descriptor associated to kernel space
    //     set_fs(get_ds());
    //     // Read the file
    //     f->f_op->read(f, buf, 1024, &f->f_pos);
    //     set_fs(fs);
    //     // See what we read from file
    //     printk(KERN_INFO "buf:%s\n",buf);
    // }
    // filp_close(f,NULL);

    // // CS218: reading from proc/net/route file ------------------------------------------------------

    copy_from_user(dest_ip, buffer, count);
    dest_ip[count-1] = '\0';

    if (strncmp(dest_ip, "stop", 4) == 0)
    {
        int i;
        for (i = 0; i < MAX_NUM_PATH; i ++)
        {
            del_timer(&(cap_paramp[i].tl));
        }

        return count;
    }

    int j;
    num_path = 0;
    j = 0;
    char temp_ip[50];
    memset(temp_ip, 0, 50);

    for (i = 0; dest_ip[i] != '\0'; i ++)
    {
        
        if (dest_ip[i] == ';')
        {
            temp_ip[j] = '\0';
            cap_paramp[num_path].cap_dst = in_aton(temp_ip);
            num_path ++;
            printk(KERN_INFO "CS218 : The IP address parsed for interface: %u is %s\n", num_path, temp_ip);
            memset(temp_ip, 0, 50);
            j = 0;
            continue;
        }
        temp_ip[j] = dest_ip[i];
        j ++;
    }
    
    if (num_path != max_interface)
    {
        printk(KERN_INFO "Number of interfaces and IP destination doesn't match. Use valid input\n");
    }

    //initialising arrays that will store capprobee send timings

    for (num_path = 0; num_path < max_interface; num_path ++)
    {
        for (i=0; i<MAX_BURST_SIZE; i++) {
            cap_paramp[num_path].cap_serialnum[i] = -1;
            cap_paramp[num_path].cap_send_sec[i] = -1;
            cap_paramp[num_path].cap_send_usec[i] = -1;
        }

        del_timer(&(cap_paramp[num_path].tl));

        if (cap_paramp[num_path].cap_dst==0) 
        {
            printk(KERN_INFO "No IP address input for interface: %u\n", num_path + 1);           
            return count;           //error condition, no ip address received from user space
        }

        //get a pointer to the device by its name (here, eth0)

        rtnl_lock();
        cap_paramp[num_path].cap_dev = __dev_get_by_name(&init_net, cap_paramp[num_path].cap_device);     
        dev_hold(cap_paramp[num_path].cap_dev);
        rtnl_unlock();

        //get the host machine's ip address from the device and store it as cap_src
        //cap_src = 0;
        if (cap_paramp[num_path].cap_dev->ip_ptr) {
            struct in_device *in_dev = cap_paramp[num_path].cap_dev->ip_ptr;
            cap_src = in_dev->ifa_list->ifa_address;
        }
        else
        {
            printk(KERN_INFO "CAPCHECK\n");
        }

        //need to get dest_mac here 

        //step 0
        set_gateway_mac(num_path, &(cap_paramp[num_path].ifa_gateway), cap_src);
        
        //step 1
        memcpy(src_mac, (const void *)(cap_paramp[0].cap_dev)->dev_addr, 6);

        //step 2
        if (is_same_subnet(num_path, cap_paramp[num_path].cap_dst))
        {
            //step 2.a
            for(i=0; i<4; i++)
            {
                printk(KERN_INFO "\n\nARP request no. %d sent!\n",i+1);
                arp_send(ARPOP_REQUEST, ETH_P_ARP, cap_paramp[num_path].cap_dst, cap_paramp[num_path].cap_dev, cap_src, NULL, src_mac, NULL);
                msleep(500);
            }   

            //step 2.b
            get_dest_mac(&(cap_paramp[num_path].cap_dst), &dest_mac_req, cap_paramp[num_path].cap_dev);
            memcpy(cap_paramp[num_path].dest_mac, (const void *)dest_mac_req.arp_ha.sa_data, 6);

            if (!memcmp((const void *)error_mac, (const void *)(cap_paramp[num_path].dest_mac), 6))    //case 2.b.i
                printk(KERN_INFO "\n\nCS218 : Error in MAC address resolution to destination, no entry in ARP Cache\n");
        }
        //step 3
        else
        {
            printk(KERN_INFO "\n\nCS218 : Destination not found in same subnet. Routing through gateway\n");
            
            //step 3.a
            get_dest_mac(&(cap_paramp[num_path].ifa_gateway), &gw_mac_req, cap_paramp[num_path].cap_dev);
            memcpy(cap_paramp[num_path].gateway_mac, (const void *)gw_mac_req.arp_ha.sa_data, 6);
            printk(KERN_INFO "CS218 : MAC Addr for Gateway: %02X:%02X:%02X:%02X:%02X:%02X\n", 
                cap_paramp[num_path].gateway_mac[0], cap_paramp[num_path].gateway_mac[1], cap_paramp[num_path].gateway_mac[2], cap_paramp[num_path].gateway_mac[3], cap_paramp[num_path].gateway_mac[4], cap_paramp[num_path].gateway_mac[5]);
            
            //step 3.b
            memcpy(cap_paramp[num_path].dest_mac, (const void *)(cap_paramp[num_path].gateway_mac), 6);
        }

        printk(KERN_INFO "\n\nCS218 : Final destination MAC address set to %02X:%02X:%02X:%02X:%02X:%02X\n", 
        cap_paramp[num_path].dest_mac[0], cap_paramp[num_path].dest_mac[1], cap_paramp[num_path].dest_mac[2], cap_paramp[num_path].dest_mac[3], cap_paramp[num_path].dest_mac[4], cap_paramp[num_path].dest_mac[5]);
    
        printk(KERN_INFO "\n\nCS218 : Start CapProbe on path %u\n", num_path + 1);

        //set the first timer tl, this is when CapProbe main is triggered the first time
        setup_timer(&(cap_paramp[num_path].tl), capprobe_main, num_path);                   //initialize timer to trigger capprobe_main
    }

    for (i = 0; i < max_interface; i ++)
    {
        mod_timer(&(cap_paramp[i].tl), jiffies + msecs_to_jiffies(start_capprobe_after + 200*i));
    }

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

    int num_path;

    for (num_path = 0; num_path < MAX_NUM_PATH; num_path ++)
    {
        cap_paramp[num_path].cap_size = 1200;
        cap_paramp[num_path].cap_phase = CAP_PHASE_1;
        cap_paramp[num_path].cap_id = 101 + num_path;
    }
    //strcpy(cap_device,"eth0");
    printk(KERN_INFO "CS218 : capprobe_init called! \n");
    proc_capprobe = proc_create("probe_info", 0644, NULL, &proc_file_fops_capprobe);
    proc_capprobe_if = proc_create("device", 0644, NULL, &proc_file_fops_capprobe_if);

    return 0;
}

static void __exit capprobe_cleanup(void)
{
    int i;
    for (i = 0; i < MAX_NUM_PATH; i ++)
    {
        del_timer(&(cap_paramp[i].tl));
    }
    remove_proc_entry("probe_info", NULL);
    remove_proc_entry("device", NULL);
}

module_init(capprobe_init);
module_exit(capprobe_cleanup);