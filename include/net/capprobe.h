/*
 * CapProbe revised version
 *
 * by Ling-Jyh Chen, cclljj@cs.ucla.edu
 *
 * included files: pktgen.c ip_input.c
 */
#include <linux/netdevice.h>
#include <linux/skbuff.h>

#define MAX_BURST_SIZE 200
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
long CAP_INIT_SIZE_1 = INIT_SIZE_1;
long CAP_INIT_SIZE_2 = INIT_SIZE_2;

#define CapProbe_DIR "net/capprobe"

#define CAP_PHASE_1 1
#define CAP_PHASE_2 2
#define CAP_PHASE_3 3
#define SEC_TO_USEC 1000000

#ifndef CAP_PROBE_

#define CAP_PROBE_

long cap_serialnum[MAX_BURST_SIZE];
long cap_send_sec[MAX_BURST_SIZE];
long cap_send_usec[MAX_BURST_SIZE];
long cap_recv1_sec[MAX_BURST_SIZE];
long cap_recv1_usec[MAX_BURST_SIZE];
long cap_recv2_sec[MAX_BURST_SIZE];
long cap_recv2_usec[MAX_BURST_SIZE];
long cap_recv_num;
long cap_size = -1;
long cap_id = -1;
char cap_device[100];
long cap_C = 0;	//changed from double
long cap_RTT_SUM = TOO_LARGE_DELAY;
long cap_RTT1    = TOO_LARGE_DELAY;
long cap_RTT2    = TOO_LARGE_DELAY;
struct timeval cap_time_start;
struct timeval cap_time_end;

int cap_phase;
int cap_run = 0;
long cap_C_results[3];			//changed from double
long cap_C_min = INFINITE;		//changed from double
long cap_C_max = 0;				//changed from double
int cap_var = 0;
int cap_C_same = 0;
int cap_C_same2 = 0;

#endif

void capprobe_main(unsigned long);

static int fill_packet(void);
