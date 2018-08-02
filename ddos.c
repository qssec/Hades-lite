#include <linux/types.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <xen/page.h>

extern long nbts[10];
struct ixgbe_lrohdr {
	struct iphdr iph;
	struct tcphdr th;
	__be32 ts[0];
};
#define SYN_THRESHOLD_DEF 30000/HZ //6K pks/s syn,drop first syn
#define RST_THRESHOLD_DEF 1000/HZ //3K pks/s reset,drop reset pkts
#define SYN_LIMIT_DEF 3000/HZ //60K pks/s syn,more then it drop
#define ACK_LIMIT_DEF 3000/HZ //60K pks/s ack,more then it drop
#define SYNFLOOD_ANTI 1
#define ACKFLOOD_ANTI 1
#define TS_INTERVAL 11 		// jiffies >> TS_INTERVAL 11 for 2s, because HZ=1000, so 2^10 ~ 1000
#define TS_TIMEOUT 7  		// 14s by TS_INTERVAL with 11
#define WHITE_TAG     0x8000	//white tag
#define NOT_CHINAIP_TAG   0x4000	//chinaip tag
#define R_NOT_CHINAIP_TAG 0xBFFF	//no chinaip tag
#define TAG_MASK      0xC000	//tag mask
#define TS_MASK       0x3FFF	//ts mask
#define TS_OFFSET     16383 	//14 bit, ts max 
#define MAX_CPU 64
#define DOM0_CONTIG_NUM_ORDER       9       /**< order of 2M */
#define MAX_NUM_ORDER     (DOM0_CONTIG_NUM_ORDER + 1)
#define DOM0_MEMBLOCK_SIZE          0x400000 /**< size of memory block(4M). */

static int check_chinaip = 0; //tag for use not_china_ip check?
static spinlock_t lock_chinaip;

static uint32_t rstcnt[MAX_CPU];
static uint32_t syncnt[MAX_CPU],synpass[MAX_CPU];
static uint32_t ackpass[MAX_CPU];
static uint32_t icmp_cnt[MAX_CPU];
static long syn_lastts[MAX_CPU];
static long ack_lastts[MAX_CPU];
static long xmit_lastts[MAX_CPU];
static long icmp_lastts[MAX_CPU];
static int syn_ddos[MAX_CPU] __read_mostly = {0};
static int ack_ddos[MAX_CPU] __read_mostly = {0};
static u32 hashrnd __read_mostly;
#define SIZE_PER_BLOCK    4       /** < size of per memory block(2MB)).*/
#define MAX_NODE_NUM 4
#define MEM_RSV_8K (8192)
#define MEM_RSV_1K (1024)
#define SHR_0 0
#define SHR_3 3
#define __16G 0x400000000
#define MAPSIZE_4G (0x100000000)
#define MAPSIZE_512M (0x20000000)

static short *bigmap[MAX_NODE_NUM];//white tag:1, china ip tag:1, ts:14
static int allow_port1=htons(80);
static int allow_port2=htons(62222);
static int allow_port3=htons(443);
static int allow_udp_port=htons(5000);

#define DEBUG_LOG
#ifdef DEBUG_LOG
static uint64_t syn_white_pass[MAX_CPU],white_pass[MAX_CPU];
static uint64_t tcp_all[MAX_CPU],drop_other[MAX_CPU],drop_notchinaip[MAX_CPU];
static uint64_t syn_pass[MAX_CPU],drop_first_syn[MAX_CPU],drop_second_syn[MAX_CPU],drop_limit_syn[MAX_CPU];
static uint64_t ack_pass[MAX_CPU],drop_first_ack[MAX_CPU],drop_second_ack[MAX_CPU],drop_limit_ack[MAX_CPU];
static struct proc_dir_entry *ddos_syn_info_pde;
static struct proc_dir_entry *ddos_ack_info_pde;
#endif

struct memblock_info {
	uint64_t vir_addr;
	uint64_t pfn;
};
struct memblock_info *g_rsv_mm_info;


static struct proc_dir_entry *syn_limit_pde;
static struct proc_dir_entry *ack_limit_pde;
static struct proc_dir_entry *chinaip_pde;


// for static local ip recive flux
struct flux_s{
	uint64_t udp[MAX_CPU];
	uint64_t syn[MAX_CPU];
	uint64_t ack[MAX_CPU];
	uint64_t other_tcp[MAX_CPU];
	uint64_t other_ip[MAX_CPU];
	uint64_t none_ip[MAX_CPU];
	uint64_t reset[MAX_CPU];
	uint64_t recv_flux[MAX_CPU];
	uint64_t sent_flux[MAX_CPU];
};

struct pre_brach{
	int alloc_num;
	int shr;
	uint64_t map_size;
};

static struct pre_brach p_b;

#define LOCATE_SIZE 256
static struct flux_s flux[LOCATE_SIZE];
static struct proc_dir_entry *flux_info_pde;
static struct proc_dir_entry *ddos_locating_pde;
static int ddos_locating = 0;

static int int_set_hz(const char *val, struct kernel_param *kp);
static int int_get_hz(char *val, struct kernel_param *kp);
static int syn_threshold = SYN_THRESHOLD_DEF;
module_param_call(threshold_syn,int_set_hz,int_get_hz,&syn_threshold,0644);
MODULE_PARM_DESC(threshold_syn,"drop first syn of every addr when recved more than threshold(6K) pks/s");
static int rst_threshold = RST_THRESHOLD_DEF;
module_param_call(threshold_rst,int_set_hz,int_get_hz,&rst_threshold,0644);
MODULE_PARM_DESC(threshold_rst,"drop reset packet when sent more than threshold(3K) reset pks/s");
static int syn_limit = SYN_LIMIT_DEF;
module_param_call(syn_limit,int_set_hz,int_get_hz,&syn_limit,0644);
MODULE_PARM_DESC(ack_limit,"drop syn packet when recive more than threshold(60K) pks/s");
static int ack_limit = ACK_LIMIT_DEF;
module_param_call(ack_limit,int_set_hz,int_get_hz,&ack_limit,0644);
MODULE_PARM_DESC(ack_limit,"drop ack packet when recive more than threshold(60K) pks/s");

static inline __u32 ecmp_hash(__u32 addr)
{
	__u32 h_ip;
	int hash;

	h_ip = ntohl(addr);
/*
	if(4 == ecmp)
		hash = ((h_ip >> 3) & 0xFFFFFFF8) | (h_ip & 0x00000007);
	else //ecmp == 8
		hash = ((h_ip >> 3) & 0xFFFFFFFC) | (h_ip & 0x00000003);
*/
	// 2^32/512M=8, if ecmp==4, hash should be duplicate, so use ecmp==8 directly
	hash = ((h_ip >> p_b.shr) & (0xFFFFFFFF ^ p_b.shr)) | (h_ip & p_b.shr);
	return hash;
}

__u32 ecmp_hash_h(__u32 h_ip)
{
	int hash;
	//hash = ((h_ip >> 3) & 0xFFFFFFFC) | (h_ip & 0x00000003);
	hash = ((h_ip >> p_b.shr) & (0xFFFFFFFF ^ p_b.shr)) | (h_ip & p_b.shr);
	return hash;
}

static void locating_recv_flux(struct sk_buff *skb, struct ixgbe_lrohdr *lroh,int this_cpu)
{
	__u32 h_ip;
	int hash;
	struct flux_s *pflux;

	h_ip = ntohl(lroh->iph.daddr);
	hash = h_ip & 0x000000FF;
	pflux = &flux[hash];

	if(skb->protocol == __constant_htons(ETH_P_IP)){
		if(lroh->iph.protocol == IPPROTO_UDP)
			pflux->udp[this_cpu]++;
		else if(lroh->iph.protocol == IPPROTO_TCP){
			if(lroh->th.syn && lroh->th.ack == 0)
				pflux->syn[this_cpu]++;
			else if(lroh->th.syn == 0 && lroh->th.ack)
				pflux->ack[this_cpu]++;
			else
				pflux->other_tcp[this_cpu]++;
		}
		else
			pflux->other_ip[this_cpu]++;
		pflux->recv_flux[this_cpu] += ntohs(lroh->iph.tot_len);
	}
	else
		pflux->none_ip[this_cpu]++;
}

static void locating_sent_flux(struct sk_buff *skb,int this_cpu)
{
	__u32 h_ip;
	int hash;
	struct flux_s *pflux;

	h_ip = ntohl(ip_hdr(skb)->saddr);
	//printk("ip:%x: this_cpu:%d\n",h_ip,this_cpu);
	hash = h_ip & 0x000000FF;
	pflux = &flux[hash];

	if(skb->protocol == __constant_htons(ETH_P_IP)){
		pflux->sent_flux[this_cpu] += ntohs(ip_hdr(skb)->tot_len);
	}
}

static void locating_reset_flux(struct sk_buff *skb,int this_cpu)
{
	__u32 h_ip;
	int hash;
	struct flux_s *pflux;

	h_ip = ntohl(ip_hdr(skb)->saddr);
	hash = h_ip & 0x000000FF;
	pflux = &flux[hash];

	pflux->reset[this_cpu]++;
}

static inline int icmp_limit(struct sk_buff *skb,int cpu)
{
	int ret = 0;

	if (icmp_lastts[cpu] != jiffies){
		if(icmp_lastts[cpu] != jiffies){
			icmp_lastts[cpu] = jiffies;
			icmp_cnt[cpu] = 0;
		}
	}
	if(++icmp_cnt[cpu] > rst_threshold)
		ret = 1;

	return(ret);
}


#ifndef NIPQUAD
#define NIPQUAD(addr) \
	((unsigned char*)&addr)[0], \
	((unsigned char*)&addr)[1], \
	((unsigned char*)&addr)[2], \
	((unsigned char*)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif


int ddos_receive_skb(struct napi_struct *napi,struct sk_buff *skb)
{
	struct ixgbe_lrohdr *lroh = (struct ixgbe_lrohdr *)skb->data;
	__u32 hash=0;
	short ts=0;
	short port = 0;
	int ts_differ;
	int ts_last;
    int this_cpu = smp_processor_id();
	int nid = numa_node_id();
		
    //printk("nid %d  cpu %d\n",nid,this_cpu);
	if (skb->protocol == __constant_htons(ETH_P_IP)){
		if(lroh->iph.protocol != IPPROTO_TCP){
			// for out udp back
			hash = ecmp_hash(lroh->iph.saddr);
			if(bigmap[nid][hash] & WHITE_TAG)
				goto pass;
			else{
				//when not in white_tag, can only accept rst_throld icmp request
				if(lroh->iph.protocol == IPPROTO_ICMP){
					if(icmp_limit(skb,this_cpu) == 0)
						goto pass;
				}
				else if(lroh->iph.protocol == IPPROTO_UDP){
					if(lroh->th.dest == allow_udp_port)
						goto pass;
				}
				goto drop;
			}
		}
#ifdef DEBUG_LOG
		tcp_all[this_cpu]++;
#endif

/* @bigmap:  short (map[hash] & 0x3fff) total hash (0~ (8*1024*1024*1024 ))
  *  -------------------------------------------
  * | <---             8 * 1024 * 1024 *1024          --->   |
  *  -------------------------------------------
  *
  *@bitmap
  *15    | 14     |13                                                       0
  *--------------------------------------------
  *wite  | cn_ip |                  ts
*/

		// 2s every ts
		ts = (__u16)((jiffies >> TS_INTERVAL) & TS_MASK);
		//hash=jhash_1word(lroh->iph.saddr,hashrnd) % MAPSIZE ;
		hash = ecmp_hash(lroh->iph.saddr);
		//handle timeout ,4.5 hour 4.5*3600 = 16200
		ts_last = bigmap[nid][hash] & TS_MASK;
		if(ts_last){
			ts_differ = ts - ts_last;
			if(ts_differ < 0)
				ts_differ += TS_OFFSET;
			//if timeout, then keep NOT_CHINAIP_TAG, cancel WHITE_TAG and set ts=0
			if(ts_differ > 16200)
				bigmap[nid][hash] &= NOT_CHINAIP_TAG;
			//handle by WHITE_TAG log ts and pass it
			if(bigmap[nid][hash] & WHITE_TAG){
#ifdef DEBUG_LOG
				if(lroh->th.syn)
					syn_white_pass[this_cpu]++;
				else
					white_pass[this_cpu]++;
#endif
				//update last ts
				bigmap[nid][hash] &= TAG_MASK;
				bigmap[nid][hash] |= ts;
				goto pass;
			}
		} //END bigmap[hash].ts > 0
		//drop port !80 !62222 fixme cancel it?
		//handle syn flood
		if(lroh->th.syn && lroh->th.ack == 0){
			if (syn_lastts[this_cpu] != jiffies){
					syn_lastts[this_cpu] = jiffies;
					if (syncnt[this_cpu] > syn_threshold)
						syn_ddos[this_cpu]=SYNFLOOD_ANTI;
					else 
						syn_ddos[this_cpu]=0; 
					syncnt[this_cpu]=0;
					synpass[this_cpu]=0;
			}
			syncnt[this_cpu]++;

			if (syn_ddos[this_cpu]){
				if(bigmap[nid][hash] & NOT_CHINAIP_TAG){
#ifdef DEBUG_LOG
					drop_notchinaip[this_cpu]++;
#endif
					goto drop;
				}
					
				//when attack, no WHITE_TAGA and no NOT_CHINAIP_TAG
				ts_differ = ts - bigmap[nid][hash];
				if(ts_differ < 0)
					ts_differ += TS_OFFSET;
				if(!bigmap[nid][hash] || ts_differ > TS_TIMEOUT){ //drop first syn
					//when attack, no WHITE_TAGA and no NOT_CHINAIP_TAG
					bigmap[nid][hash] = ts;
#ifdef DEBUG_LOG
					drop_first_syn[this_cpu]++;
#endif
					goto drop;
				}
				else if (bigmap[nid][hash] == ts){ //drop other syn in same second off first syn
#ifdef DEBUG_LOG
					drop_second_syn[this_cpu]++;
#endif
					goto drop;
				}
				else if(synpass[this_cpu] > syn_limit ){
#ifdef DEBUG_LOG
					drop_limit_syn[this_cpu]++;
#endif
					goto drop;
				}
				else{
					bigmap[nid][hash]=ts;
					synpass[this_cpu]++;
#ifdef DEBUG_LOG
					syn_pass[this_cpu]++;
#endif
					goto pass;
				}
			}//END ddos  SYNFLOOD_ANTI
		}//END lroh->th.syn && lroh->th.ack == 0
		else { //handle ack flood
			if(ack_ddos[this_cpu]){
				if (ack_lastts[this_cpu] != jiffies){
					
					if (ack_lastts[this_cpu] != jiffies){
						ack_lastts[this_cpu] = jiffies;
						ackpass[this_cpu]=0;
					}
					
				}

				if(bigmap[nid][hash] & NOT_CHINAIP_TAG){
#ifdef DEBUG_LOG
					drop_notchinaip[this_cpu]++;
#endif
					goto drop;
				}

				ts_differ = ts - bigmap[nid][hash];
				if(ts_differ < 0)
					ts_differ += TS_OFFSET;
				if(!bigmap[nid][hash] || ts_differ > TS_TIMEOUT){ //drop first syn
					bigmap[nid][hash] = ts;
#ifdef DEBUG_LOG
					drop_first_ack[this_cpu]++;
#endif
					goto drop;
				}
				else if (bigmap[nid][hash] == ts){ //drop other syn in same second off first syn
#ifdef DEBUG_LOG
					drop_second_ack[this_cpu]++;
#endif
					goto drop;
				}
				else if(ackpass[this_cpu] > ack_limit ){
#ifdef DEBUG_LOG
					drop_limit_ack[this_cpu]++;
#endif
					goto drop;
				}
				else{
					bigmap[nid][hash] = ts;
					ackpass[this_cpu]++;
#ifdef DEBUG_LOG
					ack_pass[this_cpu]++;
#endif
					goto pass;
				}
			}//END ddos ack anti 
		}//END ack
	}//ETH_P_IP
pass:
	//printk("ip:%u.%u.%u.%u pass\n", NIPQUAD(lroh->iph.saddr));
	if((skb->protocol == __constant_htons(ETH_P_IP)) 
			&& lroh->iph.protocol == IPPROTO_TCP && lroh->th.dest == allow_port1){
		port=((__constant_ntohl(lroh->iph.saddr) % 8) << 8);
		lroh->th.dest|=port;
		lroh->th.check-=port;
	}

	if(ddos_locating)
		locating_recv_flux(skb, lroh,this_cpu);
    
	return napi_gro_receive(napi,skb);
drop:
	if(ddos_locating)
		locating_recv_flux(skb, lroh,this_cpu);

	//printk("ip:%u.%u.%u.%u drop\n", NIPQUAD(lroh->iph.saddr));
	dev_kfree_skb_any(skb);
	return NET_RX_SUCCESS;
}

static inline void set_white(struct sk_buff *skb)
{
	__u32 addr;
	short ts;
	int nid = numa_node_id();
	
	//addr=jhash_1word(ip_hdr(skb)->daddr,hashrnd) % MAPSIZE;
	addr = ecmp_hash(ip_hdr(skb)->daddr);
	if (!(bigmap[nid][addr] & WHITE_TAG) || !(bigmap[nid][addr] & TS_MASK)){
		ts = (__u16)((jiffies >> TS_INTERVAL) & TS_MASK);
		bigmap[nid][addr] &= NOT_CHINAIP_TAG;
		bigmap[nid][addr] |= WHITE_TAG;
		bigmap[nid][addr] |= ts;
	}
}

int ddos_xmit_skb(struct sk_buff *skb)
{
	unsigned short port;
	int this_cpu = smp_processor_id();

	if (skb->protocol != __constant_htons(ETH_P_IP))
		return 0;
	if (ip_hdr(skb)->protocol == IPPROTO_UDP){
		set_white(skb);
	}
	else if ((ip_hdr(skb)->protocol == IPPROTO_ICMP) && (icmp_hdr(skb)->type == ICMP_ECHO)){
		set_white(skb);
	}
	else if(ip_hdr(skb)->protocol == IPPROTO_TCP){//TCP
		port = ntohs(tcp_hdr(skb)->source);
		if (port >= 80 && port <= 87)
			tcp_hdr(skb)->source = 0x5000;

		if (xmit_lastts[this_cpu] != jiffies){
				xmit_lastts[this_cpu]=jiffies;
				if (rstcnt[this_cpu] > rst_threshold)
					ack_ddos[this_cpu]=ACKFLOOD_ANTI;
				else 
					ack_ddos[this_cpu]=0; 
				rstcnt[this_cpu] = 0;
		}

		if ( ( tcp_hdr(skb)->syn && !tcp_hdr(skb)->ack ) || ( !tcp_hdr(skb)->syn && tcp_hdr(skb)->ack ) ){
			//set whitelist
			set_white(skb);
		}
		else if (tcp_hdr(skb)->rst){
			if(ddos_locating)
				locating_reset_flux(skb,this_cpu);
			if(++rstcnt[this_cpu] > rst_threshold){ 			
				dev_kfree_skb_any(skb);
				return 1;
			}
		}
	}
	if(ddos_locating)
		locating_sent_flux(skb,this_cpu);
	return 0;
}
static int int_set_hz(const char *val, struct kernel_param *kp)
{
	int tmp;
	char *p;
	tmp=simple_strtol(val,&p,10)/HZ;
	memcpy(kp->arg,&tmp,sizeof(int));
	return 0;
}
static int int_get_hz(char *val, struct kernel_param *kp)
{
	return sprintf(val,"%d",*((int*)kp->arg)*HZ);
}
#ifdef DEBUG_LOG
static ssize_t ddos_syn_info_proc_read(struct file *file, char __user *output,size_t size,loff_t *ofs)
{
	char buf[256];
    int i;
    uint64_t tcp=0,other=0,syn_white=0,pass_white=0,syn=0,
        drop_first=0,drop_second=0,drop_limit=0,drop_nochina=0;
    
	if(*ofs > 0) return 0;
    for(i=0;i<MAX_CPU;i++)
    {
        tcp += tcp_all[i];
        other += drop_other[i];
        syn_white += syn_white_pass[i];
        pass_white += white_pass[i];
        syn += syn_pass[i];
        drop_first += drop_first_syn[i];
        drop_second += drop_second_syn[i];
        drop_limit += drop_limit_syn[i];
        drop_nochina += drop_notchinaip[i];
    }
	sprintf(buf,"tcp_all=%llu drop_other=%llu white_syn=%llu white_other=%llu syn_pass=%llu drop_first=%llu drop_second=%llu drop_limit=%llu drop_nochinaip=%llu\n",
        tcp,other,syn_white,pass_white,syn,drop_first,drop_second,drop_limit,drop_nochina);
   
	if(copy_to_user(output,buf,strlen(buf)))
		return -EFAULT;
	*ofs += strlen(buf);
	return strlen(buf);
}
static struct file_operations ddos_syn_info_proc_ops = {
	.owner = THIS_MODULE,
	.read  = ddos_syn_info_proc_read
};
static ssize_t ddos_ack_info_proc_read(struct file *file, char __user *output,size_t size,loff_t *ofs)
{
	char buf[256];
    int i;
    uint64_t tcp=0,other=0,syn_white=0,pass_white=0,ack=0,
        drop_first=0,drop_second=0,drop_limit=0,drop_nochina=0;
    
    if(*ofs > 0) return 0;
    for(i=0;i<MAX_CPU;i++)
    {
        tcp += tcp_all[i];
        other += drop_other[i];
        syn_white += syn_white_pass[i];
        pass_white += white_pass[i];
        ack += ack_pass[i];
        drop_first += drop_first_ack[i];
        drop_second += drop_second_ack[i];
        drop_limit += drop_limit_ack[i];
        drop_nochina += drop_notchinaip[i];
    }
    
	sprintf(buf,"tcp_all=%llu drop_other=%llu white_syn=%llu white_other=%llu ack_pass=%llu drop_first=%llu drop_second=%llu drop_limit=%llu drop_nochinaip=%llu\n",
        tcp,other,syn_white,pass_white,ack,drop_first,drop_second,drop_limit,drop_nochina);
    
	if(copy_to_user(output,buf,strlen(buf)))
		return -EFAULT;
	*ofs += strlen(buf);
	return strlen(buf);
}
static struct file_operations ddos_ack_info_proc_ops = {
	.owner = THIS_MODULE,
	.read  = ddos_ack_info_proc_read
};
#endif
static ssize_t syn_limit_proc_write(struct file *file,const char __user *input,size_t size,loff_t *ofs)
{
	char buf[128];
	int i;
	if(copy_from_user(buf,(void *)input,size))
		return -EFAULT;
	buf[size -1] = '\0';
	i = simple_strtol(buf,NULL,10);
	if(i < 1000)
		i = 1000;
	syn_limit = i/HZ;
	return size;
}
static ssize_t syn_limit_proc_read(struct file *file, char __user *output,size_t size,loff_t *ofs)
{
	char buf[128];
	if(*ofs > 0) return 0;
	sprintf(buf,"%d", syn_limit * HZ);
	if(copy_to_user(output,buf,strlen(buf)))
		return -EFAULT;
	*ofs += strlen(buf);
	return strlen(buf);
}
static struct file_operations syn_limit_proc_ops = {
	.owner = THIS_MODULE,
	.read  = syn_limit_proc_read,
	.write = syn_limit_proc_write
};
static ssize_t ack_limit_proc_write(struct file *file,const char __user *input,size_t size,loff_t *ofs)
{
	char buf[128];
	int i;
	if(copy_from_user(buf,(void *)input,size))
		return -EFAULT;
	buf[size -1] = '\0';
	i = simple_strtol(buf,NULL,10);
	if(i < 1000)
		i = 1000;
	ack_limit = i/HZ;
	return size;
}
static ssize_t ack_limit_proc_read(struct file *file, char __user *output,size_t size,loff_t *ofs)
{
	char buf[128];
	if(*ofs > 0) return 0;
	sprintf(buf,"%d", ack_limit * HZ);
	if(copy_to_user(output,buf,strlen(buf)))
		return -EFAULT;
	*ofs += strlen(buf);
	return strlen(buf);
}
static struct file_operations ack_limit_proc_ops = {
	.owner = THIS_MODULE,
	.read  = ack_limit_proc_read,
	.write = ack_limit_proc_write
};

static ssize_t ddos_locating_proc_write(struct file *file,const char __user *input,size_t size,loff_t *ofs)
{
	char buf[128];
	int i,j,k;

	if(copy_from_user(buf,(void *)input,size))
		return -EFAULT;
	buf[size -1] = '\0';
	j = simple_strtol(buf,NULL,10);
	if(((j == 0) || (j == 1)) && (ddos_locating != j)){
		if(j == 1){
			for(i = 0;i < LOCATE_SIZE;i++)
				for(k = 0;k < MAX_CPU;k++){
					flux[i].ack[k] = 0;
					flux[i].none_ip[k] = 0;
					flux[i].other_ip[k] = 0;
					flux[i].other_tcp[k] = 0;
					flux[i].recv_flux[k] = 0;
					flux[i].sent_flux[k] = 0;
					flux[i].reset[k] = 0;
					flux[i].syn[k] = 0;
					flux[i].udp[k] = 0;
				}
		}
		ddos_locating = j;
	}

	return size;
}
static ssize_t ddos_locating_proc_read(struct file *file, char __user *output,size_t size,loff_t *ofs)
{
	char buf[128];
	if(*ofs > 0) return 0;
	sprintf(buf,"%d", ddos_locating);
	if(copy_to_user(output,buf,strlen(buf)))
		return -EFAULT;
	*ofs += strlen(buf);
	return strlen(buf);
}
static struct file_operations ddos_locating_proc_ops = {
	.owner = THIS_MODULE,
	.read  = ddos_locating_proc_read,
	.write = ddos_locating_proc_write
};

void * flux_info_seq_start (struct seq_file * s, loff_t * pos) 
{ 
	if (*pos < 1)
		return pos;
	else
		return NULL;
}
void * flux_info_seq_next (struct seq_file * s, void * v, loff_t * pos) 
{ 
	(*pos)++;
	if (*pos < 1)
		return pos;
	else
		return NULL;
}
void flux_info_seq_stop (struct seq_file * s, void * v) 
{ 
}
static int flux_info_seq_show(struct seq_file *s, void *v)
{
	int i,j;
	uint64_t udp=0,syn=0,ack=0,other_tcp=0,
		other_ip=0,none_ip=0,reset=0,recv_flux=0,sent_flux=0;

	seq_printf(s, "seq %18s %18s %18s %18s %18s %18s %18s %18s %18s\n", "udp_times", "syn_times", 
			"ack_times", "other_tcp_times", "other_ip_times", "none_ip_times", "send_reset_times", "recv_flux","sent_flux"); 
	for(i=0;i<LOCATE_SIZE;i++){
		
		for(j = 0;j < MAX_CPU;j++){
			recv_flux += flux[i].recv_flux[j];
			sent_flux += flux[i].sent_flux[j];
		}
		if(recv_flux > 0){
			for(j = 0;j < MAX_CPU;j++){
				udp += flux[i].udp[j];
				syn += flux[i].syn[j];
				ack += flux[i].ack[j];
				other_tcp += flux[i].other_tcp[j];
				other_ip += flux[i].other_ip[j];
				none_ip += flux[i].none_ip[j];
				reset += flux[i].reset[j];
			}
			seq_printf(s,"%3d %18llu %18llu %18llu %18llu %18llu %18llu %18llu %18llu %18llu\n", i,udp,syn,ack,other_tcp,
					other_ip,none_ip,reset,recv_flux,sent_flux);
			udp=0,syn=0,ack=0,other_tcp=0,other_ip=0,none_ip=0,reset=0,recv_flux=0,sent_flux=0;
			}
		}
	return 0;
}

static struct seq_operations flux_info_seq_ops = { 
	.start      = flux_info_seq_start, 
	.next       = flux_info_seq_next, 
	.stop       = flux_info_seq_stop, 
	.show       = flux_info_seq_show, 
};
int flux_info_proc_open(struct inode * inode , struct file * file) 
{ 
	return seq_open(file, &flux_info_seq_ops ); 
}
static struct file_operations flux_info_proc_ops = {
	.owner      = THIS_MODULE,
	.open       = flux_info_proc_open,
	.read       = seq_read,
	.llseek     = seq_lseek,
	.release    = seq_release,
};

static ssize_t chinaip_proc_write(struct file *file, const char __user *input, size_t size, loff_t *ofs)
{
	char buf[32];
	__u32 addr,tmp,h_ip;
	ulong num = 0, i,j,node_num;
	char *p;
	
	if(size > 31)
		return -EFAULT;
	if (copy_from_user(buf, input, 32)){
		return -EFAULT;
	}
	buf[size]='\0';
	if(buf[size-1] == '\n')
		buf[size-1]='\0';

	p = strchr(buf, ',');
	if(p){
		*p = '\0';
		p++;
		num = simple_strtol(p, NULL, 10);
	}

	addr = in_aton(buf);
	node_num = num_possible_nodes();
	//printk("num node:%d\n",node_num);
	for(j=0;j<node_num;j++)
	{
		if(addr == 0){
			//clear chinaip set
			if(check_chinaip == 1){
				check_chinaip = 0;
				printk("ANTI-DDOS MODULE, Clean CHINAIP_TAG\n");
				for(i=0; i<p_b.map_size; i++)
				{
					bigmap[j][i] &= R_NOT_CHINAIP_TAG;	
				}
			}
		}
		else{
			if(num > 0){
				if(check_chinaip == 0){
					spin_lock_bh(&lock_chinaip);
					if(check_chinaip == 0){
						check_chinaip = 1;
					for(i=0; i<p_b.map_size; i++){
						bigmap[j][i] |= NOT_CHINAIP_TAG;	
					  }
					}
					printk("ANTI-DDOS MODULE, Set CHINAIP_TAG\n");
					spin_unlock_bh(&lock_chinaip);
				}
				h_ip = ntohl(addr);
				for(i=0; i<num; i++){
					tmp = ecmp_hash_h(h_ip+i);
					bigmap[j][tmp] &= R_NOT_CHINAIP_TAG;	
				}
			}
			else{ //query
				tmp = ecmp_hash(addr);
				printk("ANTI-DDOS MODULE, IP tag query: %s(%u/%u) WHITE_TAG=%d ts=%d check_ip=%d CHINAIP_TAG=%d\n", buf, addr, tmp,
						bigmap[j][tmp]&WHITE_TAG ? 1:0, bigmap[j][tmp]&TS_MASK, check_chinaip, bigmap[j][tmp]&NOT_CHINAIP_TAG ? 0:1);
			}
		}

	}
	
	return size;
}

static ssize_t chinaip_proc_read(struct file *file, char __user *output,size_t size,loff_t *ofs)
{
	ulong i;
	ulong cnt_white=0, cnt_white_nochinaip=0, cnt_valid=0;
	int ts_differ;
	int ts_last;
	short ts;
	char buf[128];
	int nid = numa_node_id();
	
	if(*ofs > 0) return 0;

	ts = (__u16)((jiffies >> TS_INTERVAL) & TS_MASK);
	for(i=0;i<p_b.map_size;i++){
		if(bigmap[nid][i] & WHITE_TAG){
			cnt_white ++;
			if(bigmap[nid][i] & NOT_CHINAIP_TAG)
				cnt_white_nochinaip ++;
		}
		ts_last = bigmap[nid][i] & TS_MASK;
		if(ts_last){
			ts_differ = ts - ts_last;
			if(ts_differ < 0)
				ts_differ += TS_OFFSET;
			if(ts_differ < 16201)
				cnt_valid ++;
		}
	}

	sprintf(buf,"ANTI-DDOS hash=%llu white=%lu white_nochinaip=%lu valid=%lu\n", p_b.map_size, cnt_white, cnt_white_nochinaip, cnt_valid);
	if(copy_to_user(output, buf, strlen(buf)))
		return -EFAULT;
	*ofs += strlen(buf);
	return strlen(buf);
}

static struct file_operations chinaip_proc_ops = {
	.owner      = THIS_MODULE,
	.write      = chinaip_proc_write,
	.read 	    = chinaip_proc_read,
};


static void
sort_viraddr(struct memblock_info *mb, int cnt)
{
	int i,j;
	uint64_t tmp_pfn;
	uint64_t tmp_viraddr;

	/*sort virtual address and pfn */
	for(i = 0; i < cnt; i ++) {
		for(j = cnt - 1; j > i; j--) {
			if(mb[j].pfn < mb[j - 1].pfn) {
				tmp_pfn = mb[j - 1].pfn;
				mb[j - 1].pfn = mb[j].pfn;
				mb[j].pfn = tmp_pfn;

				tmp_viraddr = mb[j - 1].vir_addr;
				mb[j - 1].vir_addr = mb[j].vir_addr;
				mb[j].vir_addr = tmp_viraddr;
			}
		}
	}
}

uint64_t g_rsv_free[MAX_NODE_NUM][MEM_RSV_8K];

static void *
memory_reserve(uint32_t rsv_size,int node)
{
	uint64_t pfn, vstart, vaddr;
	uint32_t i,j, num_block, size;
	struct memblock_info *rsv_mm_info;
	struct page *page;
	int found,begin,end;

	memset(g_rsv_free[node],0,sizeof(uint64_t)*rsv_size);
	/* 4M as memory block */
	num_block = rsv_size / SIZE_PER_BLOCK *2;/* double alloc avoid failed */

	rsv_mm_info = vmalloc(sizeof(struct memblock_info) * num_block);
	if (!rsv_mm_info) {
		printk("Unable to allocate device memory information\n");
		return NULL;
	}
	memset(rsv_mm_info, 0, sizeof(struct memblock_info) * num_block);

	/* try alloc size of 4M once */
	for (i = 0; i < num_block; i ++) {
			page =	alloc_pages_node(node, GFP_ATOMIC, MAX_NUM_ORDER);//node 0 alloc memory
			if (page == NULL)
			{
				printk("alloc_pages_node failed\n");
				vaddr = 0;
				goto failed;
			}
		vstart = (unsigned long)page_address(page);
		/* size of 4M */
		size = DOM0_MEMBLOCK_SIZE;
		vaddr = vstart;
		while (size > 0) {
			SetPageReserved(virt_to_page(vaddr));
			vaddr += PAGE_SIZE;
			size -= PAGE_SIZE;
		}
		pfn = virt_to_pfn(vstart);
		rsv_mm_info[i].pfn = pfn;
		rsv_mm_info[i].vir_addr = vstart;
	}
	
	sort_viraddr(rsv_mm_info, num_block);
	
	//for(i = 0;i < num_block;i++)
		//printk("after sort:%lx\n",rsv_mm_info[i].vir_addr);
	
	/* find mem to use */
    found = 0;
    begin = 0;
    end = 0 ;
    for (i=0;i<(num_block);i++)
    {
        vstart = rsv_mm_info[i].vir_addr ;
        for (j=i+1;j<(num_block);j++)
        {
            if ( (vstart + DOM0_MEMBLOCK_SIZE ) != rsv_mm_info[j].vir_addr )
            {
            	//printk("failed :%p\n",vstart);
                break;
            }
            if ( j >= (i+num_block/2-1) )
            {
                found = 1;
                break;
            }
            vstart = rsv_mm_info[j].vir_addr ;
        }
        if ( found == 1 )
        {
            begin = i;
            end = j;
            break;
        }
    }

    if ( 0 == found  )
    {
        for (i=0;i<(num_block);i++)
        {
            if ( rsv_mm_info[i].vir_addr )
            {
                /* free not use */
				size = DOM0_MEMBLOCK_SIZE;
				vaddr = rsv_mm_info[i].vir_addr;
				while (size > 0) {
					ClearPageReserved(virt_to_page(vaddr));
					vaddr += PAGE_SIZE;
					size -= PAGE_SIZE;
				}
                free_pages( rsv_mm_info[i].vir_addr, MAX_NUM_ORDER);
            }
        }
		printk("not mem to use\n");
		vfree(rsv_mm_info);
        return NULL;
    }

    for (i=0;i<(num_block);i++)
    {
        if ( ( i<begin )||( i>end ) )
        {
            if ( rsv_mm_info[i].vir_addr )
            {
                /* free not use */
				size = DOM0_MEMBLOCK_SIZE;
				vaddr = rsv_mm_info[i].vir_addr;
				while (size > 0) {
					ClearPageReserved(virt_to_page(vaddr));
					vaddr += PAGE_SIZE;
					size -= PAGE_SIZE;
				}
                free_pages( rsv_mm_info[i].vir_addr, MAX_NUM_ORDER);
            }
        }
		else
		{
			g_rsv_free[node][i] = rsv_mm_info[i].vir_addr;
		}
    }
	
	printk("found begin:%p,end:%p\n",(void *)rsv_mm_info[begin].vir_addr,(void *)rsv_mm_info[end].vir_addr);

	vaddr = rsv_mm_info[begin].vir_addr;
	vfree(rsv_mm_info);
failed:
	return (void *)vaddr;
}

void free_ddos_mem(int nid,int rsv_size)
{
	uint32_t i,size;
	uint64_t vaddr;
	
	for (i=0;i<rsv_size;i++)
	{
		if ( g_rsv_free[nid][i] )
		{
			//printk("free %p\n",(void *)g_rsv_free[nid][i]);
			/* free not use */
			size = DOM0_MEMBLOCK_SIZE;
			vaddr = g_rsv_free[nid][i];
			while (size > 0) {
				ClearPageReserved(virt_to_page(vaddr));
				vaddr += PAGE_SIZE;
				size -= PAGE_SIZE;
			}
			free_pages( g_rsv_free[nid][i], MAX_NUM_ORDER);
		}
	}
	printk("free_ddos_mem ok\n");
}

void ddos_init(void)
{
	int i,node_num;
	uint64_t available_mem = (totalram_pages*PAGE_SIZE);
	
	memset(&p_b,0,sizeof(struct pre_brach));
	node_num = num_possible_nodes();
	printk("num node:%d\n",node_num);
	
	if((available_mem / node_num) < __16G)
	{
		pr_err("Need more than %llu MiB system memory to use this" \
			" driver (minimum = %lu MiB)!\n", available_mem/1024/1024,
			__16G/1024/1024*node_num);
		
		p_b.shr = SHR_3;
		p_b.map_size = MAPSIZE_512M;
		p_b.alloc_num = MEM_RSV_1K;
	}
	else
	{
		p_b.shr = SHR_0;
		p_b.map_size = MAPSIZE_4G;
		p_b.alloc_num = MEM_RSV_8K;
	}
	for(i=0;i<node_num;i++)
	{
		bigmap[i] = (short *)memory_reserve(p_b.alloc_num,i);
		if(bigmap[i])
		{
			memset(bigmap[i],0,p_b.map_size*sizeof(short));
		}
		printk("mem_node %d:%p\n",i,bigmap[i]);
	}

	spin_lock_init(&lock_chinaip);

	get_random_bytes(&hashrnd, sizeof(hashrnd));
#ifdef DEBUG_LOG

	ddos_syn_info_pde = proc_create("ddos_info_syn",S_IRUSR,init_net.proc_net,&ddos_syn_info_proc_ops);
	ddos_ack_info_pde = proc_create("ddos_info_ack",S_IRUSR,init_net.proc_net,&ddos_ack_info_proc_ops);
#endif
	syn_limit_pde = proc_create("ddos_limit_syn",S_IWUSR,init_net.proc_net,&syn_limit_proc_ops);
	ack_limit_pde = proc_create("ddos_limit_ack",S_IWUSR,init_net.proc_net,&ack_limit_proc_ops);
	chinaip_pde = proc_create("ddos_chinaip_input",S_IWUSR,init_net.proc_net,&chinaip_proc_ops);

	ddos_locating_pde = proc_create("ddos_locating",S_IWUSR,init_net.proc_net,&ddos_locating_proc_ops);
	flux_info_pde = proc_create("ddos_flux_info",S_IWUSR,init_net.proc_net,&flux_info_proc_ops);

	printk("ANTI-DDOS MODULE, init for syn_threshold:%d,rst_threshold:%d\n",syn_threshold*HZ,rst_threshold*HZ);
}


void ddos_deinit(void)
{
	int i,node_num;
	node_num = num_possible_nodes();
	printk("num node:%d\n",node_num);
	for(i=0;i<node_num;i++)
		free_ddos_mem(i,p_b.alloc_num);
#ifdef DEBUG_LOG
	proc_remove( ddos_syn_info_pde);
	proc_remove( ddos_ack_info_pde);
#endif
	proc_remove( syn_limit_pde);
	proc_remove(ack_limit_pde);
	proc_remove( chinaip_pde);

	proc_remove( ddos_locating_pde);
	proc_remove( flux_info_pde);

	printk("ANTI-DDOS MODULE, deinit.\n");
}
