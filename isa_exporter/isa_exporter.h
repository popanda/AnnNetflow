/*
*	File: isa_exporter.h
*	Offline netflow probe, project into Network Applications and Network Administration (ISA)
* 	Author: Anna Popková
*	Other files: isa_exporter.cpp packets.h 
*/

#include <pcap/pcap.h>
#include <iostream>
#include <string>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <getopt.h>
#include <vector>
#include <bitset>
#include <ctime>
#include <cmath>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <sstream>
#include <vector>
#include <signal.h>


#define SERR 	std::cerr
#define SOUT 	std::cout
#define SIN 	std::cin

#define ETH_HEADER 	14

#define IP_PROTO 	0
#define ICMP_PROTO 	1
#define IGMP_PROTO 	2
#define TCP_PROTO 	6
#define UDP_PROTO	17

#define DEBUG 		1
#define MORE_DEBUG 	0

//structure which can identify ip packet
typedef struct pktInfo {
	in_addr srcAddr;
	in_addr dstAddr;
	u_short srcPort;
	u_short dstPort;
	u_char 	proto;
} t_pktInfo;

//structure of parameters for this program
typedef struct params {
	
	const char 	*inFile;
	in_addr 	collectorAddr;
	int 		collectorPort;
	int 		intervalToExport;
	u_int 		maxFlows;
	int 		intervalToExpire;

} t_params;

//information about seen flows
typedef struct flowInfo
{
	in_addr	srcAddr;
	in_addr dstAddr;
	u_short srcPort;
	u_short dstPort;
	u_char 	proto;
	u_int 	pktCnt;
	u_int 	octCnt;
	u_long 	byteCnt;
	u_char 	ToS;
	u_char 	tcpFlags;
	struct 	timeval lstPktTime;
	struct 	timeval startTime;
	struct 	timeval endTime;
	bool 	oneAckToExp;

	/* data */
} t_flowInfo;

typedef std::vector<t_flowInfo *> t_flowInfoVector;

// FUNCTIONS - descriptions are next to its definitions
int 		processTCP(const u_char *packet, t_flowInfoVector *flowInfoVector, t_flowInfoVector *expiredFlowInfoVector, struct ip *myIP, struct timeval pktTime, bpf_u_int32 len, t_params params);
int 		processUDPorICMPorIGMP(const u_char *packet, t_flowInfoVector *expiredFlowInfoVector, struct ip *myIP, struct timeval pktTime, bpf_u_int32 len);
t_flowInfo 	*createNewFlow(u_short srcPort, u_short dstPort, unsigned long srcAddr, unsigned long dstAddr, int proto, long lstPktTime);
int 		isEqualFlow(t_pktInfo pktInfo, t_flowInfo *flow);
int 		isOppositeFlow(t_pktInfo pktInfo, t_flowInfo *flow);
int 		exportExpired(t_flowInfoVector *expiredFlowInfoVector, struct timeval pktTime, double *intervalBgn, t_params params);
void 		expireOldestUnactive(t_flowInfoVector *flowInfoVector, t_flowInfoVector *expiredFlowInfoVector, struct timeval pktTime);
void 		expireAll(t_flowInfoVector *flowInfoVector, t_flowInfoVector *expiredFlowInfoVector, struct timeval pktTime);
int 		processParams(int argc, char **argv, t_params *ptrParams);
void 		setDefaultsParams(t_params *ptrParams);
double 		timeInSeconds(struct timeval t);
void 		sigHandler(int s);



/*
struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN 
	u_char	ip_hl:4,				header length
	ip_v:4;			 				version 
#endif
#if BYTE_ORDER == BIG_ENDIAN 
	u_char	ip_v:4,					version 
	ip_hl:4;		 				header length 
#endif
	u_char	ip_tos;					type of service 
	short	ip_len;					total length 
	u_short	ip_id;					identification 
	short	ip_off;					fragment offset field 
#define	IP_DF 0x4000				dont fragment flag
#define	IP_MF 0x2000				more fragments flag 
	u_char	ip_ttl;					time to live 
	u_char	ip_p;					protocol 
	u_short	ip_sum;					checksum 
	struct	in_addr ip_src,ip_dst;	source and dest address

	struct in_addr {
    unsigned long s_addr;  // load with inet_aton()
	};

}

struct tcphdr {
	u_short	th_sport;		source port 
	u_short	th_dport;		destination port 
	tcp_seq	th_seq;			sequence number 
	tcp_seq	th_ack;			acknowledgement number 
#if BYTE_ORDER == LITTLE_ENDIAN 
	u_char	th_x2:4,		(unused) 
		th_off:4;			data offset 
#endif
#if BYTE_ORDER == BIG_ENDIAN 
	u_char	th_off:4,		data offset 
		th_x2:4;			(unused) 
#endif
	u_char	th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
	u_short	th_win;			window 
	u_short	th_sum;			checksum 
	u_short	th_urp;			urgent pointer 
}; 


struct udphdr {
	u_short	uh_sport;		source port 
	u_short	uh_dport;		destination port 
	short	uh_ulen;		udp length 
	u_short	uh_sum;			udp checksum 
};

struct icmp {
	u_char	icmp_type;		 type of message, see below 
	u_char	icmp_code;		 type sub code 
	u_short	icmp_cksum;		 ones complement cksum of struct 
	union {
		u_char ih_pptr;			 ICMP_PARAMPROB 
		struct in_addr ih_gwaddr;	 ICMP_REDIRECT 
		struct ih_idseq {
			n_short	icd_id;
			n_short	icd_seq;
		} ih_idseq;
		int ih_void;
	} icmp_hun;
#define	icmp_pptr	icmp_hun.ih_pptr
#define	icmp_gwaddr	icmp_hun.ih_gwaddr
#define	icmp_id		icmp_hun.ih_idseq.icd_id
#define	icmp_seq	icmp_hun.ih_idseq.icd_seq
#define	icmp_void	icmp_hun.ih_void
	union {
		struct id_ts {
			n_time its_otime;
			n_time its_rtime;
			n_time its_ttime;
		} id_ts;
		struct id_ip  {
			struct ip idi_ip;
			options and then 64 bits of data 
		} id_ip;
		u_long	id_mask;
		char	id_data[1];
	} icmp_dun;
#define	icmp_otime	icmp_dun.id_ts.its_otime
#define	icmp_rtime	icmp_dun.id_ts.its_rtime
#define	icmp_ttime	icmp_dun.id_ts.its_ttime
#define	icmp_ip		icmp_dun.id_ip.idi_ip
#define	icmp_mask	icmp_dun.id_mask
#define	icmp_data	icmp_dun.id_data
};


struct igmp {
	u_char		igmp_type;	 version & type of IGMP message  
	u_char		igmp_code;	 unused, should be zero          
	u_short		igmp_cksum;	 IP-style checksum               
	struct in_addr	igmp_group;	group address being reported    
};	
*/