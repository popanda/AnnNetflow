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