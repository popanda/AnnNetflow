/*
*	File: packets.h
*	Offline netflow probe, project into Network Applications and Network Administration (ISA)
* 	Author: Anna Popková
*	Other files: isa_exporter.h isa_exporter.cpp 
*/

#include <cstdint>
#include <arpa/inet.h>

typedef uint8_t 	oneByte;
typedef uint16_t 	twoBytes;
typedef uint32_t 	fourBytes;

#define MAX_FLOWS_IN_PACKET 30


// structures for netflow datagram version 5
// description of all the variables in these structures is under
typedef struct nfV5hdr
{
	twoBytes 	version = 5;
	twoBytes 	count;
	fourBytes 	SysUptime;
	fourBytes 	unix_secs;
	fourBytes 	unix_nsecs;
	fourBytes 	flow_sequence;
	oneByte 	engine_type = 0;
	oneByte 	engine_id = 0;
	twoBytes 	sampling_interval = 0; 

} t_nfV5hdr;

typedef struct nfV5flowRec
{
	struct in_addr 	srcaddr;
	struct in_addr 	dstaddr;
	struct in_addr 	nexthop;
	twoBytes 		input 	= 0;
	twoBytes 		output = 0;
	fourBytes 		dPkts;
	fourBytes 		dOctets;
	fourBytes 		First;
	fourBytes 		Last;
	twoBytes 		srcport;
	twoBytes 		dstport;
	oneByte 		pad1 = 0;
	oneByte 		tcp_flags;
	oneByte 		prot;
	oneByte 		ToS;
	twoBytes 		src_as = 0;
	twoBytes 		dst_as = 0;
	oneByte 		src_mask = 0;
	oneByte 		dst_mask = 0;
	twoBytes 		pad2 = 0;

} t_nfV5flowRec;


// structure which represents packet which will be sended to collector
typedef struct nfPkt
{
	nfV5hdr 	hdr;	
	nfV5flowRec rec[MAX_FLOWS_IN_PACKET]; // could contains 30 flows or less
} t_nfPkt;


/*
	What we will need in Netflow export datagram:

	(my opinions are in brackets)
		
		a) IN HEADER
	bytes		
	0-1		1) version - of the NF export format  (V5)

	2-3		2) count - number of flows exported in this packet  
			
**	4-7		3) SysUptime - current time in miliseconds since the export device booted 
			(MO - miliseconds since our virtual machine isa2015 booted)
			
	8-11	4) unix_secs - Current count of seconds since 0000 UTC 1970 
	12-15	5) unix_nsecs - Residual nanoseconds since 0000 UTC 1970 
			(MO - there will be some function for storing these two values)
	
	16-19	6) flow_sequence - sequence counter of total flows seen
	
	20 		7) engine_type - Type of flow-switching engine 			
	21		8) engine_id - Slot number of the flow-switching engine 
	22-23	9) sampling_interval - First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval 
			(MO - unconflicted value = 0 - all of these three)
*/

/*
		b) IN FLOW RECORD
	bytes
	0-3		1) srcaddr - Source IP address 
	4-7 	2) dstaddr - Destination IP address 

	8-11	3) nexthop - IP address of next hop router 
	12-13	4) input - SNMP index of input interface 
	14-15	5) output - SNMP index of output interface 
			(MO - unconflicted value = 0 - all of these three)

	16-19	6) dPkts - packets in the flow 
			(MO - number of packed in this flow)

**	20-23	7) dOctets - Total number of Layer 3 bytes in the packets of the flow 
			(MO - maybe the value which we can see on softflowd?)

	24-27	8) First - SysUptime at start of flow 
	28-31	9) Last - SysUptime at the time the last packet of the flow was received
			(MO - times stored from pcap file - timestamp of first and last packet in particular flow)

	32-33	10) srcport - TCP/UDP source port number or equivalent 
	34-35	11) dstport - TCP/UDP destination port number or equivalent 

*	36		12) pad1 - Unused (zero) bytes 
			(MO - unconflicted value = 0)

*	37		13) tcp_flags - Cumulative OR of TCP flags 
			(MO - take all the flag vectors from all tcp packets and do OR on them)

	38		14) prot - IP protocol type (for example, TCP = 6; UDP = 17) 
	39		15) IP type of service (ToS) 
			(MO - could be stored from struct ip (maybe sth like ip_tos))

*	40-41	16) src_as - Autonomous system number of the source, either origin or peer 
*	42-43	17) dst_as - Autonomous system number of the destination, either origin or peer
*	44 		18) src_mask - Source address prefix mask bits 
*	45 		19) dst_mask - Destination address prefix mask bits 
*	46-47 	20) pad2 - Unused (zero) bytes 
			(MO - unconflicted value = 0 - all of these five values)

*/



