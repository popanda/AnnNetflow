#include "isa_exporter.h"


int main(int argc, char **argv)
{
	t_params params;
	const u_char *packet;

	//structure for store the beggining of the interval after what the expired flows will be exported
	struct timeval intervalBgn;

	struct pcap_pkthdr packetHeader;
	/*
	struct timeval 	ts    	...time stamp
	struct timeval {
	long	tv_sec;		seconds 
	long	tv_usec;	 and microseconds 
	};
	bpf_u_int32 	caplen	...length of portion present
	bpf_u_int32 	len 	...length this packet (off wire) 
	*/
	
	struct ether_header *etherPtr;
	/*
	u_char 	ether_dhost [6]		...Destination MAC address.
	u_char 	ether_shost [6]		...Source MAC address.
	u_short 	ether_type		...Protocol type.
 	*/

	pcap_t *pcapHandle;
	int ether_offset = 0;
	char errbuf[1000];

	//packet counters
	int udps = 0; int tcps = 0; int icmps = 0; int igmps = 0; int arps = 0; int others = 0;
	
	//bytes counters
	int udpsb = 0;int tcpsb = 0; int icmpsb = 0; int igmpsb = 0; int arpsb = 0; int othersb = 0;

	short retValue;

	//pointer to the vector of flows in cache
	t_flowInfoVector *flowInfoVector;
	
	//pointer to the vector of expired flows
	t_flowInfoVector *expiredFlowInfoVector;
	
	//alocation of the vectors
	flowInfoVector = new t_flowInfoVector;
	expiredFlowInfoVector = new t_flowInfoVector;

	setDefaultsParams(&params);
	
	//check if user specified some parameters and set the values 
	if ((processParams(argc, argv, &params)) != 0)
	{
		if (DEBUG)
			SOUT << "Processing parameters failed." << std::endl;
		return 1;
	}

	//open the pcap file or STDIN if no imput file is specified
	if ((pcapHandle = pcap_open_offline(params.inFile, errbuf)) == NULL)
		SERR << "Cannot open pcap file." << std::endl;

	bool isFirstPkt = true;
	//main cycle for processing packets from the file - cycle until EOF
	while ((packet = pcap_next(pcapHandle, &packetHeader)) != NULL)
	{
		//store the timestamp of current packet
		struct timeval pktTime;
		pktTime.tv_sec = packetHeader.ts.tv_sec;
		pktTime.tv_usec = packetHeader.ts.tv_usec;

		//check if it is first packet -> will be the beginning of the interval after that the export of expire flows will be done
		if (isFirstPkt)
		{
			intervalBgn.tv_sec = packetHeader.ts.tv_sec;
			intervalBgn.tv_usec = packetHeader.ts.tv_usec;
			isFirstPkt = false;
		}

		if (DEBUG)
		{
			SOUT << "\t\tpktTime.tv_sec:" << pktTime.tv_sec << "  -  intervalBgn.tv_sec:" << intervalBgn.tv_sec << " (" << pktTime.tv_sec - intervalBgn.tv_sec << ")  >=  " << "params.intervalToExport:" << params.intervalToExport << std::endl;
		}

		//check the interval to export expire flows 
		if ((pktTime.tv_sec - intervalBgn.tv_sec) >= params.intervalToExport)
		{
			if (DEBUG)
				SOUT << "Expired flows will be exported." << std::endl;
			intervalBgn.tv_sec = pktTime.tv_sec;
			intervalBgn.tv_usec = pktTime.tv_usec;
		}


		etherPtr = (struct ether_header *) packet;

		if (DEBUG)
		{
			SOUT << "\n\n\tRecieved packet time (seconds): \t\t\t" << pktTime.tv_sec << std::endl;
			SOUT << "\tRecieved packet time (microseconds): \t\t\t" << pktTime.tv_usec << std::endl;
			SOUT << "\tLength " << packetHeader.len << " received at " << ctime((const time_t*)&packetHeader.ts.tv_sec) << std::endl; 
			SOUT << "\tSource MAC: " << ether_ntoa((const struct ether_addr *)&etherPtr->ether_shost) << std::endl;
		}

		//check if its IP packet - the others will be ignored
		if (ntohs(etherPtr->ether_type) == ETHERTYPE_IP)         
		{
			struct ip *myIP;
			myIP = (struct ip*) (packet+ETH_HEADER);

			if (DEBUG)
			{
				SOUT << "\t\tEthernet type packet processing..." << std::endl;
				SOUT << "\tIP id " << ntohs(myIP->ip_id) << ", header lenght "<< myIP->ip_hl*4 << "bytes, version " << myIP->ip_v << std::endl;;
				SOUT << "\tIP type of service: " << u_short(myIP->ip_tos) << "\tIP total length " << myIP->ip_len << " bytes, TTL " << u_short(myIP->ip_ttl) << std::endl;
			}

			//what kind of protocol the current packet is?
			switch(myIP->ip_p)
			{	
				case TCP_PROTO: tcps++; tcpsb += packetHeader.len; //increment counter of tcp packets and bytes sended in its
				retValue = processTCP(packet, flowInfoVector, expiredFlowInfoVector, myIP, pktTime, packetHeader.len, params);
				break; 
				case UDP_PROTO: udps++; udpsb += packetHeader.len; //increment counter of udp packets and bytes sended in its
				retValue = processUDP(packet, flowInfoVector, expiredFlowInfoVector, myIP, pktTime, packetHeader.len, params);
				break;
				case ICMP_PROTO: icmps++; icmpsb += packetHeader.len;
				//retValue = processICMP(packet, flowInfoVector);
				break;
				case IGMP_PROTO: igmps++; igmpsb += packetHeader.len;
				//retValue = processIGMP(packet, flowInfoVector);
				break; 
				default:
					retValue = 2; 
			}

			if (retValue != 0)
			{				
				if (retValue == 1)
					SERR << "Error while proccesing packet TCP/UDP/ICMP/IGMP." << std::endl;
				if (retValue == 2)
					SERR << "Error while proccesing Unknown packet." << std::endl;
				return 1;
			}
		}

		else  if (ntohs(etherPtr->ether_type) == ETHERTYPE_ARP) // ARP packet
		{
			if (DEBUG)
			{
				SOUT << "\t\tARP packet processing..." << std::endl;
				arps++;
			}
		}
		else
		{
			if (DEBUG)
			{
				SOUT << "\t\tEthernet type 0x" << ntohs(etherPtr->ether_type) << " not IPv4" << std::endl;	
				others++;
			}
		}
	}
	
	if (DEBUG)
	{

		for(t_flowInfoVector::iterator iterator = expiredFlowInfoVector->begin(); iterator != expiredFlowInfoVector->end(); ++iterator) 
		{
			SOUT << (*iterator)->srcPort << " : " << (*iterator)->dstPort << "  |  " << inet_ntoa((*iterator)->srcAddr) << " : " << inet_ntoa((*iterator)->dstAddr) << "  |  " <<
			(*iterator)->proto << "  |  " << "packets: " << (*iterator)->pktCnt << "  |  bytes: " << (*iterator)->byteCnt << std::endl;
		}

		SOUT << "Number of expired flows: " << expiredFlowInfoVector->size() << std::endl;
		SOUT << "Number of flows in cache: " << flowInfoVector->size() << std::endl;
		SOUT << "End of file reached..." << std::endl;
		SOUT << "== STATISTICS ==" << std::endl;
		SOUT << "TCP \tpackets: " << tcps << ",\tbytes: " << tcpsb << std::endl;
		SOUT << "UDP \tpackets: " << udps << ",\tbytes: " << udpsb << std::endl;
		SOUT << "ICMP \tpackets: " << icmps << ",\tbytes: " << icmpsb << std::endl;
		SOUT << "IGMP \tpackets: " << igmps << ",\tbytes: " << igmpsb << std::endl;
		SOUT << "ARP \tpackets: " << arps << ",\tbytes: " << arpsb << std::endl;
		SOUT << "OTHER \tpackets: " << others << ",\tbytes: " << othersb << std::endl;
		SOUT << "total \tpackets: " << tcps + udps + icmps + igmps << ",\tbytes: " << 
		tcpsb + udpsb + icmpsb + igmpsb << std::endl;
		SOUT << "== END OF STATISTICS ==" << std::endl;

	}

	pcap_close(pcapHandle);

	return(0);
}


/*
* Funcion for setting the default parametres - all of them are optional
*
* @param ptrParams structure with the paramaters
*/
void setDefaultsParams(t_params *ptrParams)
{
	ptrParams->inFile = "-";
	inet_aton("127.0.0.1", &(ptrParams->collectorAddr));
	ptrParams->collectorPort = 2055;
	ptrParams->intervalToExport = 300; //after this interval all the expired flows will be exported into collector - in seconds
	ptrParams->maxFlows = 50; //max amount of flows in this program cache
	ptrParams->intervalToExpire = 300; //unactive timeout for TCP connection
}

/*
* Function loads the parameters from user and store them into structure
* parameters which are not specified stay on default value
*/
int processParams(int argc, char **argv, t_params *ptrParams)
{
	int a;
	char *endPtr;

	static struct option longOptions[] = 
	{
		{"input", required_argument, 0, 'i'},
		{"collector", required_argument, 0, 'c'},
		{"interval", required_argument, 0, 'I'},
		{"max-flows", required_argument, 0, 'm'},
		{"tcp-timeout", required_argument, 0, 't'}
	};
	

	while ((a = getopt_long(argc, argv, "i:c:I:m:t:", longOptions, &optind)) != -1)
	{

		switch(a)
		{
			case 0:
			break;

			case 'i':
				if(DEBUG)
					SOUT << "Option input with value " << optarg << "." << std::endl;
				ptrParams->inFile = optarg;
				break;

			case 'c':
				if(DEBUG)
					SOUT << "Option collector with value " << optarg << "." << std::endl;
				if ((inet_aton(optarg, &(ptrParams->collectorAddr))) == 0)
				{
					SERR << "Invalid collector address."<< std::endl << "Exiting..." << std::endl;
					return -1;
				}
				break;

			case 'I':
				if(DEBUG)
					SOUT << "Option interval with value " << optarg << "." << std::endl;
				ptrParams->intervalToExport = strtol(optarg, &endPtr, 10);
				if (*endPtr != '\0')
				{
					SERR << "Invalid value for interval to export." << std::endl << "Exiting..." << std::endl;
					return -1;
				}	
				break;

			case 'm':
				if(DEBUG)
					SOUT << "Option max-flows with value " << optarg << "." << std::endl;
				ptrParams->maxFlows = strtol(optarg, &endPtr, 10);
				if (*endPtr != '\0')
				{
					SERR << "Invalid value for max-flows." << std::endl << "Exiting..." << std::endl;
					return -1;
				}
				break;

			case 't':
				if(DEBUG)
					SOUT << "Option tcp-timeout with value " << optarg << "." << std::endl;
				ptrParams->intervalToExpire = strtol(optarg, &endPtr, 10);
				if (*endPtr != '\0')
				{
					SERR << "Invalid value for interval to expire (tcp-timeout)." << std::endl << "Exiting..." << std::endl;
					return -1;
				}
				break;

			case '?':
				SERR << "Invalid option." << std::endl << "Exiting..." << std::endl;
				if (DEBUG)
					SOUT << "*?*" << std::endl;
				return -1;
				break;

			default:
				if (DEBUG)
					SOUT << "*default*" << std::endl;
				abort();

		}
		
	}

	if (optind < argc)
		{
			SERR << "Unknown argument." << std::endl << "Exiting..." << std::endl;
			if (DEBUG)
				SOUT << "*optInd < argc*" << std::endl;
			return -1;
		}

	return 0;
}

/*
* Function create an allocate space for new flow, store the main values into it and returns pointer on the new flow.
*/
t_flowInfo *createNewFlow(u_short srcPort, u_short dstPort, unsigned long srcAddr, unsigned long dstAddr, int proto, struct timeval lstPktTime)
{

	t_flowInfo *newFlow;
	//allocation of the new flow
	newFlow = new t_flowInfo;

	newFlow->srcAddr.s_addr = srcAddr;
	newFlow->dstAddr.s_addr = dstAddr;
	newFlow->srcPort = srcPort;
	newFlow->dstPort = dstPort;
	newFlow->proto = proto;
	newFlow->pktCnt = 1;
	newFlow->byteCnt = 0;
	newFlow->lstPktTime.tv_usec = lstPktTime.tv_usec;
	newFlow->lstPktTime.tv_sec = lstPktTime.tv_sec;
	newFlow->startTime.tv_usec = lstPktTime.tv_usec;
	newFlow->startTime.tv_sec = lstPktTime.tv_sec;

	switch(proto)
	{
		case UDP_PROTO:
			newFlow->isExpired = true;  //udp flow is expired immediately
		case TCP_PROTO:
		case ICMP_PROTO:
		case IGMP_PROTO:
		default:
			newFlow->isExpired = false;
			break;
	}

	return newFlow;
}

/*
* Function processing the TCP packet.
*/
int processTCP(const u_char *packet, t_flowInfoVector *flowInfoVector, t_flowInfoVector *expiredFlowInfoVector, struct ip *myIP, struct timeval pktTime, bpf_u_int32 len, t_params params)
{
	struct tcphdr *myTCP;
	t_flowInfo *currentFlow;

	// retype packet to possibility to read information from it
	myTCP = (struct tcphdr*) (packet+ETH_HEADER+(myIP->ip_hl*4));

	//store the flags - TH_RST/TH_FIN will be interested for us
	u_char flags = myTCP->th_flags;

	if (DEBUG)
	{
		SOUT << "\t\tTCP protocol processing." << std::endl;
		SOUT << "\t\tsrc port: " << u_short(myTCP->th_sport) << "\tdst port: " << u_short(myTCP->th_dport) << std::endl;
		SOUT << "\t\tsrc addr: " << inet_ntoa(myIP->ip_src) << "\tdst addr: " << inet_ntoa(myIP->ip_dst) << std::endl;

		#define	TH_FIN	0x01
		#define	TH_SYN	0x02
		#define	TH_RST	0x04
		#define	TH_PUSH	0x08
		#define	TH_ACK	0x10
		#define	TH_URG	0x20
		switch(flags)
		{
			case TH_RST:
			SOUT << "\t\tTCP FLAG: RST" << std::endl;
			break;
			case TH_FIN:
			SOUT << "\t\tTCP FLAG: FIN" << std::endl;
			break;
			case TH_ACK:
			SOUT << "\t\tTCP FLAG: ACK" << std::endl;
			break;
			case TH_SYN:
			SOUT << "\t\tTCP FLAG: SYN" << std::endl;
			break;
		}
		
	}

	bool needNewFlow = true;
		
	for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ++iterator) 
	{
		if ((*iterator)->proto == TCP_PROTO && (((pktTime.tv_sec) - ((*iterator)->lstPktTime.tv_sec)) >= params.intervalToExpire ))
		{
			//this flow have to be expired - because tcp connection is inactive for time longer than intervalToExpire
			if (DEBUG)
				SOUT << "Unactive timeout off!" << std::endl;

			if (DEBUG)
				SOUT << "before: expired: " << expiredFlowInfoVector->size() << "  cache: " << flowInfoVector->size() << std::endl;
			expiredFlowInfoVector->push_back(*iterator);
			flowInfoVector->erase(iterator);
			
			if (DEBUG)
				SOUT << "after: expired: " << expiredFlowInfoVector->size() << "  cache: " << flowInfoVector->size() << std::endl;
		}
		if ((*iterator)->dstPort == u_short(myTCP->th_dport) && 
			(*iterator)->srcPort == u_short(myTCP->th_sport) && 
			(*iterator)->dstAddr.s_addr == myIP->ip_dst.s_addr &&
			(*iterator)->srcAddr.s_addr == myIP->ip_src.s_addr &&
			(*iterator)->proto == TCP_PROTO)
		{
			//packet with known information founded - adding packet into existing flow
			if (DEBUG)
				SOUT << "This packet is part of already existing flow!" << std::endl;
			((*iterator)->pktCnt)++;
			(*iterator)->byteCnt += len;
			needNewFlow = false;
			break;
		}
	}

	if (needNewFlow)
	{
		//check if there are more than max-flows in cache
		if (flowInfoVector->size() >= params.maxFlows)
		{
			if (DEBUG)
				SOUT << "Max-flows in cache reached!" << std::endl;
			struct timeval oldstTime;
			oldstTime.tv_sec = pktTime.tv_sec;
			oldstTime.tv_usec = 999999;
			t_flowInfoVector::iterator iteratorOldst;
			//the older flow has to be expired
			for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ++iterator) 
			{
				if ((*iterator)->startTime.tv_sec < oldstTime.tv_sec) 
				{
					oldstTime.tv_sec = (*iterator)->startTime.tv_sec;
					oldstTime.tv_usec = (*iterator)->startTime.tv_usec;
					iteratorOldst = iterator;
				}
				else if ((*iterator)->startTime.tv_sec == oldstTime.tv_sec)
				{
					if ((*iterator)->startTime.tv_usec < oldstTime.tv_usec)
					{
						oldstTime.tv_usec = (*iterator)->startTime.tv_usec;
						iteratorOldst = iterator;
					}
				}
			}
			if (DEBUG)
				SOUT << "before: expired: " << expiredFlowInfoVector->size() << "  cache: " << flowInfoVector->size() << std::endl;
			expiredFlowInfoVector->push_back(*iteratorOldst);
			flowInfoVector->erase(iteratorOldst);
			if (DEBUG)
				SOUT << "after: expired: " << expiredFlowInfoVector->size() << "  cache: " << flowInfoVector->size() << std::endl;

		}

		//this packet will be the firts in new flow, we have to created the new flow and save important information about this packet/flow
		currentFlow = createNewFlow(u_short(myTCP->th_sport), u_short(myTCP->th_dport), 
			myIP->ip_src.s_addr, myIP->ip_dst.s_addr, TCP_PROTO, pktTime);
		currentFlow->byteCnt += len;

		flowInfoVector->push_back(currentFlow);

		if (DEBUG)
		{
			SOUT << "ADDED NEW FLOW: "<< std::endl << "TCP src port: " << u_short(myTCP->th_sport) << "  TCP dst port: " << u_short(myTCP->th_dport) << std::endl;
		}
	}
	return 0;
}

int processUDP(const u_char *packet, t_flowInfoVector *flowInfoVector, t_flowInfoVector *expiredFlowInfoVector, struct ip *myIP, struct timeval pktTime, bpf_u_int32 len, t_params params)
{
	struct udphdr *myUDP;
	t_flowInfo *currentFlow;

	myUDP = (struct udphdr*) (packet+ETH_HEADER+(myIP->ip_hl*4));

	if (DEBUG)
	{
		SOUT << "\t\tUDP protocol processing." << std::endl;
		SOUT << "\t\tsrc port: " << u_short(myUDP->uh_sport) << "\tdst port: " << u_short(myUDP->uh_dport) << std::endl;
		SOUT << "\t\tsrc addr: " << inet_ntoa(myIP->ip_src) << "\tdst addr: " << inet_ntoa(myIP->ip_dst) << std::endl;
	}

	//every UDP packet = new expired flow

	currentFlow = createNewFlow(u_short(myUDP->uh_sport), u_short(myUDP->uh_dport), 
			myIP->ip_src.s_addr, myIP->ip_dst.s_addr, UDP_PROTO, pktTime);
	currentFlow->byteCnt = len;
	currentFlow->endTime.tv_usec = pktTime.tv_usec;
	currentFlow->endTime.tv_sec = pktTime.tv_sec;

	expiredFlowInfoVector->push_back(currentFlow);

	return 0;

}