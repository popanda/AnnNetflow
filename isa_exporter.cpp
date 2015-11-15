#include "isa_exporter.h"


int main(int argc, char **argv)
{
	t_params params;
	const u_char *packet;

	//structure for store the beggining of the interval after what the expired flows will be exported
	struct timeval *intervalBgn;
	intervalBgn = new struct timeval;

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
			intervalBgn->tv_sec = packetHeader.ts.tv_sec;
			intervalBgn->tv_usec = packetHeader.ts.tv_usec;
			isFirstPkt = false;
		}

		if (DEBUG)
		{
			SOUT << "\n\n\tCECKING THE INTERVAL TO EXPORT:";
			SOUT << "  pktTime.tv_sec:" << pktTime.tv_sec << "  -  intervalBgn->tv_sec:" << intervalBgn->tv_sec << " (" << pktTime.tv_sec - intervalBgn->tv_sec << ")  >=  " << "params.intervalToExport:" << params.intervalToExport << std::endl;
		}

		//check the interval to export expire flows 
		if ((pktTime.tv_sec - intervalBgn->tv_sec) >= params.intervalToExport)
		{
			if (DEBUG)
			{
				SOUT << "\t --> Interval to export reached!" 
					 << "\tExporting expired flows!" << std::endl;
			}

			exportExpired(flowInfoVector, expiredFlowInfoVector, pktTime, intervalBgn);

		}

		//check timeout of unactive TCP connection

		for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ++iterator) 
		{
			if (DEBUG)
			{
				SOUT << "\tCECKING THE timeout TO EXPIRE:";
				SOUT << "\tpktTime.tv_sec:" << pktTime.tv_sec << "  -  (*iterator)->lstPktTime.tv_sec:" << (*iterator)->lstPktTime.tv_sec << " (" << ((pktTime.tv_sec) - ((*iterator)->lstPktTime.tv_sec))  << ")  >=  " << "params.intervalToExpire:" << params.intervalToExpire << std::endl;
			}

			if ((*iterator)->proto == TCP_PROTO && (((pktTime.tv_sec) - ((*iterator)->lstPktTime.tv_sec)) >= params.intervalToExpire ))
			{
				//this flow have to be expired - because tcp connection is inactive for time longer than intervalToExpire
				if (DEBUG)
					SOUT << "\t --> Unactive timeout reached!" << std::endl;

				if (DEBUG)
					SOUT << "\tbefore: expired: " << expiredFlowInfoVector->size() << "  cache: " << flowInfoVector->size() << std::endl;
				expiredFlowInfoVector->push_back(*iterator);
				flowInfoVector->erase(iterator);
				
				if (DEBUG)
					SOUT << "\tafter: expired: " << expiredFlowInfoVector->size() << "  cache: " << flowInfoVector->size() << std::endl;
			}
		}
		


		etherPtr = (struct ether_header *) packet;

		if (DEBUG)
		{
			SOUT << "\tRecieved packet time (seconds):" << pktTime.tv_sec << " \t(microseconds):" << pktTime.tv_usec << std::endl;
			SOUT << "\tLength " << packetHeader.len << " received at " << ctime((const time_t*)&packetHeader.ts.tv_sec);
			//SOUT << "\tSource MAC: " << ether_ntoa((const struct ether_addr *)&etherPtr->ether_shost) << std::endl;
		}

		//check if its IP packet - the others will be ignored
		if (ntohs(etherPtr->ether_type) == ETHERTYPE_IP)         
		{
			struct ip *myIP;
			myIP = (struct ip*) (packet+ETH_HEADER);

			if (0)
			{
				SOUT << "\tEthernet type packet processing..." << std::endl;
				SOUT << "\tIP id " << ntohs(myIP->ip_id) << ", header lenght "<< myIP->ip_hl*4 << "bytes, version " << myIP->ip_v << std::endl;;
				SOUT << "\tIP type of service: " << u_short(myIP->ip_tos) << "\tIP total length " << myIP->ip_len << " bytes, TTL " << u_short(myIP->ip_ttl) << std::endl;
			}

			//what kind of protocol the current packet is?
			switch(myIP->ip_p)
			{	
				case TCP_PROTO: tcps++; tcpsb += packetHeader.len; //increment counter of tcp packets and bytes sended in its
				retValue = processTCP(packet, flowInfoVector, expiredFlowInfoVector, myIP, pktTime, packetHeader.len, params, intervalBgn);
				break; 
				case UDP_PROTO: udps++; udpsb += packetHeader.len; //increment counter of udp packets and bytes sended in its
				retValue = processUDP(packet, flowInfoVector, expiredFlowInfoVector, myIP, pktTime, packetHeader.len, params, intervalBgn);
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
				SOUT << "\tARP packet processing..." << std::endl;
				arps++;
			}
		}
		else
		{
			if (DEBUG)
			{
				SOUT << "\tEthernet type 0x" << ntohs(etherPtr->ether_type) << " not IPv4" << std::endl;	
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

		//TODO: expireAll, export all


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
t_flowInfo *createNewFlow(t_pktInfo pktInfo, struct timeval lstPktTime)
{

	t_flowInfo *newFlow;
	//allocation of the new flow
	newFlow = new t_flowInfo;

	newFlow->srcAddr.s_addr = pktInfo.srcAddr.s_addr;
	newFlow->dstAddr.s_addr = pktInfo.dstAddr.s_addr;
	newFlow->srcPort = pktInfo.srcPort;
	newFlow->dstPort = pktInfo.dstPort;
	newFlow->proto = pktInfo.proto;
	newFlow->pktCnt = 1;
	newFlow->byteCnt = 0;
	newFlow->lstPktTime.tv_usec = lstPktTime.tv_usec;
	newFlow->lstPktTime.tv_sec = lstPktTime.tv_sec;
	newFlow->startTime.tv_usec = lstPktTime.tv_usec;
	newFlow->startTime.tv_sec = lstPktTime.tv_sec;
	newFlow->oneAckToExp = false;

	if (pktInfo.proto == UDP_PROTO)
	{
		newFlow->endTime.tv_usec = lstPktTime.tv_usec;
		newFlow->endTime.tv_sec = lstPktTime.tv_sec;
	}
	return newFlow;
}

/*
* Function processing the TCP packet.
*/
int processTCP(const u_char *packet, t_flowInfoVector *flowInfoVector, t_flowInfoVector *expiredFlowInfoVector, struct ip *myIP, struct timeval pktTime, bpf_u_int32 len, t_params params, struct timeval *intervalBgn)
{
	struct tcphdr *myTCP;
	t_flowInfo *currentFlow;

	// retype packet to possibility to read information from it
	myTCP = (struct tcphdr*) (packet+ETH_HEADER+(myIP->ip_hl*4));

	//fills the auxillinary variable with real values
	t_pktInfo pktInfo;
	pktInfo.srcAddr.s_addr = myIP->ip_src.s_addr;
	pktInfo.dstAddr.s_addr = myIP->ip_dst.s_addr;
	pktInfo.srcPort = u_short(myTCP->th_sport);
	pktInfo.dstPort = u_short(myTCP->th_dport);
	pktInfo.proto = TCP_PROTO;

	//store the flags - RST/FIN will be interested for us
	std::bitset<8> flags = myTCP->th_flags;
	
	if (DEBUG)
	{
		SOUT << "\tTCP (" << inet_ntoa(myIP->ip_src) << ":" << u_short(myTCP->th_sport) << " --> "  
			 << inet_ntoa(myIP->ip_dst) << ":" << u_short(myTCP->th_dport) << ") PROTOCOL PROCESSING." << " FLAGS: " << flags << std::endl;	
	}

	bool needNewFlow = true;
		
	for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ++iterator) 
	{
		if (isEqualFlow(pktInfo, *iterator))
		{
			//flow with known information founded - adding packet into existing flow
			if (DEBUG)
				SOUT << "\tThis packet is part of already existing flow!" << std::endl;
			//inkrements packet and byte counter in this flow
			((*iterator)->pktCnt)++;
			(*iterator)->byteCnt += len;
			//set the last packet time on this packet time
			(*iterator)->lstPktTime.tv_sec = pktTime.tv_sec;
			(*iterator)->lstPktTime.tv_usec = pktTime.tv_usec;
			currentFlow = *iterator;
			needNewFlow = false;
			break;
		}
	}

	//flow with the same onformation as this packet has is not fouded - has to be created new flow 
	if (needNewFlow)
	{
		//at first check if there are more than max-flows in cache
		if (flowInfoVector->size() + expiredFlowInfoVector->size() >= params.maxFlows)
		{
			if (DEBUG)
			{
				SOUT << "\t --> Max-flows in cache reached!" 
					 << "\tExporting expired flows!" << std::endl;
			}
			exportExpired(flowInfoVector, expiredFlowInfoVector, pktTime, intervalBgn);	
		}

		//this packet will be the firts in new flow, we have to created the new flow and save important information about this packet/flow
		currentFlow = createNewFlow(pktInfo, pktTime);
		currentFlow->byteCnt += len;

		flowInfoVector->push_back(currentFlow);

		if (DEBUG)
		{
			SOUT << "\tNew flow added: "<< inet_ntoa(currentFlow->srcAddr) << ":" << currentFlow->srcPort << " --> "  
			 << inet_ntoa(currentFlow->dstAddr) << ":" << currentFlow->dstPort << " Flows in cache now: " << flowInfoVector->size() << " Expired flows: " << expiredFlowInfoVector->size() << std::endl;
		}
	}

	//check the flags
	if (flags.test(0))
	{
		//FIN flag founded --> this connection will be closed from one side	after ACK flag will be sent
		currentFlow->oneAckToExp = true;
		if (DEBUG)
			SOUT << "\tFIN flag founded. " << std::endl;
	}
	if (flags.test(2))
	{
		//RST flag founded --> immediately reset this connection - both sides
		if (DEBUG)
			SOUT << "\tRST flag founded. " << std::endl;
		for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ++iterator) 
		{
			if (isEqualFlow(pktInfo, *iterator))
			{
				expiredFlowInfoVector->push_back(*iterator);
				flowInfoVector->erase(iterator);
				break;				
			}
		}
		for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ++iterator) 
		{
			if (isOppositeFlow(pktInfo, *iterator))
			{
				expiredFlowInfoVector->push_back(*iterator);
				flowInfoVector->erase(iterator);
				break;
			}
		}
	}
	
	if (flags.test(4))
	{
		//ACK flag founded
		//looking for opposite flow and check if waiting for one ack to expire
		for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ++iterator) 
		{
			if (isOppositeFlow(pktInfo, *iterator))
			{
				if ((*iterator)->oneAckToExp)
				{
					//this opposite flow will be expired
					expiredFlowInfoVector->push_back(*iterator);
					flowInfoVector->erase(iterator);
					if (DEBUG)
						SOUT << "\tACK flag founded after FIN --> Adding opposite flow to expired, erasing from cache..." << std::endl;
				}

				break;
			}
		}
	}

	if (DEBUG)
	{
		SOUT << "Expired flows: " << std::endl;
		for(t_flowInfoVector::iterator iterator = expiredFlowInfoVector->begin(); iterator != expiredFlowInfoVector->end(); ++iterator) 
		{
			SOUT << "\t\t" << inet_ntoa((*iterator)->srcAddr) << ":" << (*iterator)->srcPort << " --> " << inet_ntoa((*iterator)->dstAddr) << ":" << (*iterator)->dstPort << std::endl;
		}
		SOUT << "Processing flows: " << std::endl;
		for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ++iterator) 
		{
			SOUT << "\t\t" << inet_ntoa((*iterator)->srcAddr) << ":" << (*iterator)->srcPort << " --> " << inet_ntoa((*iterator)->dstAddr) << ":" << (*iterator)->dstPort << std::endl;
		}
	}

	return 0;
}

int processUDP(const u_char *packet, t_flowInfoVector *flowInfoVector, t_flowInfoVector *expiredFlowInfoVector, struct ip *myIP, struct timeval pktTime, bpf_u_int32 len, t_params params, struct timeval *intervalBgn)
{
	struct udphdr *myUDP;
	t_flowInfo *currentFlow;

	myUDP = (struct udphdr*) (packet+ETH_HEADER+(myIP->ip_hl*4));

	t_pktInfo pktInfo;
	pktInfo.srcAddr.s_addr = myIP->ip_src.s_addr;
	pktInfo.dstAddr.s_addr = myIP->ip_dst.s_addr;
	pktInfo.srcPort = u_short(myUDP->uh_sport);
	pktInfo.dstPort = u_short(myUDP->uh_dport);
	pktInfo.proto = TCP_PROTO;

	if (DEBUG)
	{
		SOUT << "\tUDP (" << inet_ntoa(myIP->ip_src) << " : " << u_short(myUDP->uh_sport) << "  -->  "  
			 << inet_ntoa(myIP->ip_dst) << " : " << u_short(myUDP->uh_dport) << ") PROTOCOL PROCESSING." << std::endl;
	}

	//every UDP packet = new expired flow
	//check if cahce is full
	if (flowInfoVector->size() + expiredFlowInfoVector->size() >= params.maxFlows)
	{
		if (DEBUG)
		{
			SOUT << "\t --> Max-flows in cache reached!" 
				 << "\tExporting expired flows!" << std::endl;
		}
		exportExpired(flowInfoVector, expiredFlowInfoVector, pktTime, intervalBgn);	
	}

	currentFlow = createNewFlow(pktInfo, pktTime);
	currentFlow->byteCnt += len;

	//adds this udp flow into expired flows
	expiredFlowInfoVector->push_back(currentFlow);

	if (DEBUG)
	{
		SOUT << "Expired flows: " << std::endl;
		for(t_flowInfoVector::iterator iterator = expiredFlowInfoVector->begin(); iterator != expiredFlowInfoVector->end(); ++iterator) 
		{
			SOUT << "\t\t" << inet_ntoa((*iterator)->srcAddr) << ":" << (*iterator)->srcPort << " --> " << inet_ntoa((*iterator)->dstAddr) << ":" << (*iterator)->dstPort << std::endl;
		}
		SOUT << "Processing flows: " << std::endl;
		for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ++iterator) 
		{
			SOUT << "\t\t" << inet_ntoa((*iterator)->srcAddr) << ":" << (*iterator)->srcPort << " --> " << inet_ntoa((*iterator)->dstAddr) << ":" << (*iterator)->dstPort << std::endl;
		}
	}

	return 0;

}

/*
* Function compare flow given as @param flow with the given other five params - src address, dst address, src port, dst port and protocol 
* funcion returns 1 if searching is successful, 0 if not
*/
int isEqualFlow(t_pktInfo pktInfo, t_flowInfo *flow)
{
	return (
	flow->srcAddr.s_addr == pktInfo.srcAddr.s_addr &&
	flow->dstAddr.s_addr == pktInfo.dstAddr.s_addr &&
	flow->srcPort == pktInfo.srcPort && 
	flow->dstPort == pktInfo.dstPort && 	
	flow->proto == pktInfo.proto
	);
}
/*
* The same function as above - only chceck if in @param flow is the opposite flow from than which information are in the others params
*/
int isOppositeFlow(t_pktInfo pktInfo, t_flowInfo *flow)
{
	return (
	flow->srcAddr.s_addr == pktInfo.dstAddr.s_addr &&
	flow->dstAddr.s_addr == pktInfo.srcAddr.s_addr &&
	flow->srcPort == pktInfo.dstPort && 
	flow->dstPort == pktInfo.srcPort  && 	
	flow->proto == pktInfo.proto
	);
}

int exportExpired(t_flowInfoVector *flowInfoVector, t_flowInfoVector *expiredFlowInfoVector, struct timeval pktTime, struct timeval *intervalBgn)
{
	if (expiredFlowInfoVector->size() == 0)
	{
		//auxilliary variable storing the oldest time of connection in cache
		struct timeval oldstTime;
		oldstTime.tv_sec = pktTime.tv_sec;
		oldstTime.tv_usec = 999999;

		//auxilliary iterator for storing the oldest flow 
		t_flowInfoVector::iterator iteratorOldst;

		if (DEBUG)
			SOUT << "\tNo expired flow to export." << std::endl;
		
		for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ++iterator) 
		{
			SOUT << "\t(*iterator)->startTime.tv_sec: " << (*iterator)->startTime.tv_sec
				 << " oldstTime.tv_sec: " << oldstTime.tv_sec 
				 << "\t(*iterator)->startTime.tv_usec: " << (*iterator)->startTime.tv_usec
				 << " oldstTime.tv_usec: " << oldstTime.tv_usec << std::endl; 
			//comes through all flows in cache and tries to find the oldest connection
			if ((*iterator)->startTime.tv_sec < oldstTime.tv_sec) 
			{
				//the founded flow has less seconds (=is older) -> rewrite temporary oldest
				oldstTime.tv_sec = (*iterator)->startTime.tv_sec;
				oldstTime.tv_usec = (*iterator)->startTime.tv_usec;
				iteratorOldst = iterator;
			}
			else if ((*iterator)->startTime.tv_sec == oldstTime.tv_sec)
			{
				//seconds are equal - chceck microseconds
				if ((*iterator)->startTime.tv_usec < oldstTime.tv_usec)
				{
					oldstTime.tv_usec = (*iterator)->startTime.tv_usec;
					iteratorOldst = iterator;
				}
			}
		}
		if (DEBUG)
			SOUT << "\tExpiring the odest one:" << inet_ntoa((*iteratorOldst)->srcAddr) << ":" << (*iteratorOldst)->srcPort << " --> " << inet_ntoa((*iteratorOldst)->dstAddr) << ":" << (*iteratorOldst)->dstPort
				 << "\n\tbefore: expired: " << expiredFlowInfoVector->size() << "  cache: " << flowInfoVector->size();
		//moves the oldes flow to expired 
		expiredFlowInfoVector->push_back(*iteratorOldst);
		//removes this flow from cache
		flowInfoVector->erase(iteratorOldst);
		if (DEBUG)
			SOUT << "\tafter: expired: " << expiredFlowInfoVector->size() << "  cache: " << flowInfoVector->size() << std::endl;

	}

	if (DEBUG)
	{
		SOUT << "\tExporting: ..." << std::endl;
		for(t_flowInfoVector::iterator iterator = expiredFlowInfoVector->begin(); iterator != expiredFlowInfoVector->end(); ++iterator) 
		{
			SOUT << inet_ntoa((*iterator)->srcAddr) << ":" << (*iterator)->srcPort << " --> " << inet_ntoa((*iterator)->dstAddr) << ":" << (*iterator)->dstPort << std::endl;
		}

	}
	//restart interval to export
	intervalBgn->tv_sec = pktTime.tv_sec;
	intervalBgn->tv_usec = pktTime.tv_usec;

	expiredFlowInfoVector->clear();
}
