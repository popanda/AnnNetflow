#include "isa_exporter.h"
#include "packets.h"

// number of flows seen since the virtual machine isa2015 boted
u_int32_t flowSequence;

// time of the first packet arrival (SysUptime for us)
double firstPktArr;


int main(int argc, char **argv)
{
	flowSequence = 0;
	
	t_params params;
	const u_char *packet;

	//variable for store the beggining of the interval after what the expired flows will be exported
	double *intervalBgn;

	//structure for store the current time = time of the processing packet
	struct timeval pktTime;
	
	intervalBgn = new double;
	//ntervalBgn = new struct timeval;

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
	{
		SERR << "Error occured while opening pcap file. The file is most likely invalid." << std::endl;
		return 1;
	}

	bool isFirstPkt = true;
	//main cycle for processing packets from the file - cycle until EOF
	while ((packet = pcap_next(pcapHandle, &packetHeader)) != NULL)
	{
		//store the timestamp of current packet
		pktTime.tv_sec = packetHeader.ts.tv_sec;
		pktTime.tv_usec = packetHeader.ts.tv_usec;

		//check if it is first packet -> will be the beginning of the interval after that the export of expire flows will be done
		if (isFirstPkt)
		{
			*intervalBgn = timeInSeconds(packetHeader.ts);
			firstPktArr = timeInSeconds(packetHeader.ts);
			isFirstPkt = false;
		}
		
		if (DEBUG)
			SOUT << "\n\nPcket no. " << tcps + udps + icmps + igmps + 1 << std::endl;

		if (MORE_DEBUG)
		{
			SOUT << "\tCECKING THE INTERVAL TO EXPORT:";
			//SOUT << "  pktTime.tv_sec:" << pktTime.tv_sec << "  -  intervalBgn->tv_sec:" << intervalBgn->tv_sec << " (" << pktTime.tv_sec - intervalBgn->tv_sec << ")  >=  " << "params.intervalToExport:" << params.intervalToExport << std::endl;
			SOUT << "  pktTime:" << std::fixed << timeInSeconds(pktTime) << "  -  intervalBgn:" << std::fixed << *intervalBgn << " (" << std::fixed << timeInSeconds(pktTime) - *intervalBgn << ")  >=  " << "params.intervalToExport:" << params.intervalToExport << std::endl;
		}

		//check the interval to export expire flows 
		if ((timeInSeconds(pktTime) - *intervalBgn) >= params.intervalToExport)
		{
			if (DEBUG)
			{
				SOUT << "\t --> Interval to export reached!" 
					 << "\tExporting expired flows!" << std::endl;
			}

			if ((exportExpired(expiredFlowInfoVector, pktTime, intervalBgn, params)) != 0)
			{
				SERR << "Error occured while exporting to collector." << std::endl;
				return 1;
			}

		}

		//check timeout of unactive TCP connection

		for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ) 
		{
			if (MORE_DEBUG)
			{
				SOUT << "\tCHECKING THE timeout TO EXPIRE:";
				SOUT << "\tpktTime:" << std::fixed << timeInSeconds(pktTime) << "  -  (*iterator)->lstPktTime:" << std::fixed << timeInSeconds((*iterator)->lstPktTime) << " (" << std::fixed << (timeInSeconds(pktTime) - timeInSeconds((*iterator)->lstPktTime)) << ")  >=  params.intervalToExpire:" << params.intervalToExpire << std::endl;
			}

			if ((*iterator)->proto == TCP_PROTO && ( (timeInSeconds(pktTime) - timeInSeconds((*iterator)->lstPktTime) ) >= params.intervalToExpire ))
			{
				//this flow have to be expired - because tcp connection is inactive for time longer than intervalToExpire
				if (DEBUG)
					SOUT << "\t --> Unactive timeout reached!" << std::endl;

				if (MORE_DEBUG)
					SOUT << "\tbefore: expired: " << expiredFlowInfoVector->size() << "  cache: " << flowInfoVector->size() << std::endl;
				
				//expiring this flow
				(*iterator)->endTime.tv_sec = pktTime.tv_sec;
				(*iterator)->endTime.tv_usec = pktTime.tv_usec;
				expiredFlowInfoVector->push_back(*iterator);
				flowInfoVector->erase(iterator);
				
				if (MORE_DEBUG)
					SOUT << "\tafter: expired: " << expiredFlowInfoVector->size() << "  cache: " << flowInfoVector->size() << std::endl;
			}
			else
				++iterator;
		}
		


		etherPtr = (struct ether_header *) packet;

		if (DEBUG)
		{
			SOUT << "\tRecieved packet time (seconds):" << pktTime.tv_sec << " \t(microseconds):" << pktTime.tv_usec << std::endl;
			SOUT << "\tFunction timeInSeconds says: " << std::fixed << timeInSeconds(pktTime) << std::endl;
			SOUT << "\tLength " << packetHeader.len << " received at " << ctime((const time_t*)&packetHeader.ts.tv_sec);
			//SOUT << "\tSource MAC: " << ether_ntoa((const struct ether_addr *)&etherPtr->ether_shost) << std::endl;
		}

		//check if its IP packet - the others will be ignored
		if (ntohs(etherPtr->ether_type) == ETHERTYPE_IP)         
		{
			struct ip *myIP;
			myIP = (struct ip*) (packet+ETH_HEADER);

			//what kind of protocol the current packet is?
			switch(myIP->ip_p)
			{	
				case TCP_PROTO: tcps++; tcpsb += packetHeader.len; //increment counter of tcp packets and bytes sended in its
				retValue = processTCP(packet, flowInfoVector, expiredFlowInfoVector, myIP, pktTime, packetHeader.len, params, intervalBgn);
				break; 
				case UDP_PROTO: udps++; udpsb += packetHeader.len; //increment counter of udp packets and bytes sended in its
				retValue = processUDPorICMPorIGMP(packet, flowInfoVector, expiredFlowInfoVector, myIP, pktTime, packetHeader.len, params, intervalBgn);
				break;
				case ICMP_PROTO: icmps++; icmpsb += packetHeader.len;
				retValue = processUDPorICMPorIGMP(packet, flowInfoVector, expiredFlowInfoVector, myIP, pktTime, packetHeader.len, params, intervalBgn);
				break;
				case IGMP_PROTO: igmps++; igmpsb += packetHeader.len;
				retValue = processUDPorICMPorIGMP(packet, flowInfoVector, expiredFlowInfoVector, myIP, pktTime, packetHeader.len, params, intervalBgn);
				break; 
				default:
					retValue = 2; 
			}

			if (retValue != 0)
			{				
				if (retValue == 1)
					SERR << "Error while proccesing TCP/UDP/ICMP/IGMP packet" << std::endl;
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
				
			}
			arps++;
		}
		else
		{
			if (DEBUG)
			{
				SOUT << "\tEthernet type 0x" << ntohs(etherPtr->ether_type) << " not IPv4" << std::endl;	
			}
			others++;
		}
	}
	
	if (DEBUG)
	{

		for(t_flowInfoVector::iterator iterator = expiredFlowInfoVector->begin(); iterator != expiredFlowInfoVector->end(); ++iterator) 
		{
			SOUT << (*iterator)->srcPort << " : " << (*iterator)->dstPort << "  |  " << inet_ntoa((*iterator)->srcAddr) << " : " << inet_ntoa((*iterator)->dstAddr) << "  |  " <<
			(*iterator)->proto << "  |  " << "packets: " << (*iterator)->pktCnt << "  |  bytes: " << (*iterator)->byteCnt << std::endl;
		}
	}

		SOUT << "Number of expired flows: " << expiredFlowInfoVector->size() << std::endl;
		SOUT << "Number of flows in cache: " << flowInfoVector->size() << std::endl;
		SOUT << "End of file reached..." << std::endl;

		if ((expireAll(flowInfoVector, expiredFlowInfoVector, pktTime)) != 0)
		{
			SERR << "Error occured while expiring the rest of the processing flows." << std::endl;
			return 1;
		}
		if ((exportExpired(expiredFlowInfoVector, pktTime, intervalBgn, params)) != 0)
		{
			SERR << "Error occured while exporting." << std::endl;
			return 1;
		}

		SOUT << "== STATISTICS ==" << std::endl;
		SOUT << "Total flows: " << flowSequence << std::endl;
		SOUT << "TCP \tpackets: " << tcps << ",\tbytes: " << tcpsb << std::endl;
		SOUT << "UDP \tpackets: " << udps << ",\tbytes: " << udpsb << std::endl;
		SOUT << "ICMP \tpackets: " << icmps << ",\tbytes: " << icmpsb << std::endl;
		SOUT << "IGMP \tpackets: " << igmps << ",\tbytes: " << igmpsb << std::endl;
		SOUT << "ARP \tpackets: " << arps << ",\tbytes: " << arpsb << std::endl;
		SOUT << "OTHER \tpackets: " << others << ",\tbytes: " << othersb << std::endl;
		SOUT << "total \tpackets: " << tcps + udps + icmps + igmps << ",\tbytes: " << 
		tcpsb + udpsb + icmpsb + igmpsb << std::endl;
		
		SOUT << "== END OF STATISTICS ==" << std::endl;

	

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
		u_int16_t i = 1;
		std::vector<std::string> splitted; 
		std::string tmpString;

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
				tmpString.assign(optarg);
				SOUT << "Parsing: " << tmpString << std::endl;
				splitted = split(tmpString, ':');
				for(std::vector<std::string>::iterator iterator = splitted.begin(); iterator != splitted.end(); ++iterator) 
				{			
					
					if (i == 1)
					{
						SOUT << "Adress processing." << *iterator << std::endl;
// 						if ((inet_aton(, &(ptrParams->collectorAddr))) == 0)
// 						{
// 							SERR << "Invalid collector address."<< std::endl << "Exiting..." << std::endl;
// 							return -1;
// 						}
					}	
					else
					{
						//port processing
						SOUT << "Port processing." << std::endl;
// 						ptrParams->collectorPort = strtol(*iterator, &endPtr, 10);
						if (*endPtr != '\0')
						{
							SERR << "Invalid value for max-flows." << std::endl << "Exiting..." << std::endl;
							return -1;
						}
						
					}	
					i++;
				}
							
				if(DEBUG)
					SOUT << "Option collector with value " << optarg << "." << std::endl;

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

	if (pktInfo.proto == UDP_PROTO || pktInfo.proto == ICMP_PROTO || pktInfo.proto == IGMP_PROTO)
	{
		newFlow->endTime.tv_usec = lstPktTime.tv_usec;
		newFlow->endTime.tv_sec = lstPktTime.tv_sec;
		newFlow->tcpFlags = 0;
	}
	
	flowSequence++;
	
	return newFlow;
}

/*
* Function processing the TCP packet.
*/
int processTCP(const u_char *packet, t_flowInfoVector *flowInfoVector, t_flowInfoVector *expiredFlowInfoVector, struct ip *myIP, struct timeval pktTime, bpf_u_int32 len, t_params params, double *intervalBgn)
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
	bool expireImmediately = false;
		
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
		if (needNewFlow)
			expireImmediately = true; //this packet is alone and will be expired immediately

		if (DEBUG)
			SOUT << "\tRST flag founded. " << std::endl;
		for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ++iterator) 
		{
			if (isEqualFlow(pktInfo, *iterator))
			{
				//expiring this flow
				(*iterator)->endTime.tv_sec = pktTime.tv_sec;
				(*iterator)->endTime.tv_usec = pktTime.tv_usec;
				expiredFlowInfoVector->push_back(*iterator);
				flowInfoVector->erase(iterator);
				break;				
			}
		}
// 		for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ++iterator) 
// 		{
// 			if (isOppositeFlow(pktInfo, *iterator))
// 			{
// 				//expiring this flow
// 				(*iterator)->endTime.tv_sec = pktTime.tv_sec;
// 				(*iterator)->endTime.tv_usec = pktTime.tv_usec;
// 				expiredFlowInfoVector->push_back(*iterator);
// 				flowInfoVector->erase(iterator);
// 				break;
// 			}
// 		}
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
					(*iterator)->endTime.tv_sec = pktTime.tv_sec;
					(*iterator)->endTime.tv_usec = pktTime.tv_usec;
					expiredFlowInfoVector->push_back(*iterator);
					flowInfoVector->erase(iterator);
					if (DEBUG)
						SOUT << "\tACK flag founded after FIN --> Adding opposite flow to expired, erasing from cache..." << std::endl;
					if (needNewFlow)
						expireImmediately = true; //this packet is alone and will be expired immediately
				}

				break;
			}
		}
	}
	
		//flow with the same onformation as this packet has is not fouded - has to be created new flow 
	if (needNewFlow)
	{
		//at first check if there are more than max-flows in cache
		if (flowInfoVector->size() >= params.maxFlows)
		{
			if (DEBUG)
			{
				SOUT << "\t --> Max-flows in cache reached!" 
					 << "\tExpiring the oldest unactive flow!" << std::endl;
			}
			expireOldestUnactive(flowInfoVector, expiredFlowInfoVector, pktTime);
		}
		//this packet will be the firts in new flow, we have to created the new flow and save important information about this packet/flow
		currentFlow = createNewFlow(pktInfo, pktTime);
		currentFlow->tcpFlags = myTCP->th_flags;
		currentFlow->ToS = myIP->ip_tos;
		currentFlow->byteCnt += len;

		if (expireImmediately)
		{
			currentFlow->endTime.tv_usec = pktTime.tv_usec;
			currentFlow->endTime.tv_sec = pktTime.tv_sec;
			expiredFlowInfoVector->push_back(currentFlow);
		}
		else
			flowInfoVector->push_back(currentFlow);

		if (DEBUG)
		{
			SOUT << "\tNew flow added: "<< inet_ntoa(currentFlow->srcAddr) << ":" << currentFlow->srcPort << " --> "  
			 << inet_ntoa(currentFlow->dstAddr) << ":" << currentFlow->dstPort << " Flows in cache now: " << flowInfoVector->size() << " Expired flows: " << expiredFlowInfoVector->size() << std::endl;
		}
	}

	if (MORE_DEBUG)
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

int processUDPorICMPorIGMP(const u_char *packet, t_flowInfoVector *flowInfoVector, t_flowInfoVector *expiredFlowInfoVector, struct ip *myIP, struct timeval pktTime, bpf_u_int32 len, t_params params, double *intervalBgn)
{
	t_flowInfo *currentFlow;
	struct udphdr *myUDPorICMPorIGMP;
	t_pktInfo pktInfo;
	
	pktInfo.srcAddr.s_addr = myIP->ip_src.s_addr;
	pktInfo.dstAddr.s_addr = myIP->ip_dst.s_addr;
	
	myUDPorICMPorIGMP = (struct udphdr*) (packet+ETH_HEADER+(myIP->ip_hl*4));
	
	switch(myIP->ip_p)
	{
		case UDP_PROTO:	
			pktInfo.srcPort = u_short(myUDPorICMPorIGMP->uh_sport);
			pktInfo.dstPort = u_short(myUDPorICMPorIGMP->uh_dport);
			pktInfo.proto = UDP_PROTO;
			if (DEBUG)
			{
				SOUT << "\tUDP (" << inet_ntoa(myIP->ip_src) << " : " << u_short(myUDPorICMPorIGMP->uh_sport) << "  -->  "  << inet_ntoa(myIP->ip_dst) << " : " << u_short(myUDPorICMPorIGMP->uh_dport) << ") PROTOCOL PROCESSING." << std::endl;
			}
			break;
		
		case ICMP_PROTO:
			pktInfo.srcPort = 0; // ICMP does not have ports
			pktInfo.dstPort = 0;
			pktInfo.proto = ICMP_PROTO;
			if (DEBUG)
			{
				SOUT << "\tICMP (" << inet_ntoa(myIP->ip_src) << " : " << u_short(myUDPorICMPorIGMP->uh_sport) << "  -->  "  << inet_ntoa(myIP->ip_dst) << " : " << u_short(myUDPorICMPorIGMP->uh_dport) << ") PROTOCOL PROCESSING." << std::endl;
			}
			break;
		
		case IGMP_PROTO:
			pktInfo.srcPort = 0; // IGMP does not have ports
			pktInfo.dstPort = 0;
			pktInfo.proto = IGMP_PROTO;
			if (DEBUG)
			{
				SOUT << "\tIGMP (" << inet_ntoa(myIP->ip_src) << " : " << u_short(myUDPorICMPorIGMP->uh_sport) << "  -->  "  << inet_ntoa(myIP->ip_dst) << " : " << u_short(myUDPorICMPorIGMP->uh_dport) << ") PROTOCOL PROCESSING." << std::endl;
			}
			break;
	}
	
	//every packet = new expired flow
	//not nessesary to check if cahce is full --> UDP packet goes immediately into expired flows
	/*if (flowInfoVector->size() >= params.maxFlows)
	{
		if (DEBUG)
		{
			SOUT << "\t --> Max-flows in cache reached!" 
				 << "\tExpiring the oldest unactive flow!" << std::endl;
		}
		expireOldestUnactive(flowInfoVector, expiredFlowInfoVector, pktTime);	
	}
	*/

	currentFlow = createNewFlow(pktInfo, pktTime);
	currentFlow->ToS = myIP->ip_tos;
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

int exportExpired(t_flowInfoVector *expiredFlowInfoVector, struct timeval pktTime, double *intervalBgn, t_params params)
{
	

	//1. creates packets for exporting to the collector

	u_short pktCnt; // <--- how many packets do will need? 
	
	double devBootTimeD = firstPktArr;
	double sysuptimeD;
	fourBytes sysuptime;
	
	t_flowInfoVector::iterator lastIterator = expiredFlowInfoVector->begin();
	
	if ((expiredFlowInfoVector->size() % MAX_FLOWS_IN_PACKET) == 0)
	{
		//the number of expired flows is multiple of MAX_FLOWS_IN_PACKET
		pktCnt = expiredFlowInfoVector->size() / MAX_FLOWS_IN_PACKET;
	}
	else
	{
		//some of the sending packets won't be full
		pktCnt = (expiredFlowInfoVector->size() / MAX_FLOWS_IN_PACKET) + 1;
	}
	
	//creates new socket
	int skt;
	struct sockaddr_in saddr;
	
	if ((skt = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	{
		SERR << "Failed on creating packet." << std::endl;
		return -1;
	}
	
	memset(&saddr, 0, sizeof(saddr));
	
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(params.collectorPort);
	saddr.sin_addr = params.collectorAddr;
	
	t_nfPkt *newPkt;
	
	//makes new packet in every cycle and sends it to collector
	for (;pktCnt;pktCnt--)
	{
		newPkt = new t_nfPkt;
		
		u_short flowsCnt = 0;
		
		if (MORE_DEBUG)
			SOUT << "In this packet there will be these flows: " <<  std::endl;

		
		// comes through expired flows and adds into this packet
		for(t_flowInfoVector::iterator iterator = lastIterator; iterator != expiredFlowInfoVector->end(); ++iterator) 
		{
			lastIterator = iterator+1;
			double firstD = ((timeInSeconds((*iterator)->startTime)) - devBootTimeD) * 1000;
			double lastD = ((timeInSeconds((*iterator)->endTime)) - devBootTimeD) * 1000; //*1000 seconds to miliseconds
			
			sysuptimeD = (timeInSeconds(pktTime) - devBootTimeD) * 1000;
			
			fourBytes first = round(firstD);
			fourBytes last = round(lastD);
			
			inet_aton("0.0.0.0", &(newPkt->rec[flowsCnt].nexthop));
			
			newPkt->rec[flowsCnt].srcaddr = (*iterator)->srcAddr;
			newPkt->rec[flowsCnt].dstaddr = (*iterator)->dstAddr;
			newPkt->rec[flowsCnt].dPkts = htonl((*iterator)->pktCnt);
			newPkt->rec[flowsCnt].dOctets = htonl((*iterator)->byteCnt); //TODO
			newPkt->rec[flowsCnt].First = htonl(first);
			newPkt->rec[flowsCnt].Last = htonl(last);
			newPkt->rec[flowsCnt].srcport = (*iterator)->srcPort;
			newPkt->rec[flowsCnt].dstport = (*iterator)->dstPort;
			newPkt->rec[flowsCnt].tcp_flags = (*iterator)->tcpFlags;
			newPkt->rec[flowsCnt].prot = (*iterator)->proto;
			newPkt->rec[flowsCnt].ToS = (*iterator)->ToS;
			
			if (MORE_DEBUG)
			{
				SOUT << inet_ntoa(newPkt->rec[flowsCnt].srcaddr) << " : " << std::endl;
				SOUT << inet_ntoa(newPkt->rec[flowsCnt].dstaddr) << " : " << std::endl;
				SOUT << inet_ntoa(newPkt->rec[flowsCnt].nexthop) << " : " << std::endl;
				SOUT << newPkt->rec[flowsCnt].input << " : " << newPkt->rec[flowsCnt].output << " : " << newPkt->rec[flowsCnt].dPkts << " : " << newPkt->rec[flowsCnt].dOctets << " : " << newPkt->rec[flowsCnt].First << " (" << firstD << ") : " << newPkt->rec[flowsCnt].Last << " ("  << lastD << ") : " << newPkt->rec[flowsCnt].srcport << " : " << newPkt->rec[flowsCnt].dstport << " : " << newPkt->rec[flowsCnt].pad1 << " : " << newPkt->rec[flowsCnt].tcp_flags << " : " << newPkt->rec[flowsCnt].prot <<  " : " << newPkt->rec[flowsCnt].ToS << " : " << newPkt->rec[flowsCnt].src_as << " : " << newPkt->rec[flowsCnt].dst_as << " : " << newPkt->rec[flowsCnt].src_mask << " : " << newPkt->rec[flowsCnt].dst_mask << " : " << newPkt->rec[flowsCnt].pad2 <<  std::endl;
			}
				
			flowsCnt++;
				
			if (flowsCnt >= MAX_FLOWS_IN_PACKET)
				break;
			
		}
		
		//adds header for this packet
		sysuptime = round(sysuptimeD);
		
		newPkt->hdr.count = htons(flowsCnt);
		newPkt->hdr.SysUptime = htonl(sysuptime);
		newPkt->hdr.unix_secs = htonl(pktTime.tv_sec);
		newPkt->hdr.unix_nsecs = htonl(pktTime.tv_usec);
		
		newPkt->hdr.version = htons(5);
		newPkt->hdr.flow_sequence = htonl(flowSequence);
			
		// packet is ready to send
		if (MORE_DEBUG)
		{
			SOUT << "Packet is ready to send (with " << flowsCnt << " flows), total size: " << sizeof(*newPkt) << ", header size: " << sizeof(newPkt->hdr) << ". \nHeader: " <<  std::endl;
			SOUT <<  newPkt->hdr.version << " : " << newPkt->hdr.count << " : " << newPkt->hdr.SysUptime << " ("  << sysuptimeD << ") : " << newPkt->hdr.unix_secs << " : " << newPkt->hdr.unix_nsecs << " : " << newPkt->hdr.flow_sequence << " : " << newPkt->hdr.engine_type << " : " << newPkt->hdr.engine_id << " : " << newPkt->hdr.sampling_interval << std::endl;
		}
			
		//sends this packet
		if ((sendto(skt, newPkt, sizeof(t_nfV5hdr) + flowsCnt * sizeof(t_nfV5flowRec), 0, (const sockaddr *)&saddr, sizeof(saddr))) == -1)
		{
			SERR << "Error occured while sending packet to collector." << std::endl;
			return -1;
		}
		
		if (MORE_DEBUG)
			SOUT << "Packet sended successfuly!" << std::endl;
		
		delete newPkt;
		
	}

	
	if (MORE_DEBUG)
	{
		SOUT << "\tExporting: ..." << std::endl;
		for(t_flowInfoVector::iterator iterator = expiredFlowInfoVector->begin(); iterator != expiredFlowInfoVector->end(); ++iterator) 
		{
			SOUT << inet_ntoa((*iterator)->srcAddr) << ":" << (*iterator)->srcPort << " --> " << inet_ntoa((*iterator)->dstAddr) << ":" << (*iterator)->dstPort << std::endl;
		}

	}
	//restart interval to export
	*intervalBgn = timeInSeconds(pktTime);

	expiredFlowInfoVector->clear();
	
	return 0;
}

int expireAll(t_flowInfoVector *flowInfoVector, t_flowInfoVector *expiredFlowInfoVector, struct timeval pktTime)
{
	t_flowInfoVector::iterator iterator = flowInfoVector->begin();

	//save the end of connection and expire all of the processsing flows
	while (iterator != flowInfoVector->end())
	{	
		(*iterator)->endTime.tv_sec = pktTime.tv_sec;
		(*iterator)->endTime.tv_usec = pktTime.tv_usec;
		expiredFlowInfoVector->push_back(*iterator);
		flowInfoVector->erase(iterator);
	}
	
	return 0;
}

double timeInSeconds(struct timeval t)
{
	double tmp;
	tmp = (double) t.tv_usec/1000000;
	tmp = (double) tmp + t.tv_sec;

	return tmp;
}

void expireOldestUnactive(t_flowInfoVector *flowInfoVector, t_flowInfoVector *expiredFlowInfoVector, struct timeval pktTime)
{
	if (flowInfoVector->size() > 0)
	{
		//auxilliary variable storing the oldest time of connection in cache
		double oldstTime;

		oldstTime = timeInSeconds(pktTime);

		//auxilliary iterator for storing the oldest flow 
		t_flowInfoVector::iterator iteratorOldst;
		
		for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ++iterator) 
		{
			//comes through all flows in cache and tries to find the oldest connection
			if (timeInSeconds((*iterator)->lstPktTime) < oldstTime) 
			{
				//the founded flow has less seconds (=is older) -> rewrite temporary oldest
				oldstTime = timeInSeconds((*iterator)->lstPktTime);
				iteratorOldst = iterator;
			}

		}
		if (DEBUG)
			SOUT << "\tExpiring the odest one (time - " << std::fixed << oldstTime << "): " << inet_ntoa((*iteratorOldst)->srcAddr) << ":" << (*iteratorOldst)->srcPort << " --> " << inet_ntoa((*iteratorOldst)->dstAddr) << ":" << (*iteratorOldst)->dstPort << "\n\tbefore: expired: " << expiredFlowInfoVector->size() << "  cache: " << flowInfoVector->size();
		
		//expiring this flow
		(*iteratorOldst)->endTime.tv_sec = pktTime.tv_sec;
		(*iteratorOldst)->endTime.tv_usec = pktTime.tv_usec;
		//moves the oldes flow to expired 
		expiredFlowInfoVector->push_back(*iteratorOldst);
		//removes this flow from cache
		flowInfoVector->erase(iteratorOldst);

		if (DEBUG)
			SOUT << "\tafter: expired: " << expiredFlowInfoVector->size() << "  cache: " << flowInfoVector->size() << std::endl;
	}
}

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}


std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
}
