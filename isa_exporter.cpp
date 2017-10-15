/*
*	File: isa_exporter.cpp
*	Offline netflow probe, project into Network Applications and Network Administration (ISA)
* 	Author: Anna Popková
*	Other files: isa_exporter.h packets.h 
*/

#include "isa_exporter.h"
#include "packets.h"

// number of flows seen since isa_exporter was executed
u_int32_t flowSequence;

// time of the first packet arrival (SysUptime for us)
double firstPktArr;


int main(int argc, char **argv)
{
	t_params 			params; 		//structure contains all the user parameters
	const u_char 		*packet;		//pointer to current packet data, NULL if EOF or other mistake
	double 				*intervalBgn; 	//variable for store the beggining of the interval after what the expired flows will be exported
	struct timeval 		pktTime;		//structure for store the current time (time of the processing packet for us)
	struct pcap_pkthdr 	pktHdr;			//there will be sored the header of the processing packet
	pcap_t 				*pcapHandle;	//pcap file handler
	char 				errbuf[1000];	//buffer for errors
	short 				retValue;

	signal(SIGINT, &sigHandler);		//catch when somebody push ctrl+c 

 	intervalBgn = new double;
 	struct ether_header *etherPtr;
	//int ether_offset = 0;

	flowSequence = 0;

	//packet counters
	int udps = 0; int tcps = 0; int icmps = 0; int igmps = 0; int arps = 0; int others = 0;
	//bytes counters
	int udpsb = 0;int tcpsb = 0; int icmpsb = 0; int igmpsb = 0; int arpsb = 0; int othersb = 0;

	
	t_flowInfoVector *flowInfoVector;			//pointer to the vector of flows in cache
	t_flowInfoVector *expiredFlowInfoVector;	//pointer to the vector of expired flows
	
	//alocation of the vectors
	flowInfoVector 			= new t_flowInfoVector;
	expiredFlowInfoVector 	= new t_flowInfoVector;

	setDefaultsParams(&params);
	
	//check if user specified some parameters and change these values if he did
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

	bool isFirstPkt = true;	//aux variable for identify the first packet in pcap file - we need its time to store

	//main cycle for processing packets from the file - cycle until EOF
	while ((packet = pcap_next(pcapHandle, &pktHdr)) != NULL)
	{
		//store the timestamp of current packet
		pktTime.tv_sec 	= pktHdr.ts.tv_sec;
		pktTime.tv_usec = pktHdr.ts.tv_usec;

		//check if it is first packet 
		if (isFirstPkt)
		{
			*intervalBgn 	= timeInSeconds(pktHdr.ts); // --> it will be the beginning of the interval after that the expired flows will be exported
			firstPktArr 	= timeInSeconds(pktHdr.ts); // --> save our SysUptime
			isFirstPkt 		= false;
		}
		
		if (DEBUG)
			SOUT << "\n\nPacket no. " << tcps + udps + icmps + igmps + 1 << std::endl;
		if (MORE_DEBUG)
		{
			SOUT << "\tCHECKING THE INTERVAL TO EXPORT:";
			SOUT << "  pktTime:" << std::fixed << timeInSeconds(pktTime) << "  -  intervalBgn:" << std::fixed << *intervalBgn << " (" << std::fixed << timeInSeconds(pktTime) - *intervalBgn << ")  >=  " << "params.intervalToExport:" << params.intervalToExport << std::endl;
		}

		//checks the interval to export the expired flows 
		if ((timeInSeconds(pktTime) - *intervalBgn) >= params.intervalToExport)
		{
			if (DEBUG)
			{
				SOUT << "\t --> Interval to export reached!" 
					 << "\tExporting expired flows!" << std::endl;
			}

			if ((exportExpired(expiredFlowInfoVector, pktTime, intervalBgn, params)) != 0)
			{
				SERR << "Error occured while exporting on collector." << std::endl;
				return 1;
			}

		}

		//checks timeout of unactive TCP connection
		for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ) 
		{
			if (MORE_DEBUG)
			{
				SOUT << "\tCHECKING THE TIMEOUT TO EXPIRATION:";
				SOUT << "\tpktTime:" << std::fixed << timeInSeconds(pktTime) << "  -  (*iterator)->lstPktTime:" << std::fixed << timeInSeconds((*iterator)->lstPktTime) << " (" << std::fixed << (timeInSeconds(pktTime) - timeInSeconds((*iterator)->lstPktTime)) << ")  >=  params.intervalToExpire:" << params.intervalToExpire << std::endl;
			}

			if ((*iterator)->proto == TCP_PROTO && ( (timeInSeconds(pktTime) - timeInSeconds((*iterator)->lstPktTime) ) >= params.intervalToExpire ))
			{
				//this flow has to be expired - because tcp connection is inactive for time longer than intervalToExpire
				if (DEBUG)
					SOUT << "\t --> Inactive timeout reached!" << std::endl;
				
				//expiring this flow
				(*iterator)->endTime.tv_sec 	= pktTime.tv_sec;	//sets the time of end of connection
				(*iterator)->endTime.tv_usec 	= pktTime.tv_usec;
				expiredFlowInfoVector->push_back(*iterator);
				flowInfoVector->erase(iterator); 					//iterator increments automaticaly
			}
			else
				++iterator;
		}
		
		etherPtr = (struct ether_header *) packet;

		if (DEBUG)
			SOUT << "\tReceived packet time (seconds):" << pktTime.tv_sec << " \t(microseconds):" << pktTime.tv_usec << std::endl;

		//check if its IP packet - the others will be ignored
		if (ntohs(etherPtr->ether_type) == ETHERTYPE_IP)         
		{
			struct ip *myIP;	//structure for the IP packet
			myIP = (struct ip*) (packet+ETH_HEADER);

			//what kind of protocol the current packet is?
			switch(myIP->ip_p)
			{	
				case TCP_PROTO: tcps++; tcpsb += pktHdr.len; //increment counter of tcp packets and bytes sended in its
				retValue = processTCP(packet, flowInfoVector, expiredFlowInfoVector, myIP, pktTime, pktHdr.len, params);
				break; 
				case UDP_PROTO: udps++; udpsb += pktHdr.len; //increment counter of udp packets and bytes sended in its
				retValue = processUDPorICMPorIGMP(packet, expiredFlowInfoVector, myIP, pktTime, pktHdr.len);
				break;
				case ICMP_PROTO: icmps++; icmpsb += pktHdr.len;
				retValue = processUDPorICMPorIGMP(packet, expiredFlowInfoVector, myIP, pktTime, pktHdr.len);
				break;
				case IGMP_PROTO: igmps++; igmpsb += pktHdr.len;
				retValue = processUDPorICMPorIGMP(packet, expiredFlowInfoVector, myIP, pktTime, pktHdr.len);
				break; 
				default:
					retValue = 2; 
			}

			if (retValue != 0)
			{				
				if (retValue == 1)
					SERR << "Error while proccesing TCP/UDP/ICMP/IGMP packet." << std::endl;
				if (retValue == 2)
					SERR << "Error while proccesing Unknown packet." << std::endl;
				return 1;
			}
		}

		else  if (ntohs(etherPtr->ether_type) == ETHERTYPE_ARP) // ARP packet
			arps++;
		else
			others++;
	}
	
	if (DEBUG)
	{
		SOUT << "Number of expired flows: " << expiredFlowInfoVector->size() << std::endl;
		SOUT << "Number of flows in cache: " << flowInfoVector->size() << std::endl;
		SOUT << "End of file reached..." << std::endl;
	}

	// EOF --> expires the rest of the flows which are in cache
	expireAll(flowInfoVector, expiredFlowInfoVector, pktTime);

	// exports the rest of the expired flows into collector
	if ((exportExpired(expiredFlowInfoVector, pktTime, intervalBgn, params)) != 0)
	{
		SERR << "Error occured while exporting." << std::endl;
		return 1;
	}

	SERR << "== STATISTICS ==" << std::endl;
	SERR << "Total flows: " << flowSequence << std::endl;
	SERR << "TCP \tpackets: " << tcps << ",\tbytes: " << tcpsb << std::endl;
	SERR << "UDP \tpackets: " << udps << ",\tbytes: " << udpsb << std::endl;
	SERR << "ICMP \tpackets: " << icmps << ",\tbytes: " << icmpsb << std::endl;
	SERR << "IGMP \tpackets: " << igmps << ",\tbytes: " << igmpsb << std::endl;
	SERR << "ARP \tpackets: " << arps << ",\tbytes: " << arpsb << std::endl;
	SERR << "OTHER \tpackets: " << others << ",\tbytes: " << othersb << std::endl;
	SERR << "total \tpackets: " << tcps + udps + icmps + igmps << ",\tbytes: " << 
	tcpsb + udpsb + icmpsb + igmpsb << std::endl;
	
	SERR << "== END OF STATISTICS ==" << std::endl;

	pcap_close(pcapHandle);

	return(0);
}


/*
* Funcion for setting the default parametres - all of them are optional
* @param ptrParams structure with the paramaters which will be inicialized
*/
void setDefaultsParams(t_params *ptrParams)
{
	ptrParams->inFile 			= "-";	//stdin
	ptrParams->collectorPort 	= 2055;
	ptrParams->intervalToExport = 300; 	//after this interval all the expired flows will be exported into collector - in seconds
	ptrParams->maxFlows 		= 50; 	//max amount of flows in this program cache
	ptrParams->intervalToExpire = 300; 	//unactive timeout for TCP connection
	inet_aton("127.0.0.1", &(ptrParams->collectorAddr));
}

/*
* Function loads the parameters from user and store them into structure
* parameters which are not specified stay on default values
* @param ptrParams structure with the paramaters which will be changed
*/
int processParams(int argc, char **argv, t_params *ptrParams)
{
	int 	a;			//aux variable for identification of each parameter
	char 	*endPtr;	//aux variable for checking if numeric parameters are specified correctly
	char 	*ptr;		//aux variable for spliting collector address and collector port

	static struct option longOptions[] = 
	{
		{"input", required_argument, 0, 'i'},
		{"collector", required_argument, 0, 'c'},
		{"interval", required_argument, 0, 'I'},
		{"max-flows", required_argument, 0, 'm'},
		{"tcp-timeout", required_argument, 0, 't'}
	};
	
	// processing parameters individualy
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
			    ptr = strtok(optarg, ":");
			    if (ptr)
			    {
			    	//Adress processing
			    	SOUT << "Address processing: " << ptr << std::endl;
			    	if ((inet_aton(ptr, &(ptrParams->collectorAddr))) == 0)
	 				{
	 					SERR << "Invalid collector address."<< std::endl << "Exiting..." << std::endl;
	 					return -1;
					}
			    }
			    ptr = strtok(NULL, ":");
			    if(ptr)
			    {
			    	SOUT << "Port processing: " << ptr << std::endl;
			    	ptrParams->collectorPort = strtol(ptr, &endPtr, 10);
					if (*endPtr != '\0')
					{
						SERR << "Invalid value for collector port." << std::endl << "Exiting..." << std::endl;
						return -1;
					}	
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
* Function creates and allocates space for new flow and stores the main values into it 
* @param pktInfo - five values - src and dst ip address, src and dst ip port, and type of the ip protocol
* @param pktTime - time of the first packet arrival
* @return pointer on the new flow
*/
t_flowInfo *createNewFlow(t_pktInfo pktInfo, struct timeval pktTime)
{

	t_flowInfo *newFlow;
	//allocation of the new flow
	newFlow = new t_flowInfo;

	newFlow->srcAddr.s_addr 	= pktInfo.srcAddr.s_addr;
	newFlow->dstAddr.s_addr 	= pktInfo.dstAddr.s_addr;
	newFlow->srcPort 			= pktInfo.srcPort;
	newFlow->dstPort 			= pktInfo.dstPort;
	newFlow->proto 				= pktInfo.proto;
	newFlow->pktCnt 			= 1;
	newFlow->byteCnt	 		= 0;
	newFlow->lstPktTime.tv_usec	= pktTime.tv_usec;
	newFlow->lstPktTime.tv_sec 	= pktTime.tv_sec;
	newFlow->startTime.tv_usec 	= pktTime.tv_usec;
	newFlow->startTime.tv_sec 	= pktTime.tv_sec;
	newFlow->oneAckToExp 		= false;

	if (pktInfo.proto == UDP_PROTO || pktInfo.proto == ICMP_PROTO || pktInfo.proto == IGMP_PROTO)
	{
		//these ip protocols are expired immediately, their first packet arrival == last packet arrival
		newFlow->endTime.tv_usec	= pktTime.tv_usec;
		newFlow->endTime.tv_sec 	= pktTime.tv_sec;
		newFlow->tcpFlags 			= 0;
	}
	
	flowSequence++;
	
	return newFlow;
}

/*
* Function processing the TCP packet.
* @param *packet - pointer to current packet data - will be casted to the tcp packet
* @param *flowInfoVector - pointer into vector of processing flows (flows in cache)
* @param *expiredFlowInfoVector - pointer into vector of expired flows (waiting for export)
* @param *myIP - pointer into ip packet
* @param pktTime - arrival time of this packet - current time for us
* @param len - len of this packet - in bytes
* @param params - parameters of this program
* @param *intervalBgn - time of the last export into collector
*/
int processTCP(const u_char *packet, t_flowInfoVector *flowInfoVector, t_flowInfoVector *expiredFlowInfoVector, struct ip *myIP, struct timeval pktTime, bpf_u_int32 len, t_params params)
{
	struct tcphdr	*myTCP;			//tcp packet header
	t_flowInfo 		*currentFlow;	//aux pointer - will be point into new flow if it nessesary to create it

	// retype packet to possibility to read information from it
	myTCP = (struct tcphdr*) (packet+ETH_HEADER+(myIP->ip_hl*4));

	//fills the auxillinary variable which store the main five information about this packet with real values
	t_pktInfo pktInfo;
	pktInfo.srcAddr.s_addr 	= myIP->ip_src.s_addr;
	pktInfo.dstAddr.s_addr 	= myIP->ip_dst.s_addr;
	pktInfo.srcPort 		= u_short(myTCP->th_sport);
	pktInfo.dstPort 		= u_short(myTCP->th_dport);
	pktInfo.proto 			= TCP_PROTO;

	//store the flags - RST/FIN will be interested for us
	std::bitset<8> flags 	= myTCP->th_flags;
	
	if (DEBUG)
	{
		SOUT << "\tTCP (" << inet_ntoa(myIP->ip_src) << ":" << u_short(myTCP->th_sport) << " --> "  
			 << inet_ntoa(myIP->ip_dst) << ":" << u_short(myTCP->th_dport) << ") PROTOCOL PROCESSING." << " FLAGS: " << flags << std::endl;	
	}

	bool needNewFlow 		= true;	
	bool expireImmediately 	= false;
		
	for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ++iterator) 
	{
		if (isEqualFlow(pktInfo, *iterator))
		{
			//flow with known information founded - adding packet into existing flow
			if (DEBUG)
				SOUT << "\tThis packet is part of already existing flow!" << std::endl;
			currentFlow = *iterator;
			
			(currentFlow->pktCnt)++;	//inkrements packet and byte counter in this flow
			currentFlow->byteCnt 			+= len;
			currentFlow->lstPktTime.tv_sec 	= pktTime.tv_sec;	//set the last packet time on this packet time
			currentFlow->lstPktTime.tv_usec = pktTime.tv_usec;
			currentFlow->tcpFlags 			|= myTCP->th_flags; 
			
			needNewFlow = false;
			break;
		}
	}
	//checks the flags
	if (flags.test(0))
	{
		//FIN flag founded --> this connection will be closed from one side	after ACK flag will be sent
		if(!needNewFlow) //if needNewFlow --> it was expired yet, does not waiting for ack
			currentFlow->oneAckToExp = true;
		if (DEBUG)
			SOUT << "\tFIN flag found. " << std::endl;
	}
	if (flags.test(2))
	{
		//RST flag founded --> immediately reset this connection - both sides
		if (needNewFlow)
			expireImmediately = true; //this packet is alone and will be expired immediately
		if (DEBUG)
			SOUT << "\tRST flag found. " << std::endl;
		for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ++iterator) 
		{
			if (isEqualFlow(pktInfo, *iterator))
			{
				//expiring this flow
				(*iterator)->endTime.tv_sec 	= pktTime.tv_sec;
				(*iterator)->endTime.tv_usec 	= pktTime.tv_usec;
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
		//looking for opposite flow and check if waiting for one ack to expire <-- answer for FIN
		for(t_flowInfoVector::iterator iterator = flowInfoVector->begin(); iterator != flowInfoVector->end(); ++iterator) 
		{
			if (isOppositeFlow(pktInfo, *iterator))
			{
				//opposite flow founded
				if ((*iterator)->oneAckToExp)
				{
					//this opposite flow waiting for ACK and will be expired now
					(*iterator)->endTime.tv_sec 	= pktTime.tv_sec;
					(*iterator)->endTime.tv_usec 	= pktTime.tv_usec;
					expiredFlowInfoVector->push_back(*iterator);
					flowInfoVector->erase(iterator);
					if (DEBUG)
						SOUT << "\tACK flag found after FIN --> Adding opposite flow to expired, erasing from cache..." << std::endl;
					
					//if this flow is already expired and this is only last ACT to end this connection, this packet will create new flow which will be expired immediately
					if (needNewFlow)
						expireImmediately = true;
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
					 << "\tExpiring the oldest inactive flow!" << std::endl;
			}
			expireOldestUnactive(flowInfoVector, expiredFlowInfoVector, pktTime);
		}
		//this packet will be the firts in new flow, we have to created the new flow and save important information about this packet/flow
		currentFlow 			= createNewFlow(pktInfo, pktTime);
		currentFlow->tcpFlags 	= myTCP->th_flags;
		currentFlow->ToS 		= myIP->ip_tos;
		currentFlow->byteCnt 	+= len;

		if (expireImmediately) //new flow goes ti expired
		{
			currentFlow->endTime.tv_usec = pktTime.tv_usec;
			currentFlow->endTime.tv_sec = pktTime.tv_sec;
			expiredFlowInfoVector->push_back(currentFlow);
		}
		else //new flow goes to processing flows (cache)
			flowInfoVector->push_back(currentFlow);

		if (DEBUG)
		{
			SOUT << "\tNew flow added: "<< inet_ntoa(currentFlow->srcAddr) << ":" << currentFlow->srcPort << " --> "  
			 << inet_ntoa(currentFlow->dstAddr) << ":" << currentFlow->dstPort << " Flows in cache now: " << flowInfoVector->size() << " Expired flows: " << expiredFlowInfoVector->size() << std::endl;
		}
	}

	return 0;
}

/*
* Function processing the UDP packet.
* @param *packet - pointer to current packet data - will be casted to the udp packet
* @param *flowInfoVector - pointer into vector of processing flows (flows in cache)
* @param *expiredFlowInfoVector - pointer into vector of expired flows (waiting for export)
* @param *myIP - pointer into ip packet
* @param pktTime - arrival time of this packet - current time for us
* @param len - len of this packet - in bytes
* @param params - parameters of this program
* @param *intervalBgn - time of the last export into collector
*/
int processUDPorICMPorIGMP(const u_char *packet, t_flowInfoVector *expiredFlowInfoVector, struct ip *myIP, struct timeval pktTime, bpf_u_int32 len)
{
	t_flowInfo 		*currentFlow; 		//aux pointer of the flow which this packet will be part of
	struct udphdr 	*myUDPorICMPorIGMP;	//packet header
	t_pktInfo 		pktInfo;

	//fills the auxillinary variable which store the main five information about this packet with real values
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

	//not nessesary to check if cache is full --> UDP packet goes immediately into expired flows
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

	currentFlow 			= createNewFlow(pktInfo, pktTime);
	currentFlow->ToS 		= myIP->ip_tos;
	currentFlow->byteCnt 	+= len;

	//adds this udp flow into expired flows
	expiredFlowInfoVector->push_back(currentFlow);

	return 0;
}

/*
* Function compares flows given as @param flow with the @param pktInfo 
* @return 1 if searching is successful, 0 if not
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

/*
* Function takes the vector of the expired flows (@param *expiredFlowInfoVector is pointer to this vector), makes packets from them and sends them into collector
* an restarts time of the beginning of the new interval after that next export will come (@param *intervalBgn) into current time (@param pktTime) after that
* @param params - parameters of this program
* @return 0 if all goes right, -1 if not
*/
int exportExpired(t_flowInfoVector *expiredFlowInfoVector, struct timeval pktTime, double *intervalBgn, t_params params)
{
	//1. creates packets for exporting to the collector
	u_short 	pktCnt; 					// <--- how many packets do will need? 
	double 		devBootTimeD = firstPktArr; //aux
	double 		sysuptimeD; 				//aux variable for storing the time of this program runs
	fourBytes 	sysuptime;					//the same but in unsigned int - will be converted into it
	u_short 	flowsCnt;					//aux variable for counting the flows in current packet - cannot reach MAX_FLOWS_IN_PACKET (=30)
	
	t_flowInfoVector::iterator lastIterator = expiredFlowInfoVector->begin();	//pointer on last exported flow will be stored here - not all flows could be exported in one packet
	
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
	int 				skt;	//socket
	struct sockaddr_in 	saddr; 	//server address
	
	if ((skt = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	{
		SERR << "Failed when creating packet." << std::endl;
		return -1;
	}
	
	memset(&saddr, 0, sizeof(saddr));
	
	saddr.sin_family	= AF_INET;
	saddr.sin_port 		= htons(params.collectorPort);
	saddr.sin_addr 		= params.collectorAddr;
	
	t_nfPkt *newPkt;	//pointer on packet which will be filled by expired flows
	
	//makes new packet in every cycle and sends it to collector
	for (;pktCnt;pktCnt--)
	{
		newPkt 		= new t_nfPkt;	//makes new packet
		flowsCnt 	= 0;

		// comes through expired flows and adds into this packet
		for(t_flowInfoVector::iterator iterator = lastIterator; iterator != expiredFlowInfoVector->end(); ++iterator) 
		{
			lastIterator 	= iterator + 1; //saves pointer into next flow (in the possibility of reaching MAX_FLOWS_IN_PACKET) --> newt packet will continue from newt flow
			
			//aux variables - this doubles will be converted into unsigned ints
			double firstD 	= ((timeInSeconds((*iterator)->startTime)) - devBootTimeD) * 1000;
			double lastD 	= ((timeInSeconds((*iterator)->endTime)) - devBootTimeD) * 1000; 	//*1000 because seconds to miliseconds		
			sysuptimeD		= (timeInSeconds(pktTime) - devBootTimeD) * 1000;
			
			//converting into unsigned int and rounding 
			fourBytes first = round(firstD);
			fourBytes last 	= round(lastD);
			sysuptime 		= round(sysuptimeD);
			
			//save all of the important information for netflow datagram version 5
			//values for netflow data record:
			inet_aton("0.0.0.0", &(newPkt->rec[flowsCnt].nexthop)); 	//unconflict value	
			newPkt->rec[flowsCnt].srcaddr 	= (*iterator)->srcAddr;
			newPkt->rec[flowsCnt].dstaddr 	= (*iterator)->dstAddr;
			newPkt->rec[flowsCnt].dPkts 	= htonl((*iterator)->pktCnt);
			newPkt->rec[flowsCnt].dOctets 	= htonl((*iterator)->byteCnt); 
			newPkt->rec[flowsCnt].First 	= htonl(first);
			newPkt->rec[flowsCnt].Last 		= htonl(last);
			newPkt->rec[flowsCnt].srcport 	= (*iterator)->srcPort;
			newPkt->rec[flowsCnt].dstport 	= (*iterator)->dstPort;
			newPkt->rec[flowsCnt].tcp_flags = (*iterator)->tcpFlags;
			newPkt->rec[flowsCnt].prot 		= (*iterator)->proto;
			newPkt->rec[flowsCnt].ToS 		= (*iterator)->ToS;

			
			if (MORE_DEBUG)
			{
				std::bitset<8> flags = newPkt->rec[flowsCnt].tcp_flags;
				SOUT << "Cummulative OR of packets in this flow:" << flags << std::endl;
				SOUT << inet_ntoa(newPkt->rec[flowsCnt].srcaddr) << " : " << std::endl;
				SOUT << inet_ntoa(newPkt->rec[flowsCnt].dstaddr) << " : " << std::endl;
				SOUT << inet_ntoa(newPkt->rec[flowsCnt].nexthop) << " : " << std::endl;
				SOUT << newPkt->rec[flowsCnt].input << " : " << newPkt->rec[flowsCnt].output << " : " << newPkt->rec[flowsCnt].dPkts << " : " << newPkt->rec[flowsCnt].dOctets << " : " << newPkt->rec[flowsCnt].First << " (" << firstD << ") : " << newPkt->rec[flowsCnt].Last << " ("  << lastD << ") : " << newPkt->rec[flowsCnt].srcport << " : " << newPkt->rec[flowsCnt].dstport << " : " << newPkt->rec[flowsCnt].pad1 << " : " << newPkt->rec[flowsCnt].tcp_flags << " : " << newPkt->rec[flowsCnt].prot <<  " : " << newPkt->rec[flowsCnt].ToS << " : " << newPkt->rec[flowsCnt].src_as << " : " << newPkt->rec[flowsCnt].dst_as << " : " << newPkt->rec[flowsCnt].src_mask << " : " << newPkt->rec[flowsCnt].dst_mask << " : " << newPkt->rec[flowsCnt].pad2 <<  std::endl;
			}
				
			flowsCnt++;				
			if (flowsCnt >= MAX_FLOWS_IN_PACKET) //newt flows will be in another packet --> let's send this packet
				break;
			
		}
		
		//values for netflow header:
		newPkt->hdr.count = htons(flowsCnt);
		newPkt->hdr.SysUptime = htonl(sysuptime);
		newPkt->hdr.unix_secs = htonl(pktTime.tv_sec);
		newPkt->hdr.unix_nsecs = htonl(pktTime.tv_usec);
		
		newPkt->hdr.version = htons(5);
		newPkt->hdr.flow_sequence = htonl(flowSequence);
			
		// packet is ready to send
		if (MORE_DEBUG)
		{
			SOUT << "Packet is ready to be sent (with " << flowsCnt << " flows), total size: " << sizeof(*newPkt) << ", header size: " << sizeof(newPkt->hdr) << ". \nHeader: " <<  std::endl;
			SOUT <<  newPkt->hdr.version << " : " << newPkt->hdr.count << " : " << newPkt->hdr.SysUptime << " ("  << sysuptimeD << ") : " << newPkt->hdr.unix_secs << " : " << newPkt->hdr.unix_nsecs << " : " << newPkt->hdr.flow_sequence << " : " << newPkt->hdr.engine_type << " : " << newPkt->hdr.engine_id << " : " << newPkt->hdr.sampling_interval << std::endl;
		}
			
		//sends this packet
		if ((sendto(skt, newPkt, sizeof(t_nfV5hdr) + flowsCnt * sizeof(t_nfV5flowRec), 0, (const sockaddr *)&saddr, sizeof(saddr))) == -1)
		{
			SERR << "Error occured while sending packet to collector." << std::endl;
			return -1;
		}
		
		if (MORE_DEBUG)
			SOUT << "Packet sent successfuly!" << std::endl;
		
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

/*
* Function expires all the packet which are in cache - used when EOF reached
* @param *flowInfoVector - pointer into vector of processing flows (flows in cache) <-- will be removed
* @param *expiredFlowInfoVector - pointer into vector of expired flows (waiting for export) <-- will be filled by the flows in cache
* @param pkTime - time of expiration - will be stored into information about last packet arrival in all flows which will be expired
*/
void expireAll(t_flowInfoVector *flowInfoVector, t_flowInfoVector *expiredFlowInfoVector, struct timeval pktTime)
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
	return;
}

/*
* Function for get time in seconds in double value
* @param t - time structure contains seconds and microseconds - this value will be converted into seconds
* @return time in seconds in double precision
*/
double timeInSeconds(struct timeval t)
{
	double tmp;
	tmp = (double) t.tv_usec/1000000;
	tmp = (double) tmp + t.tv_sec;

	return tmp;
}

/*
* Function finds and expires the oldest inactive flow from the flows which are in cache
* @param *flowInfoVector - pointer into vector of processing flows (flows in cache) <-- we are looking for the oldest unactive flow here
* @param *expiredFlowInfoVector - pointer into vector of expired flows (waiting for export) <-- the longest inactive flow will be removed here
* @param pkTime - time of expiration - will be stored into information about last packet arrival in the flow which will be expired
*/
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
			if (timeInSeconds((*iterator)->lstPktTime) <= oldstTime) 
			{
				//the founded flow has less seconds (=is older) -> rewrite temporary oldest
				oldstTime = timeInSeconds((*iterator)->lstPktTime);
				iteratorOldst = iterator;
			}

		}
		if (DEBUG)
			SOUT << "\tExpiring the oldest one (time - " << std::fixed << oldstTime << "): " << inet_ntoa((*iteratorOldst)->srcAddr) << ":" << (*iteratorOldst)->srcPort << " --> " << inet_ntoa((*iteratorOldst)->dstAddr) << ":" << (*iteratorOldst)->dstPort << "\n\tbefore: expired: " << expiredFlowInfoVector->size() << "  cache: " << flowInfoVector->size();
		
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

/*
* Function handles with ctrl+c signal.	
*/
void sigHandler(int s)
{
	signal(SIGINT, sigHandler);
	SERR << s << ": Invalid termination of this program, some of flows won't be expired and exported to collector." << std::endl;
	exit(1);
}
