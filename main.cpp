



typedef struct params {
	
	const char *inFile;
	in_addr collectorAddr;
	int collectorPort;
	int intervalToExport;
	int maxFlows;
	int intervalToExpire;

} Tparams;

int processPacket(const u_char *packet);
int processParams(int argc, char **argv, Tparams *ptrParams);
void setDefaultsParams(Tparams *ptrParams);


int main(int argc, char **argv)
{
	Tparams params;
	const u_char *packet;

	struct pcap_pkthdr packetHeader;
	/*
	struct timeval 	ts    	...time stamp
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
	int protocol;
	int udps = 0;
	int tcps = 0;
	int icmps = 0;
	int igmps = 0;
	int arps = 0;
	int others = 0;

	setDefaultsParams(&params);
	if ((processParams(argc, argv, &params)) != 0)
	{
		if (DEBUG)
			SOUT << "Processing parameters failed." << std::endl;
		return 1;
	}

	if ((pcapHandle = pcap_open_offline(params.inFile, errbuf)) == NULL)
		SERR << "Cannot open pcap file." << std::endl;

	while ((packet = pcap_next(pcapHandle, &packetHeader)) != NULL)
	{
		if (DEBUG)
			SOUT << "\tLength " << packetHeader.len << " received at " << ctime((const time_t*)&packetHeader.ts.tv_sec) << std::endl;
		etherPtr = (struct ether_header *) packet;                 // read the Ethernet header
		if (DEBUG)
			SOUT << "\tSource MAC: " << ether_ntoa((const struct ether_addr *)&etherPtr->ether_shost) << std::endl;

		if (ntohs(etherPtr->ether_type) == ETHERTYPE_IP)         // IP packet
// IP packet processing
		{
			if (DEBUG)
			{
				SOUT << "\t\tEthernet type packet processing..." << std::endl;
				SOUT << std::hex << "\t\thex: " << ntohs(eptr->ether_type) << std::endl;
				SOUT << "\t\tdec: " << ntohs(eptr->ether_type) << std::endl;
			}

			protocol = processPacket(packet);

			if (DEBUG)
				switch(protocol){	
					case TCP_PROTO: tcps++; break;
					case UDP_PROTO: udps++; break;
					case ICMP_PROTO: icmps++; break;
					case IGMP_PROTO: igmps++; break; }
		}

		else  if (ntohs(etherPtr->ether_type) == ETHERTYPE_ARP) // ARP packet
		{
			if (DEBUG)
			{
				SOUT << "\t\tARP packet processing..." << std::endl;
				arps++;
			}
		}
// ARP packet processing
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
		SOUT << "End of file reached..." << std::endl;
		SOUT << "== STATISTICS ==" << tcps << std::endl;
		SOUT << "TCP packets: " << tcps << std::endl;
		SOUT << "UDP packets: " << udps << std::endl;
		SOUT << "ICMP packets: " << icmps << std::endl;
		SOUT << "IGMP packets: " << igmps << std::endl;
		SOUT << "ARP packets: " << arps << std::endl;
		SOUT << "OTHER packets: " << others << std::endl;
		SOUT << "total packets: " << tcps + udps + icmps + igmps + arps + others << std::endl;
		SOUT << "== END OF STATISTICS ==" << tcps << std::endl;
	}

	pcap_close(pcapHandle);

	return(0);
}


int processPacket(const u_char *packet)
{
	struct ip *myIP;
	struct tcphdr *myTCP;

	myIP = (struct ip*) (packet+ETH_HEADER);

	if (DEBUG)
	{
		SOUT << "\tIP: id " << ntohs(myIP->ip_id) << ", header lenght "<< myIP->ip_hl*4 << "bytes, version " << myIP->ip_v << std::endl;;
		SOUT << "\tIP: type of service: " << u_short(myIP->ip_tos) << std::endl;
		SOUT << "\tIP: total length " << ntohs(myIP->ip_len) << "bytes, TTL " << u_short(myIP->ip_ttl) << std::endl;
		SOUT << "\tIP src = " << inet_ntoa(myIP->ip_src) << std::endl;
		SOUT << "\tIP dst = " << inet_ntoa(myIP->ip_dst) << std::endl;
	}

	switch(myIP->ip_p) 
	{
		case IP_PROTO:
		if (DEBUG)
		{
			SOUT << "\t\tIP protocol processing." << std::endl;
		}
		break;

		case ICMP_PROTO:
		if (DEBUG)
		{
			SOUT << "\t\tICMP protocol processing." << std::endl;
		}
		break;

		case IGMP_PROTO:
		if (DEBUG)
		{
			SOUT << "\t\tIGMP protocol processing." << std::endl;
		}
		break;

		case TCP_PROTO:
		myTCP = (struct tcphdr*) (packet+ETH_HEADER+(myIP->ip_hl*4));
		if (DEBUG)
		{
			SOUT << "\t\tTCP protocol processing." << std::endl;
			SOUT << "\t\tTCP src port: " << u_short(myTCP->th_sport) << std::endl;
			SOUT << "\t\tTCP dst port: " << u_short(myTCP->th_dport) << std::endl;
		}
		break;

		case UDP_PROTO:
		if (DEBUG)
		{
			SOUT << "\t\tUDP protocol processing." << std::endl;
		}
		break;

		default:
		if (DEBUG)
			SOUT << "\t\tUnknown protocol processing." << std::endl;
		return -1;

	}

	return myIP->ip_p;


}

/*
* Funcion for setting the default parametres - all of them are optional
*
* @param ptrParams structure with the paramaters
*/
void setDefaultsParams(Tparams *ptrParams)
{
	ptrParams->inFile = "-";
	inet_aton("127.0.0.1", &(ptrParams->collectorAddr));
	ptrParams->collectorPort = 2055;
	ptrParams->intervalToExport = 300;
	ptrParams->maxFlows = 50;
	ptrParams->intervalToExpire = 300;
}

int processParams(int argc, char **argv, Tparams *ptrParams)
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