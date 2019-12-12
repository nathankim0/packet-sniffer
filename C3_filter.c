#define WIN32
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>
#include <pcap\pcap.h>
#include <pcap.h>
#include <string.h>
#include <WinSock2.h>
#include <stdlib.h>
#define PCAP_SRC_IF_STRING "rpcap://"
//some packet processing functions
void ProcessPacket(u_char*, int); //This will decide how to digest
void print_ethernet_header(u_char*);
void PrintIpHeader(u_char*, int);
void PrintIcmpPacket(u_char*, int);
void print_udp_packet(u_char*, int);
void PrintTcpPacket(u_char*, int);
void PrintData(u_char*, int);
typedef struct ethernet_header
{
	UCHAR dest[6];
	UCHAR source[6];
	USHORT type;
}   ETHER_HDR, * PETHER_HDR, FAR* LPETHER_HDR, ETHERHeader;
//Ip header (v4)
typedef struct ip_hdr
{
	unsigned char ip_header_len : 4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version : 4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id; // Unique identifier
	unsigned char ip_frag_offset : 5; // Fragment offset field
	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;
	unsigned char ip_frag_offset1; //fragment offset
	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source address
} IPV4_HDR;
//UDP header
typedef struct udp_hdr
{
	unsigned short source_port; // Source port no.
	unsigned short dest_port; // Dest. port no.
	unsigned short udp_length; // Udp packet length
	unsigned short udp_checksum; // Udp checksum (optional)
} UDP_HDR;
// TCP header
typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits
	unsigned char ns : 1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1 : 3; //according to rfc
	unsigned char data_offset : 4; /*The number of 32-bit words in the TCP header.
	This indicates where the data begins.
	The length of the TCP header is always a multiple
	of 32 bits.*/
	unsigned char fin : 1; //Finish Flag
	unsigned char syn : 1; //Synchronise Flag
	unsigned char rst : 1; //Reset Flag
	unsigned char psh : 1; //Push Flag
	unsigned char ack : 1; //Acknowledgement Flag
	unsigned char urg : 1; //Urgent Flag
	unsigned char ecn : 1; //ECN-Echo Flag
	unsigned char cwr : 1; //Congestion Window Reduced Flag
	////////////////////////////////
	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;
typedef struct icmp_hdr
{
	BYTE type; // ICMP Error type
	BYTE code; // Type sub code
	USHORT checksum;
	USHORT id;
	USHORT seq;
} ICMP_HDR;
// Restore the byte boundary back to the previous value
//#include <poppack.h>
FILE* logfile;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0, i, j;
struct sockaddr_in source, dest;
char hex[2];
//Its free!
ETHER_HDR* ethhdr;
IPV4_HDR* iphdr;
TCP_HDR* tcpheader;
UDP_HDR* udpheader;
ICMP_HDR* icmpheader;
u_char* data;

u_int sel=6;

int main()
{
	u_int i, res, inum;
	char errbuf[PCAP_ERRBUF_SIZE];
	char buffer[100];
	time_t seconds;
	struct tm tbreak;
	pcap_if_t* alldevs, * d;
	pcap_t* fp;
	struct pcap_pkthdr* header;
	u_char* pkt_data;

	/* The user didn't provide a packet source: Retrieve the local device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		printf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		return -1;
	}
	i = 0;
	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s\n    ", ++i, d->name);
		if (d->description)
		{
			printf(" (%s)\n", d->description);
		}
		else
		{
			printf(" (No description available)\n");
		}
	}
	if (i == 0)
	{
		printf(stderr, "No interfaces found! Exiting.\n");
		return -1;
	}
	printf("Enter the interface number you would like to sniff >> ");
	scanf_s("%d", &inum);

	printf("<필터링>\n");
	printf(" 1. ICMP\n 2. TCP\n 3. UDP\n 4. HTTP\n 5. FTP\n 6. ALL\n");
	printf(" >> ");

	scanf_s("%d", &sel);

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	/* Open the device */
	if ((fp = pcap_open(d->name,
		100 /*snaplen*/,
		PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
		20 /*read timeout*/,
		NULL /* remote authentication */,
		errbuf)
		) == NULL)
	{
		printf(stderr, "\nError opening adapter\n");
		return -1;
	}
	//read packets in a loop :)
	while ((res = pcap_next_ex(fp, &header, (const u_char**)&pkt_data)) >= 0)
	{
		if (res == 0)
		{
			// Timeout elapsed
			continue;
		}
		seconds = header->ts.tv_sec;
		localtime_s(&tbreak, &seconds);
		strftime(buffer, 80, "%d-%b-%Y %I:%M:%S %p", &tbreak);
		//print pkt timestamp and pkt len
		printf("\nNext Packet : %s.%ld (Packet Length : %ld bytes) ", buffer, header->ts.tv_usec, header->len);
		ProcessPacket(pkt_data, header->caplen);
	}
	if (res == -1)
	{
		printf(stderr, "Error reading the packets: %s\n", pcap_geterr(fp));
		return -1;
	}
	return 0;
}
void ProcessPacket(u_char* Buffer, int Size)
{
	
	//Ethernet header
	ethhdr = (ETHER_HDR*)Buffer;
	++total;

	if (ntohs(ethhdr->type) == 0x0800)
	{
		iphdr = (IPV4_HDR*)(Buffer + sizeof(ETHER_HDR));

		switch (sel) {
		case 1:
			if (iphdr->ip_protocol == 1) {
				icmp++;
				PrintIcmpPacket(Buffer, Size);
			}
			break;
		case 2:
			if (iphdr->ip_protocol == 6) {
				tcp++;
				PrintTcpPacket(Buffer, Size);
			}
			break;
		case 3:
			if (iphdr->ip_protocol == 17) {
				udp++;
				print_udp_packet(Buffer, Size);
			}
			break;
		case 4:
			if (iphdr->ip_protocol == 6) {
				tcp++;
				PrintTcpPacket(Buffer, Size);
			}
			break;
		case 5:
		case 6:
			//Ip packets
			if (ntohs(ethhdr->type) == 0x0800)
			{
				//ip header
				iphdr = (IPV4_HDR*)(Buffer + sizeof(ETHER_HDR));
				switch (iphdr->ip_protocol) //Check the Protocol and do accordingly...
				{
				case 1: //ICMP Protocol
					icmp++;
					PrintIcmpPacket(Buffer, Size);
					break;
				case 2: //IGMP Protocol
					igmp++;
					break;
				case 6: //TCP Protocol
					tcp++;
					PrintTcpPacket(Buffer, Size);
					break;
				case 17: //UDP Protocol
					udp++;
					print_udp_packet(Buffer, Size);
					break;
				default: //Some Other Protocol like ARP etc.
					others++;
					break;
				}
			}
			printf("TCP : %d UDP : %d ICMP : %d IGMP : %d Others : %d Total : %d\r", tcp, udp, icmp, igmp, others, total);
		default:
			printf("다시 입력\b");
			break;
		}
	}
}
/*
	Print the Ethernet header
*/
void print_ethernet_header(u_char* buffer)
{
	ETHER_HDR* eth = (ETHER_HDR*)buffer;
	printf("\n");
	printf("Ethernet Header\n");
	printf(" |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->dest[0], eth->dest[1], eth->dest[2], eth->dest[3], eth->dest[4], eth->dest[5]);
	printf(" |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->source[0], eth->source[1], eth->source[2], eth->source[3], eth->source[4], eth->source[5]);
	printf(" |-Protocol            : 0x%.4x \n", ntohs(eth->type));
}
/*
	Print the IP header for IP packets
*/
void PrintIpHeader(unsigned char* Buffer, int Size)
{
	int iphdrlen = 0;
	iphdr = (IPV4_HDR*)(Buffer + sizeof(ETHER_HDR));
	iphdrlen = iphdr->ip_header_len * 4;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;
	print_ethernet_header(Buffer);
	printf("\n");
	printf("IP Header\n");
	printf(" |-IP Version : %d\n", (unsigned int)iphdr->ip_version);
	printf(" |-IP Header Length : %d DWORDS or %d Bytes\n", (unsigned int)iphdr->ip_header_len, ((unsigned int)(iphdr->ip_header_len)) * 4);
	printf(" |-Type Of Service : %d\n", (unsigned int)iphdr->ip_tos);
	printf(" |-IP Total Length : %d Bytes(Size of Packet)\n", ntohs(iphdr->ip_total_length));
	printf(" |-Identification : %d\n", ntohs(iphdr->ip_id));
	printf(" |-Reserved ZERO Field : %d\n", (unsigned int)iphdr->ip_reserved_zero);
	printf(" |-Dont Fragment Field : %d\n", (unsigned int)iphdr->ip_dont_fragment);
	printf(" |-More Fragment Field : %d\n", (unsigned int)iphdr->ip_more_fragment);
	printf(" |-TTL : %d\n", (unsigned int)iphdr->ip_ttl);
	printf(" |-Protocol : %d\n", (unsigned int)iphdr->ip_protocol);
	printf(" |-Checksum : %d\n", ntohs(iphdr->ip_checksum));
	printf(" |-Source IP : %s\n", inet_ntoa(source.sin_addr));
	printf(" |-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
}
/*
	Print the TCP header for TCP packets
*/
void PrintTcpPacket(u_char* Buffer, int Size)
{
	if (sel == 4) {
		if (ntohs(tcpheader->dest_port) != 80 && ntohs(tcpheader->source_port) != 80 && ntohs(tcpheader->dest_port) != 443 && ntohs(tcpheader->source_port) != 443)
			return;
	}

	unsigned short iphdrlen;
	int header_size = 0, tcphdrlen, data_size;
	iphdr = (IPV4_HDR*)(Buffer + sizeof(ETHER_HDR));
	iphdrlen = iphdr->ip_header_len * 4;
	tcpheader = (TCP_HDR*)(Buffer + iphdrlen + sizeof(ETHER_HDR));
	tcphdrlen = tcpheader->data_offset * 4;
	data = (Buffer + sizeof(ETHER_HDR) + iphdrlen + tcphdrlen);
	data_size = (Size - sizeof(ETHER_HDR) - iphdrlen - tcphdrlen);
	if (sel == 4) {
		printf("\n\n***********************HTTP*************************\n");
	}
	else {
		printf("\n\n***********************TCP Packet*************************\n");
	}
	PrintIpHeader(Buffer, Size);
	printf("\n");
	printf("TCP Header\n");
	printf(" |-Source Port : %u\n", ntohs(tcpheader->source_port));
	printf(" |-Destination Port : %u\n", ntohs(tcpheader->dest_port));
	printf(" |-Sequence Number : %u\n", ntohl(tcpheader->sequence));
	printf(" |-Acknowledge Number : %u\n", ntohl(tcpheader->acknowledge));
	printf(" |-Header Length : %d DWORDS or %d BYTES\n", (unsigned int)tcpheader->data_offset, (unsigned int)tcpheader->data_offset * 4);
	printf(" |-CWR Flag : %d\n", (unsigned int)tcpheader->cwr);
	printf(" |-ECN Flag : %d\n", (unsigned int)tcpheader->ecn);
	printf(" |-Urgent Flag : %d\n", (unsigned int)tcpheader->urg);
	printf(" |-Acknowledgement Flag : %d\n", (unsigned int)tcpheader->ack);
	printf(" |-Push Flag : %d\n", (unsigned int)tcpheader->psh);
	printf(" |-Reset Flag : %d\n", (unsigned int)tcpheader->rst);
	printf(" |-Synchronise Flag : %d\n", (unsigned int)tcpheader->syn);
	printf(" |-Finish Flag : %d\n", (unsigned int)tcpheader->fin);
	printf(" |-Window : %d\n", ntohs(tcpheader->window));
	printf(" |-Checksum : %d\n", ntohs(tcpheader->checksum));
	printf(" |-Urgent Pointer : %d\n", tcpheader->urgent_pointer);
	printf("\n");
	printf(" DATA Dump ");
	printf("\n");
	printf("IP Header\n");
	PrintData((u_char*)iphdr, iphdrlen);
	printf("TCP Header\n");
	PrintData((u_char*)tcpheader, tcphdrlen);
	printf("Data Payload\n");
	PrintData(data, data_size);
	printf("\n###########################################################\n");
}
/*
	Print the UDP header for UDP packets
*/
void print_udp_packet(u_char* Buffer, int Size)
{
	int iphdrlen = 0, data_size = 0;
	iphdr = (IPV4_HDR*)(Buffer + sizeof(ETHER_HDR));
	iphdrlen = iphdr->ip_header_len * 4;
	udpheader = (UDP_HDR*)(Buffer + iphdrlen + sizeof(ETHER_HDR));
	data = (Buffer + sizeof(ETHER_HDR) + iphdrlen + sizeof(UDP_HDR));
	data_size = (Size - sizeof(ETHER_HDR) - iphdrlen - sizeof(UDP_HDR));
	printf("\n\n***********************UDP Packet*************************\n");
	PrintIpHeader(Buffer, Size);
	printf("\nUDP Header\n");
	printf(" |-Source Port : %d\n", ntohs(udpheader->source_port));
	printf(" |-Destination Port : %d\n", ntohs(udpheader->dest_port));
	printf(" |-UDP Length : %d\n", ntohs(udpheader->udp_length));
	printf(" |-UDP Checksum : %d\n", ntohs(udpheader->udp_checksum));
	printf("\n");
	printf("IP Header\n");
	PrintData((u_char*)iphdr, iphdrlen);
	printf("UDP Header\n");
	PrintData((u_char*)udpheader, sizeof(UDP_HDR));
	printf("Data Payload\n");
	PrintData(data, data_size);
	printf("\n###########################################################\n");
}
void PrintIcmpPacket(u_char* Buffer, int Size)
{
	int iphdrlen = 0, icmphdrlen = 0, data_size = 0;
	iphdr = (IPV4_HDR*)(Buffer + sizeof(ETHER_HDR));
	iphdrlen = iphdr->ip_header_len * 4;
	icmpheader = (ICMP_HDR*)(Buffer + iphdrlen + sizeof(ETHER_HDR));
	data = (Buffer + sizeof(ETHER_HDR) + iphdrlen + sizeof(ICMP_HDR));
	data_size = (Size - sizeof(ETHER_HDR) - iphdrlen - sizeof(ICMP_HDR));
	printf("\n\n***********************ICMP Packet*************************\n");
	PrintIpHeader(Buffer, Size);
	printf("\n");
	printf("ICMP Header\n");
	printf(" |-Type : %d", (unsigned int)(icmpheader->type));
	if ((unsigned int)(icmpheader->type) == 11)
	{
		printf(" (TTL Expired)\n");
	}
	else if ((unsigned int)(icmpheader->type) == 0)
	{
		printf(" (ICMP Echo Reply)\n");
	}
	printf(" |-Code : %d\n", (unsigned int)(icmpheader->code));
	printf(" |-Checksum : %d\n", ntohs(icmpheader->checksum));
	printf(" |-ID : %d\n", ntohs(icmpheader->id));
	printf(" |-Sequence : %d\n", ntohs(icmpheader->seq));
	printf("\n");
	printf("IP Header\n");
	PrintData((u_char*)iphdr, iphdrlen);
	printf("ICMP Header\n");
	PrintData((u_char*)icmpheader, sizeof(ICMP_HDR));
	printf("Data Payload\n");
	PrintData(data, data_size);
	printf("\n###########################################################\n");
}
/*
	Print the hex values of the data
*/
void PrintData(u_char* data, int Size)
{
	unsigned char a, line[17], c;
	int j;
	//loop over each character and print
	for (i = 0; i < Size; i++)
	{
		c = data[i];
		//Print the hex value for every character , with a space
		printf(" %.2x", (unsigned int)c);
		//Add the character to data line
		a = (c >= 32 && c <= 128) ? (unsigned char)c : '.';
		line[i % 16] = a;
		//if last character of a line , then print the line - 16 characters in 1 line
		if ((i != 0 && (i + 1) % 16 == 0) || i == Size - 1)
		{
			line[i % 16 + 1] = '\0';
			//print a big gap of 10 characters between hex and characters
			printf("          ");
			//Print additional spaces for last lines which might be less than 16 characters in length
			for (j = strlen((const char*)line); j < 16; j++)
			{
				printf("   ");
			}
			printf("%s \n", line);
		}
	}
	printf("\n");
}