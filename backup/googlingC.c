#define WIN32
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

#include <stdio.h>
#include <pcap\pcap.h>
#include <pcap.h>
#include <string.h>
#include "googlingH.h"

#define INPUT
#define OUTPUT

typedef struct _PACKET
{
	const unsigned char* NProtocol;					/* Next Protocol  */
	
	void* (*Layer1)(INPUT const void*);
	void* (*Layer2)(INPUT const void*);
	void (*Layer3)(INPUT const void*);
}Packet;

void PrintHexAscii(const unsigned char*, unsigned int);
void* Layer2_Ether(INPUT const void* vP);
void Layer3_IP(INPUT const void*);
void Layer3_ARP(INPUT const void*);
void Layer3_RARP(INPUT const void*);
void Layer3_PUP(INPUT const void*);


int main(void)
{
	char 				errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t			*alldevs;
	pcap_if_t			*d;
	pcap_t*				pDes;
	struct pcap_pkthdr	stPInfo;
	Packet				stData;			/* Packet Information  */
	const u_char*		ucData;
	int 				iDataLink;
	unsigned int 		iCnt=0;
	unsigned int		inum;
	int					res;

	memset(&stData, 0, sizeof(stData));

	/* 패킷해더 구조체를 초기화 하지 않으면 쓰레기값이 찍힐수 있음 */
	memset(&stPInfo, 0, sizeof(stPInfo));	

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

	/* Print the list */
	for(d=alldevs; d; d=d->next)
    {
        printf("%d. ", ++iCnt);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description ava2ilable)\n");
    }
	if(iCnt==0)
    {
        printf("Error : [%s]\n", errbuf);
		return 100;
    }

	printf("Enter the interface number (1-%d):",iCnt);
    scanf_s("%d", &inum);

	if(inum < 1 || inum > iCnt)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

	/* Jump to the selected adapter */
    for(d=alldevs, iCnt=0; iCnt< inum-1 ;d=d->next, iCnt++);
    
    /* Open the device */
	pDes = pcap_open_live(d->name		/*name of the device*/
					  ,1514		/* portion of the packet to capture*/
								/* 65536 guarantees that the whole packet will be captured on all the link layers*/
					  ,NULL	/* promiscuous mode*/
					  ,1000							/* read timeout*/
					  ,errbuf						/* error buffer*/
                       );
	if(NULL == pDes)
	{
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
       return -1;
    } 
	else
	{
		iDataLink = pcap_datalink(pDes);
	}
	
	if(DLT_EN10MB == iDataLink)
	{
		printf("2Layer Type : [Ethernet 10Mb]\n");
		stData.Layer2 = Layer2_Ether;		/* Regist Layer2 Proccessor */
	}
	else
	{
		printf("2Layer Type : Not Ethernet Type......\n");
		return 0;
	}
    
    printf("\nlistening on %s...\n", d->description);

	do
	{
		ucData = pcap_next(pDes, &stPInfo);
		printf("Cap Length : [%d]\n", stPInfo.caplen);	// 캡쳐한 패킷 길이
		printf("Length : [%d]\n", stPInfo.len);	// 캡쳐한 패킷의 실제 길이

		if(300 > stPInfo.caplen)
		{
			continue;
		}

		PrintHexAscii(ucData, stPInfo.caplen);
		stData.NProtocol = ucData;
		stData.Layer2(&stData);

	}while(stPInfo.caplen<1500);

	if(0 != stData.Layer3)
	{
		stData.Layer3(&stData);
	}
	printf("\n");

	pcap_freealldevs(alldevs);
	pcap_close(pDes);
	return 0;
}
void* Layer2_Ether(INPUT const void* vP)
/* vP : (Old)Ether Frame Start Address
 * 		(Now)Packet struct Start Address
 * Retrun Value : Next Protocol Address
 */
{
	struct ether_header* ehP;
	ehP	= (struct ether_header*)( ((Packet*)vP)->NProtocol );
	((Packet*)vP)->NProtocol = (const unsigned char*)(ehP + 1); /* Next Protocol Address */

	printf("\n"
		   "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n");
	printf("┃                            Ethernet Infomation                           ┃\n");
	printf("┣━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┫\n");
	printf("┃[Source] -> [Destination]       ┃%02X-%02X-%02X-%02X-%02X-%02X -> ",	
		   ehP->ether_shost[0],
		   ehP->ether_shost[1],
		   ehP->ether_shost[2],
		   ehP->ether_shost[3],
		   ehP->ether_shost[4],
		   ehP->ether_shost[5]);
	printf("%02X-%02X-%02X-%02X-%02X-%02X  ┃\n",
		   ehP->ether_dhost[0],
		   ehP->ether_dhost[1],
		   ehP->ether_dhost[2],
		   ehP->ether_dhost[3],
		   ehP->ether_dhost[4],
		   ehP->ether_dhost[5]);
	
	switch(ntohs(ehP->ether_type))
	{
		case ETHERTYPE_IP:
			((Packet*)vP)->Layer3 = Layer3_IP;
			printf("┃[Next Protocol]                 ┃[IP (Internet Protocol)]                ┃\n");
			break;
		case ETHERTYPE_ARP:
			((Packet*)vP)->Layer3 = Layer3_ARP;
			printf("┃[Next Protocol]                 ┃[ARP (Address Resolusion Protocol)]     ┃\n");
			break;
		case ETHERTYPE_REVARP:
			((Packet*)vP)->Layer3 = Layer3_RARP;
			printf("┃[Next Protocol]                 ┃[Revers ARP]                            ┃\n");
			break;
		case ETHERTYPE_PUP:
			((Packet*)vP)->Layer3 = Layer3_PUP;
			printf("┃[Next Protocol]                 ┃[Xeros Pup]                             ┃\n");
			break;
		default:
			printf("┃[Next Protocol]                 ┃[Not Support Protocol]                  ┃\n");
			break;
		
	}
	printf("┗━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━┛\n");
	
	return (ehP + 1); // Next Protocal Address
}

void Layer3_IP(INPUT const void* vP)
/* vP : Packet Struct Start Address
 */
{
	struct ip_header* ihP
			= (struct ip_header*)( ((Packet*)vP)->NProtocol );
	unsigned char *temp = (unsigned char *)(&(ihP->ip_src));

	printf("\n"
		   "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n");
	printf("┃                               IP Infomation                              ┃\n");
	printf("┣━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┫\n");
	printf("┃ [출발] -> [도착]      ┃%15s -> ", inet_ntoa(ihP->ip_src));
	printf("%-15s      ┃\n",inet_ntoa(ihP->ip_dst));
	printf("┣━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━┫\n");
	printf("┃ [버전]               ┃ IpV%d                                   ┃\n", ihP->ip_v);
	printf("┃ [헤더길이]                ┃ %2d Octets                              ┃\n", ihP->ip_hl*4);
	printf("┃ [서비스 타입]             ┃ ");
	switch(IPTOS_TOS(ihP->ip_tos))
	{
		case IPTOS_LOWDELAY:
			printf("Low Delay (0x10)                       ┃\n");
			break;
		case IPTOS_THROUGHPUT:
			printf("Through Put (0x08)                     ┃\n");
			break;
		case IPTOS_RELIABILITY:
			printf("Reli Ability (0x04)                    ┃\n");
			break;
		case IPTOS_LOWCOST:
			printf("Low Cost (0x02)                        ┃\n");
			break;
		case 0:
			printf("Default (0)                            ┃\n");
			break;
		default:
			printf("Unknown                                ┃\n");
	}
	printf("┃ [총 패킷 길이]          ┃ %-4d Octets                            ┃\n", ntohs(ihP->ip_len));
	printf("┃ [id]               ┃ 0x%04X                                 ┃\n", ntohs(ihP->ip_id));
	printf("┃ [Reserved Fragment Flag]       ┃ %X                                      ┃\n", (ntohs(ihP->ip_off)&IP_RF)>>15);
	printf("┃ [Don't Fragments Flag]         ┃ %X                                      ┃\n", (ntohs(ihP->ip_off)&IP_DF)>>14);
	printf("┃ [More Fragments Flag]          ┃ %X                                      ┃\n", (ntohs(ihP->ip_off)&IP_MF)>>13);
	printf("┃ [Fragments Offset Field]       ┃ 0x%04X                                 ┃\n", ntohs(ihP->ip_off)&IP_OFFMASK);
	printf("┃ [TTL]                 ┃ %-3d                                    ┃\n", ihP->ip_ttl);
	printf("┃ [프로토콜]                   ┃ ");
	switch(ihP->ip_p)
	{
		case IPPROTO_ICMP:
			printf("Internet Control Message               ┃\n");
			break;
		case IPPROTO_IGMP:
			printf("Internet Group Management              ┃\n");
			break;
		case IPPROTO_TCP:
			printf("Transmission Control(TCP)              ┃\n");
			break;
		case IPPROTO_PUP:
			printf("PUP                                    ┃\n");
			break;
		case IPPROTO_UDP:
			printf("User Datagram (UDP)                    ┃\n");
			break;
		case IPPROTO_IDP:
			printf("XNS IDP                                ┃\n");
			break;
		case IPPROTO_PIM:
			printf("Independent Multicast                  ┃\n");
			break;
		case IPPROTO_RAW:
			printf("Raw IP Packets                         ┃\n");
			break;
		default:
			printf("Unknown                                ┃\n");
	}
	printf("┃ [Header Checksum]              ┃ 0x%04X                                 ┃\n", ntohs(ihP->ip_sum));
	
	printf("┗━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━┛\n");
}

void Layer3_ARP(INPUT const void* vP)
/* vP : Packet 
 */
{
	
}

void Layer3_RARP(INPUT const void* vP)
/* vP : Packet 
 */
{
	
}

void Layer3_PUP(INPUT const void* vP)
/* vP : Packet 
 */
{
	
}

void PrintHexAscii(const unsigned char* buffer, unsigned int Psize)
{
	int iCnt, iCnt2;
	
	printf("addr   ");
	for(iCnt2=0 ; iCnt2<16 ; ++iCnt2)
	{
		printf("%02X ", iCnt2);
	}
	printf("   ");
	for(iCnt2=0 ; iCnt2<16 ; ++iCnt2)
	{
		printf("%X", iCnt2);
	}
	printf("\n");
	printf("==========================================================================\n");
	for(iCnt = 0 ; iCnt < Psize+(16-(Psize%16)) ; ++iCnt)
	{
		if(0==(iCnt%16))
		{
			printf("0x%02X0  ", iCnt/16);
		}
		printf("%02X ", *(buffer+iCnt));
		if(15 == iCnt%16)
		{
			printf("   ");
			for(iCnt2=iCnt-16 ; iCnt2<iCnt ; ++iCnt2)
			{
			  if((*(buffer+iCnt2)<33)||(*(buffer+iCnt2)>127))
			  {
				  printf(".");
			  }
			  else
			  {
				  printf("%c", *(buffer+iCnt2));
			  }
			}
			printf("\n");
		}
	}	
}