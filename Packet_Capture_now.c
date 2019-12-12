#define WIN32
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

#include <stdio.h>
#include <pcap\pcap.h>
#include <pcap.h>
#include <string.h>
#include <WinSock2.h>
#include <stdint.h>

#define IPHEADER 0x0800
#define ARPHEADER 0x0806
#define RARPHEADER 0x0835


typedef struct Ethernet_Header//이더넷 헤더 구조체
{
	u_char des[6];//수신자 MAC 주소
	u_char src[6];//송신자 MAC 주소
	short int ptype;//뒤에 나올 패킷의 프로토콜 종류(예:ARP/IP/RARP)
		 //IP 헤더가 오는 경우 : 0x0800
		 //ARP 헤더가 오는 경우 : 0x0806
		 //RARP 헤더가 오는 경우 : 0x0835
}Ethernet_Header;//부를 이름 선언(별명)

typedef struct ipaddress
{
	u_char ip1;
	u_char ip2;
	u_char ip3;
	u_char ip4;
}ip;

//IP 프로토콜의 헤더를 저장할 구조체 정의
typedef struct IPHeader
{
	u_char HeaderLength : 4;//헤더 길이 *4
	u_char Version : 4;//IP v4 or IPv6
	u_char TypeOfService;//서비스 종류
	u_short TotalLength;//헤더 길이 + 데이터 길이/
	u_short ID;//프래그 먼트의 Identification
	u_short FlagOffset;//플래그 + 프래그먼트 오프셋

	u_char TimeToLive;//TimeToL
	u_char Protocol;//프로토콜 종류(1. ICMP 2. IGMP 6. TCP 17:UDP;
	u_short checksum;
	ip SenderAddress;
	ip DestinationAddress;
	u_int Option_Padding;

	// 추가
	unsigned short source_port;
	unsigned short dest_port;
}IPHeader;

typedef struct TCPHeader
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;
	unsigned char ns : 1;
	unsigned char reserved_part1 : 3;
	unsigned char data_offset : 4;
	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;
	unsigned char ecn : 1;
	unsigned char cwr : 1;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
}TCPHeader;

typedef struct CheckSummer
{
	//0    2byte       2byte   32
	// [   4500   ][   003c   ] Version, HeaderLength, TypeOfService / TotalLength
	// [   11e5   ][   0000   ] Identification / Flag, FragmentOffset
	// [   8001   ][          ] TimeToLive, Protocol / HeaderChecksum
	// [   7c89   ][   19a4   ] Source Address
	// [   7c89   ][   19a3   ] Destination Address
	// 위 모든 숫자의 합이 HeaderChecksum 값과 같을 경우, 패킷은 정상이다.
	// 그런데 다 더하면 2037b 라서 2바이트 크기를 넘게 된다.
	// 그래서 뒷 037b를 제외한 오버 플로우 값 2를 뒤에 더한다.
	//     037b
	//  +     2
	//  ────
	//     037d
	// 그리고 나서 계산 결과 값(037d)를 보수 형태로 취한다.
	// (1의 보수 = 0을 1로, 1을 0으로)
	// 037d = 0000 0011 0111 1101
	// 보수 = 1111 1100 1000 0010
	// 16진 = fc82
	// 그러므로 비워진 부분에는 fc82가 들어가게 된다.

	/*
	u_char = 1 byte
	u_short = 2 byte
	int = 4 byte
	*/
	//구조와 맞지 않지만 Version을 헤더 길이 다음으로 받아야 정상적으로 헤더 길이와 버전이 나온다.
	/*
	u_char = 1 byte
	u_short = 2 byte
	int = 4 byte
	*/
	u_short part1;
	u_short part2;
	u_short part3;
	u_short part4;
	u_short part5;
	u_short checksum;
	u_short part6;
	u_short part7;
	u_short part8;
	u_short part9;

}CheckSummer;

// (추가) HTTPHeader
typedef struct HTTPHeader

{
	uint16_t HTP[16];

}HTTPHeader;



void packet_handler(u_char* param, const struct pcap_pkthdr* h, const u_char* data); //패킷을 무한 루프 상태에서 읽고 처리하는 함수
void PrintHttpHeader(const uint8_t* packet); // Http헤더 출력 함수 (추가)
void PrintHexAscii(const u_char* buffer, unsigned int Psize); // 아스키코드 변환 (추가)
void print_first(const struct pcap_pkthdr* h, Ethernet_Header* EH);
void print_protocol(Ethernet_Header* EH, short int type, IPHeader* IH, TCPHeader* TCP, CheckSummer* CS);
u_int sel=0;

void main()
{
	pcap_if_t* allDevice; //찾아낸 디바이스를 LinkedList로 묶고, 그 중 첫 번째 오브젝트를 담을 변수 생성
	pcap_if_t* device; //Linked List의 다음 오브젝트를 담을 공간
	char errorMSG[256]; //에러 메시지를 담을 변수 생성
	char counter = 0;

	pcap_t* pickedDev; //사용할 디바이스를 저장하는 변수

				//1. 장치 검색 (찾아낸 디바이스를 LinkedList로 묶음)
	if ((pcap_findalldevs(&allDevice, errorMSG)) == -1)//변수 생성시에는 1 포인터지만, pcap_findallDevice에 쓰는건 더블 포인트이므로 주소로 주어야 함.
								  //pcap_if_t는 int형태를 반환하며, -1이 나올 경우, 디바이스를 찾지 못했을 경우이다.
		printf("장치 검색 오류");

	//2. 장치 출력
	int count = 0;
	for (device = allDevice; device != NULL; device = device->next)
		//dev에 allDevice의 첫 시작 주소를 넣으며, dev의 값이 NULL(끝)일 경우 종료, dev는 매 for마다 다음 주소값으로 전환
	{
		printf("┏  %d 번 네트워크 카드━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n", count);
		printf("┃ 어댑터 정보 : %s ┃\n", device->name);
		printf("┃ 어댑터 설명 : %s \n", device->description);
		printf("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n");
		count = count + 1;
	}

	//3. 네트워크 카드를 선택하고 선택된 디바이스로 수집할 패킷 결정하기
	printf("패킷을 수집할 네트워크 카드를 선택 하세요 : ");
	device = allDevice;//카드를 선택하지 않고 그냥 첫 번째 카드로 설정했음.

	int choice;
	scanf_s("%d", &choice);

	while (1) {
		printf("<필터링>\n");
		printf(" 1. ICMP\n 2. TCP\n 3. UDP\n 4. HTTP\n 5. FTP\n 6. ALL\n");
		printf(" >> ");
		scanf_s("%d", &sel);
		if (sel == 1 || sel == 2 || sel == 3 || sel == 4 || sel == 5 || sel == 6) {
			break;
		}
		else {
			printf("다시입력\n");
		}
	}

	for (count = 0; count < choice; count++)
	{
		device = device->next;
	}

	//네트워크 장치를 열고, 수집할 패킷 양을 설정한다.
	pickedDev = pcap_open_live(device->name, 65536, 0, 1000, errorMSG);
	//랜카드의 이름, 수집할 패킷 크기(최대 65536), 프로미스큐어스모드(패킷 수집 모드) 설정, 패킷 대기 시간, 에러 정보를 저장할 공간)

	//4. 랜카드 리스트 정보를 저장한 메모리를 비워준다.
	pcap_freealldevs(allDevice);

	//5. 설정한 네트워크 카드에서 패킷을 무한 캡쳐 할 함수를 만들고 캡쳐를 시작한다.
	pcap_loop(pickedDev, 0, packet_handler, NULL);
}
// 데이터 출력
void print_data(const u_char* data) {
	printf("┃  ----------------DATA--------------\n");
	printf("┃\t%s \n", data);
}

// HTTP 헤더 출력
void PrintHttpHeader(const uint8_t* packet) {

	HTTPHeader* hh;
	hh = (HTTPHeader*)packet;
	printf("┃  ---------------HTTP Header--------------\n");

	printf("┃\t%s \n", packet);
	for (int i = 0; i < 16; i++) {
		//printf("%02x ", hh->HTP[i]);
		//PrintHexAscii(hh->HTP[i], sizeof(uint8_t));
	}
	printf("\n");

}

void PrintHexAscii(const u_char* buffer, unsigned int Psize)
{
	int iCnt, iCnt2;

	printf("addr   ");
	for (iCnt2 = 0; iCnt2 < 16; ++iCnt2)
	{
		printf("%02X ", iCnt2);
	}
	printf("   ");
	for (iCnt2 = 0; iCnt2 < 16; ++iCnt2)
	{
		printf("%X", iCnt2);
	}
	printf("\n");
	printf("==========================================================================\n");
	for (iCnt = 0; iCnt < Psize + (16 - (Psize % 16)); ++iCnt)
	{
		if (0 == (iCnt % 16))
		{
			printf("0x%02X0  ", iCnt / 16);
		}
		printf("%02X ", *(buffer + iCnt));
		if (15 == iCnt % 16)
		{
			printf("   ");
			for (iCnt2 = iCnt - 16; iCnt2 < iCnt; ++iCnt2)
			{
				if ((*(buffer + iCnt2) < 33) || (*(buffer + iCnt2) > 127))
				{
					printf(".");
				}
				else
				{
					printf("%c", *(buffer + iCnt2));
				}
			}
			printf("\n");
		}
	}
}

//아래에서 사용할 수 있도록패킷 핸들러를 만든다.
void packet_handler(u_char* param, const struct pcap_pkthdr* h, const u_char* data)
//인자 = 파라미터, 패킷 헤더, 패킷 데이터(수신자 MAC 주소 부분 부터)
{
	/*
	 * unused variables
	 */
	(VOID)(param);
	(VOID)(data);

	//소스 읽을 때 가독성을 위해 상수를 문자로 바꾼다.
	Ethernet_Header* EH = (Ethernet_Header*)data;//data 주소에 저장된 14byte 데이터가 구조체 Ethernet_Header 형태로 EH에 저장된다.
	short int type = ntohs(EH->ptype);
	//EH->ptype은 빅 엔디언 형식을 취하므로,
	//이를 리틀 엔디언 형식으로 변환(ntohs 함수)하여 type에 저장한다.
	IPHeader* IH = (struct IPHeader*)(data + 14); //제일 처음 14byte는 이더넷 헤더(Layer 2) 그 위에는 IP헤더(20byte), 그 위에는 TCP 헤더...
	TCPHeader* TCP = (struct TCPHeader*)(data + 34); // TCP 헤더 
	CheckSummer* CS = (struct CheckSummer*)(data + 14); //체크섬을 저장 할 변수

	//1. ICMP 2. TCP 3. UDP 4. HTTP 5. FTP 6. ALL
	switch (sel) {
	case 1:
		if (IH->Protocol == IPPROTO_ICMP) {
			print_first(h, EH);
			print_protocol(EH, type, IH, TCP, CS);
			printf("Internet Control Message               \n");
		}
		break;
	case 2:
		if (IH->Protocol == IPPROTO_TCP) {
			print_first(h, EH);
			print_protocol(EH, type, IH, TCP, CS);

			printf("TCP              \n");
			// 추가
			printf("┃  --------------------------------------------  \n");
			printf("┃\t\t*[ TCP 헤더 ]*\t\t\n");
			printf("┃\tSCR PORT : %d\n", ntohs(TCP->source_port));
			printf("┃\tDEST PORT : %d\n", ntohs(TCP->dest_port));
			printf("┃\tSeg : %u\n", ntohl(TCP->sequence));
			printf("┃\tAck : %u\n", ntohl(TCP->acknowledge));
		}
		break;
	case 3:
		if (IH->Protocol == IPPROTO_UDP) {
			print_first(h, EH);
			print_protocol(EH, type, IH, TCP, CS);
		}
		break;
	case 4:
		if (IH->Protocol == IPPROTO_TCP) {
			print_protocol(EH, type, IH, TCP, CS);
			print_first(h, EH);

			printf("┃  --------------------------------------------  \n");
			printf("┃\t\t*[ TCP 헤더 ]*\t\t\n");
			printf("┃\tSCR PORT : %d\n", ntohs(TCP->source_port));
			printf("┃\tDEST PORT : %d\n", ntohs(TCP->dest_port));
			printf("┃\tSeg : %u\n", ntohl(TCP->sequence));
			printf("┃\tAck : %u\n", ntohl(TCP->acknowledge));

			if (ntohs(TCP->source_port) == 80 || ntohs(TCP->dest_port) == 80) {
				printf("┃\tHTTP 프로토콜 \n");
				PrintHttpHeader(data + 34 + (IH->HeaderLength) * 4);
			}
		}
		break;
	case 5:
		if (IH->Protocol == IPPROTO_TCP) {
			print_protocol(EH, type, IH, TCP, CS);
			print_first(h, EH);

			printf("┃  --------------------------------------------  \n");
			printf("┃\t\t*[ TCP 헤더 ]*\t\t\n");
			printf("┃\tSCR PORT : %d\n", ntohs(TCP->source_port));
			printf("┃\tDEST PORT : %d\n", ntohs(TCP->dest_port));
			printf("┃\tSeg : %u\n", ntohl(TCP->sequence));
			printf("┃\tAck : %u\n", ntohl(TCP->acknowledge));

			if (ntohs(TCP->source_port) == 21 || ntohs(TCP->dest_port) == 21) {
				printf("┃\tFTP 프로토콜 \n");
				print_data(data + 34 + (IH->HeaderLength) * 4);
			}
		}
		break;
	case 6:
		print_first(h, EH);
		print_protocol(EH, type, IH, TCP, CS);

		switch (IH->Protocol) {

		case IPPROTO_PUP:
			printf("PUP                                    \n");
			break;
		case IPPROTO_UDP:
			printf("UDP                    \n");
			break;
		case IPPROTO_IDP:
			printf("XNS IDP                                \n");
			break;
		case IPPROTO_PIM:
			printf("Independent Multicast                  \n");
			break;
		case IPPROTO_RAW:
			printf("Raw IP Packets                         \n");
			break;
		default:
			printf("Unknown                                \n");
		}
		break;
	default:
		break;
	}
	printf("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
}

void print_protocol(Ethernet_Header* EH, short int type, IPHeader* IH, TCPHeader* TCP, CheckSummer* CS) {
	printf("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
	printf("┃\t\t*[ Ethernet 헤더 ]*\t\t\n");
	printf("┃\tSrc MAC : %02x-%02x-%02x-%02x-%02x-%02x\n", EH->src[0], EH->src[1], EH->src[2], EH->src[3], EH->src[4], EH->src[5]);//송신자 MAC
	printf("┃\tDst MAC : %02x-%02x-%02x-%02x-%02x-%02x\n", EH->des[0], EH->des[1], EH->des[2], EH->des[3], EH->des[4], EH->des[5]);//수신자 MAC
	printf("┃----------------------------------------------------------------------------------------------\n");

	//물리 계층은 01010101이므로 데이터 자르기는 안해도 됨.
	//헤더가 붙는 Layer2인 데이터링크 계층부터 자르면 됨.

	if (type == IPHEADER)
	{
		printf("┃\t\t*[ IP 헤더 ]*\n");
		printf("┃\tProtocol : IP\n");
		int partSum = ntohs(CS->part1) + ntohs(CS->part2) + ntohs(CS->part3) + ntohs(CS->part4) + ntohs(CS->part5) + ntohs(CS->part6) + ntohs(CS->part7) + ntohs(CS->part8) + ntohs(CS->part9);
		u_short Bit = partSum >> 16;
		printf("┃\t파트 합 : %08x\n", partSum);
		// printf("┃\t4칸 이동 : %08x\n", Bit);
		partSum = partSum - (Bit * 65536);
		// printf("┃\t넘긴것 더한 파트 합 : %04x\n", partSum + Bit);
		// printf("┃\t보수 취하기 : %04x\n", (u_short)~(partSum + Bit));
		printf("┃\t체크섬 : %04x\n", ntohs(CS->checksum));
		if (ntohs(CS->checksum) == (u_short)~(partSum + Bit))
			printf("┃\t손상되지 않은 정상 패킷입니다.\n");
		else
			printf("┃\t손상된 패킷입니다. 재 전송 요청을 해야 합니다.\n");
		printf("┃\t버전 : IPv%d\n", IH->Version);
		printf("┃\t헤더 길이 : %d\n", (IH->HeaderLength) * 4);
		printf("┃\t서비스 종류 : %04x\n", IH->TypeOfService);
		printf("┃\t전체 크기 : %d\n", ntohs(IH->HeaderLength));//2 bytes 이상 부터는 무조건 뒤집어야 하므로 ntohs함수를 써서 뒤집는다.
		printf("┃\t프래그먼트 오프셋 : %d[byte]\n", (0x1FFF & ntohs(IH->FlagOffset) * 8));
		printf("┃\tTTL : %d\n", IH->TimeToLive);
		//  printf("┃\t체크섬 : %04x\n", ntohs(IH->checksum));//예) 0x145F
		printf("┃\t출발 IP 주소 : %d.%d.%d.%d\n", IH->SenderAddress.ip1, IH->SenderAddress.ip2, IH->SenderAddress.ip3, IH->SenderAddress.ip4);
		printf("┃\t도착 IP 주소 : %d.%d.%d.%d\n", IH->DestinationAddress.ip1, IH->DestinationAddress.ip2, IH->DestinationAddress.ip3, IH->DestinationAddress.ip4);
		//	printf("┃\t옵션/패딩 : %d\n", IH->Option_Padding);

		printf("┃\t세부 프로토콜 : "/*, IH->Protocol*/);
	}
	else if (type == ARPHEADER)
	{
		printf("┃\tProtocol : ARP\n");
	}
	else if (type == RARPHEADER)
		printf("┃\tProtocol : RARP\n");
}

void print_first(const struct pcap_pkthdr* h, Ethernet_Header* EH) {
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	/* convert the timestamp to readable format */
	local_tv_sec = h->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
	printf("Time: %s,%.6d len:%d\n", timestr, h->ts.tv_usec, h->len);

	printf("Next Packet : %04x\n", EH->ptype);
}