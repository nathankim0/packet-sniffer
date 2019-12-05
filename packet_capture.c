#define WIN32
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

#include <stdio.h>
#include <pcap\pcap.h>
#include <pcap.h>
#include <string.h>
#include <WinSock2.h>

void packet_handler(u_char* param, const struct pcap_pkthdr* h, const u_char* data);
//패킷을 무한 루프 상태에서 읽고 처리하는 함수

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

	unsigned short source_port;
	unsigned short dest_port;
}IPHeader;


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
		printf("┌%d 번 네트워크 카드───────────────────────────\n", count);
		printf("│어댑터 정보 : %s\n", device->name);
		printf("│어댑터 설명 : %s\n", device->description);
		printf("└────────────────────────────────────\n");
		count = count + 1;
	}

	//3. 네트워크 카드를 선택하고 선택된 디바이스로 수집할 패킷 결정하기
	printf("패킷을 수집할 네트워크 카드를 선택 하세요 : ");
	device = allDevice;//카드를 선택하지 않고 그냥 첫 번째 카드로 설정했음.

	int choice;
	scanf_s("%d", &choice);
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

//아래에서 사용할 수 있도록패킷 핸들러를 만든다.
void packet_handler(u_char* param, const struct pcap_pkthdr* h, const u_char* data)
//인자 = 파라미터, 패킷 헤더, 패킷 데이터(수신자 MAC 주소 부분 부터)
{
#define IPHEADER 0x0800
#define ARPHEADER 0x0806
#define RARPHEADER 0x0835
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;



	/*
	 * unused variables
	 */
	(VOID)(param);
	(VOID)(data);

	/* convert the timestamp to readable format */
	local_tv_sec = h->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	printf("시간: %s,%.6d len:%d\n", timestr, h->ts.tv_usec, h->len);


	//소스 읽을 때 가독성을 위해 상수를 문자로 바꾼다.
	Ethernet_Header* EH = (Ethernet_Header*)data;//data 주소에 저장된 14byte 데이터가 구조체 Ethernet_Header 형태로 EH에 저장된다.
	short int type = ntohs(EH->ptype);
	//EH->ptype은 빅 엔디언 형식을 취하므로,
	//이를 리틀 엔디언 형식으로 변환(ntohs 함수)하여 type에 저장한다.
	printf("다음 패킷 : %04x\n", EH->ptype);
	//귀찮으면 그냥 네트워크로 부터 1바이트를 초과하는 데이터를
	//수신 받을 때는  항상 리틀 엔디언 형식으로 변환 해 주어야 한다고 외우자.

	printf("┌─────────────────────────\n");
	printf("├  Src MAC : %02x-%02x-%02x-%02x-%02x-%02x\n", EH->src[0], EH->src[1], EH->src[2], EH->src[3], EH->src[4], EH->src[5]);//송신자 MAC
	printf("├  Dst MAC : %02x-%02x-%02x-%02x-%02x-%02x\n", EH->des[0], EH->des[1], EH->des[2], EH->des[3], EH->des[4], EH->des[5]);//수신자 MAC
	IPHeader* IH = (struct IPHeader*)(data + 14); //제일 처음 14byte는 이더넷 헤더(Layer 2) 그 위에는 IP헤더(20byte), 그 위에는 TCP 헤더...
	CheckSummer* CS = (struct CheckSummer*)(data + 14); //체크섬을 저장 할 변수
	//물리 계층은 01010101이므로 데이터 자르기는 안해도 됨.
	//헤더가 붙는 Layer2인 데이터링크 계층부터 자르면 됨.

	printf("Src Port Num : %d\n", ntohs(IH->source_port));
	printf("Dest Port Num : %d\n", ntohs(IH->dest_port));


	if (type == IPHEADER)
	{
		int partSum = ntohs(CS->part1) + ntohs(CS->part2) + ntohs(CS->part3) + ntohs(CS->part4) + ntohs(CS->part5) + ntohs(CS->part6) + ntohs(CS->part7) + ntohs(CS->part8) + ntohs(CS->part9);
		u_short Bit = partSum >> 16;
	//	printf("파트 합 : %08x\n", partSum);
	//	printf("4칸 이동 : %08x\n", Bit);
		partSum = partSum - (Bit * 65536);
	//	printf("넘긴것 더한 파트 합 : %04x\n", partSum + Bit);
	//	printf("보수 취하기 : %04x\n", (u_short)~(partSum + Bit));
	//	printf("체크섬 : %04x\n", ntohs(CS->checksum));
	//	if (ntohs(CS->checksum) == (u_short)~(partSum + Bit))
	//		printf("손상되지 않은 정상 패킷입니다.\n");
	//	else
	//		printf("손상된 패킷입니다. 재 전송 요청을 해야 합니다.\n");
		printf("버전 : IPv%d\n", IH->Version);
		printf("헤더 길이 : %d\n", (IH->HeaderLength) * 4);
	//	printf("서비스 종류 : %04x\n", IH->TypeOfService);
		printf("전체 크기 : %d\n", ntohs(IH->HeaderLength));//2 bytes 이상 부터는 무조건 뒤집어야 하므로 ntohs함수를 써서 뒤집는다.
		printf("패킷 ID : %d\n", ntohs(IH->ID));
	//	if (0x4000 == ((ntohs(IH->FlagOffset)) & 0x4000))
	//		printf("[1] 단편화 되지 않은 패킷입니다.\n");
	//	else
	//		printf("[0] 정상 단편화된 패킷\n");
	//	if (0x2000 == ((ntohs(IH->FlagOffset)) & 0x2000))
	//		printf("[1] 단편화된 패킷이 더 있습니다.\n");
	//	else
	//		printf("[0] 마지막 패킷입니다.\n");
	//	printf("프래그먼트 오프셋 : %d[byte]\n", (0x1FFF & ntohs(IH->FlagOffset) * 8));
		printf("TTL : %d\n", IH->TimeToLive);
		printf("프로토콜 : "/*, IH->Protocol*/);
		switch (IH->Protocol)
		{
		case IPPROTO_ICMP:
			printf("Internet Control Message\n");
			break;
		case IPPROTO_IGMP:
			printf("Internet Group Management\n");
			break;
		case IPPROTO_TCP:
			printf("TCP\n");
			break;
		case IPPROTO_PUP:
			printf("PUP\n");
			break;
		case IPPROTO_UDP:
			printf("UDP\n");
			break;
		case IPPROTO_IDP:
			printf("XNS IDP\n");
			break;
		case IPPROTO_PIM:
			printf("Independent Multicast\n");
			break;
		case IPPROTO_RAW:
			printf("Raw IP Packets\n");
			break;
		default:
			printf("Unknown\n");
		}
		printf("체크섬 : %04x\n", ntohs(IH->checksum));//예) 0x145F
		printf("출발 IP 주소 : %d.%d.%d.%d\n", IH->SenderAddress.ip1, IH->SenderAddress.ip2, IH->SenderAddress.ip3, IH->SenderAddress.ip4);
		printf("도착 IP 주소 : %d.%d.%d.%d\n", IH->DestinationAddress.ip1, IH->DestinationAddress.ip2, IH->DestinationAddress.ip3, IH->DestinationAddress.ip4);
	//	printf("옵션/패딩 : %d\n", IH->Option_Padding);
	//	printf("├Protocol : IP\n");

		
	}
	else if (type == ARPHEADER)
	{
		printf("├Protocol : ARP\n");
	}
	else if (type == RARPHEADER)
		printf("├Protocol : RARP\n");
	printf("└─────────────────────────\n");
}
