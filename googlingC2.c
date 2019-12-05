#include "pcap.h"

#include <stdio.h>
#include <winsock2.h>

#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib" )

#define FILTER_RULE "host 165.246.12.215 and port 7778"

struct ether_addr
{
	unsigned char ether_addr_octet[6];
};

struct ether_header
{
	struct  ether_addr ether_dhost;
	struct  ether_addr ether_shost;
	unsigned short ether_type;
};

struct ip_header
{
	unsigned char ip_header_len : 4;
	unsigned char ip_version : 4;
	unsigned char ip_tos;
	unsigned short ip_total_length;
	unsigned short ip_id;
	unsigned char ip_frag_offset : 5;
	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;
	unsigned char ip_frag_offset1;
	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	struct in_addr ip_srcaddr;
	struct in_addr ip_destaddr;
};

struct tcp_header
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
};

void print_ether_header(const unsigned char* data);
int print_ip_header(const unsigned char* data);
int print_tcp_header(const unsigned char* data);
void print_data(const unsigned char* data);

int main() {
	pcap_if_t* alldevs = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	int offset = 0;

	// find all network adapters
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("dev find failed\n");
		return -1;
	}
	if (alldevs == NULL) {
		printf("no devs found\n");
		return -1;
	}
	// print them
	pcap_if_t* d; int i;
	for (d = alldevs, i = 0; d != NULL; d = d->next) {
		printf("%d-th dev: %s ", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	int inum;

	printf("enter the interface number: ");
	scanf("%d", &inum);
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++); // jump to the i-th dev

	// open
	pcap_t* fp;
	if ((fp = pcap_open_live(d->name,      // name of the device
		65536,                   // capture size
		1,  // promiscuous mode
		20,                    // read timeout
		errbuf
	)) == NULL) {
		printf("pcap open failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("pcap open successful\n");

	struct bpf_program  fcode;
	if (pcap_compile(fp,  // pcap handle
		&fcode,  // compiled rule
		FILTER_RULE,  // filter rule
		1,            // optimize
		NULL) < 0) {
		printf("pcap compile failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_setfilter(fp, &fcode) < 0) {
		printf("pcap compile failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	pcap_freealldevs(alldevs); // we don't need this anymore

	struct pcap_pkthdr* header;

	const unsigned char* pkt_data;
	int res;

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
		if (res == 0) continue;

		print_ether_header(pkt_data);
		pkt_data = pkt_data + 14;       // raw_pkt_data의 14번지까지 이더넷
		offset = print_ip_header(pkt_data);
		pkt_data = pkt_data + offset;           // ip_header의 길이만큼 오프셋
		offset = print_tcp_header(pkt_data);
		pkt_data = pkt_data + offset;           //print_tcp_header *4 데이터 위치로 오프셋
		print_data(pkt_data);
	}


	return 0;

}

void print_ether_header(const unsigned char* data)
{
	struct  ether_header* eh;               // 이더넷 헤더 구조체
	unsigned short ether_type;
	eh = (struct ether_header*)data;       // 받아온 로우 데이터를 이더넷 헤더구조체 형태로 사용
	ether_type = ntohs(eh->ether_type);       // 숫자는 네트워크 바이트 순서에서 호스트 바이트 순서로 바꿔야함

	if (ether_type != 0x0800)
	{
		printf("ether type wrong\n");
		return;
	}
	// 이더넷 헤더 출력
	printf("\n============ETHERNET HEADER==========\n");
	printf("Dst MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for dest
		eh->ether_dhost.ether_addr_octet[0],
		eh->ether_dhost.ether_addr_octet[1],
		eh->ether_dhost.ether_addr_octet[2],
		eh->ether_dhost.ether_addr_octet[3],
		eh->ether_dhost.ether_addr_octet[4],
		eh->ether_dhost.ether_addr_octet[5]);
	printf("Src MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for src
		eh->ether_shost.ether_addr_octet[0],
		eh->ether_shost.ether_addr_octet[1],
		eh->ether_shost.ether_addr_octet[2],
		eh->ether_shost.ether_addr_octet[3],
		eh->ether_shost.ether_addr_octet[4],
		eh->ether_shost.ether_addr_octet[5]);
}

int print_ip_header(const unsigned char* data)
{
	struct  ip_header* ih;
	ih = (struct ip_header*)data;  // 마찬가지로 ip_header의 구조체 형태로 변환

	printf("\n============IP HEADER============\n");
	printf("IPv%d ver \n", ih->ip_version);
	// Total packet length (Headers + data)
	printf("Packet Length : %d\n", ntohs(ih->ip_total_length) + 14);
	printf("TTL : %d\n", ih->ip_ttl);
	if (ih->ip_protocol == 0x06)
	{
		printf("Protocol : TCP\n");
	}
	printf("Src IP Addr : %s\n", inet_ntoa(ih->ip_srcaddr));
	printf("Dst IP Addr : %s\n", inet_ntoa(ih->ip_destaddr));

	// return to ip header size
	return ih->ip_header_len * 4;
}

int print_tcp_header(const unsigned char* data)
{
	struct  tcp_header* th;
	th = (struct tcp_header*)data;

	printf("\n============TCP HEADER============\n");
	printf("Src Port Num : %d\n", ntohs(th->source_port));
	printf("Dest Port Num : %d\n", ntohs(th->dest_port));
	printf("Flag :");
	if (ntohs(th->cwr))
	{
		printf(" CWR ");
	}
	if (ntohs(th->ecn))
	{
		printf(" ENC ");
	}
	if (ntohs(th->urg))
	{
		printf(" URG ");
	}
	if (ntohs(th->ack))
	{
		printf(" ACK ");
	}
	if (ntohs(th->psh))
	{
		printf(" PUSH ");
	}
	if (ntohs(th->rst))
	{
		printf(" RST ");
	}
	if (ntohs(th->syn))
	{
		printf(" SYN ");
	}
	if (ntohs(th->fin))
	{
		printf(" FIN ");
	}

	printf("\n");

	// return to tcp header size
	return th->data_offset * 4;
}

void print_data(const unsigned char* data)
{
	printf("\n============DATA============\n");
	printf("%s\n", data);
}