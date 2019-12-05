#include <winsock2.h>

#define ETH_ALEN			6                
#define ETHERTYPE_PUP       0x0200      /* Xerox PUP */
#define ETHERTYPE_IP        0x0800      /* IP */
#define ETHERTYPE_ARP       0x0806      /* Address resolution */
#define ETHERTYPE_REVARP    0x8035      /* Reverse ARP */

#define IPTOS_TOS_MASK      0x1E
#define IPTOS_TOS(tos)      ((tos)&IPTOS_TOS_MASK)
#define IPTOS_LOWDELAY      0x10
#define IPTOS_THROUGHPUT    0x08
#define IPTOS_RELIABILITY   0x04
#define IPTOS_LOWCOST       0x02

struct ether_header
{
  unsigned char ether_dhost[ETH_ALEN];
  unsigned char ether_shost[ETH_ALEN];
  unsigned short ether_type;
};

#pragma pack(1)
struct ip_header{

  unsigned char  ip_hl:4;	// 헤더 길이
  unsigned char  ip_v:4;	// 버전

  u_char		ip_tos;		// 서비스 타입
  u_short		ip_len;		// 전체길이
  u_short		ip_id;		// 식별자
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff 
  u_short      ip_off;		// 플래그, 오프셋 필드
  
  u_int8_t    ip_ttl;		// TTL
  u_int8_t    ip_p;			// 프로토콜
  u_short     ip_sum;		// 체크섬

  struct in_addr ip_src;	// 출발지 IP주소
  struct in_addr ip_dst;	// 도착지 IP주소

};
#pragma pack()