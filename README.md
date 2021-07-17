# pcap-test
## 개념 정리

pcap-test Ethernet Header / IP Header / TCP Header / HTTP Header
---

## 21.07.16

### Code Review

#### Case 1
fread(&f1, sizeof(int), 1, file1); //4바이트씩 1번 읽어라. 만약 3바이트면 0을 반환함

#### Case 2
fread(&f1, 1, sizeof(int), file1); //최대 4바이트까지 읽어라. 3바이트라면 3바이트 반환

Case 2가 더 좋다.

코드의 중복 처리 => 함수화 해야한다.

초보 개발자와 고수 개발자의 차이는 main 함수가 얼마나 짧은지.

---

### OSI 7 계층

**OSI 7 계층**
- Application
- Presentation
- Session
- Transport
- Network
- Data Link
- Pyhsical

**TCP/IP**

Ehternet(L2) / IP(L3) / TCP(L4)) / HTTP(L7)

---

#### Ethernet Header
이더넷 헤더는 총 14바이트로 구성되어 있다.

(Source  MAC 6바이트 + Destination MAC 6바이트 + Ether Type 2바이트)

(MAC Address : 6 bytes == 48 bits)

Ether Type
- IPv4 : 0800
- IPv6 : 86DD
- ARP : 0806

---

#### IP Header
IP 헤더는 총 20바이트로 구성되어 있다.

- Version : 4 bits
- Header Length : 4 bits
- Type of Service : 1바이트
- Total Packet Length : 2바이트
- Identifier : 2바이트
- Flags : 3 bits
- Fragment Offset : 13 bits
- Time to live : 2바이트
- Protocol : 1바이트
- Header checksum : 2바이트
- Source IP : 4 바이트
- Destination IP : 4바이트

Protocol Value
- TCP : 6
- UDP : 17

---

#### TCP Header

TCP 헤더는 총 20 바이트로 구성된다.

- Source Port : 2바이트
- Destination Port : 2바이트
- Sequence Number : 4바이트
- Acknowledgement Number : 4바이트
- HLEN + MLP + Reserved + Code Bits : 2바이트
- Window : 2바이트
- Checksum : 2바이트
- Urgent Pointer : 2바이트

---

#### HTTP Header

큰 바이트로 구성

---

## 과제

TCP 8바이트 출력

데이터는 8바이트까지만

header 구조체

ifconfig 하고 eth0 값 주면 됨.

sudo로 실행해야 됨.

---

### `#include <libnet.h>` 사용

#### `libnet/include/libnet/libnet-headers.h` hdr 구조체 살펴보기

``` c
/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};


```

#### #include <pcap.h> 살펴보기

`sudo apt install libpcap-dev`

* pcap 핸들 열기 : pcap_open, pcap_open_live, pcap_open_offline //리눅스는 pcap_open_live() 사용하면 됨
* pcap 핸들 닫기 : pcap_close
* packet 수신 : pcap_next_ex
* packet 송신 : pcap_sendpacket

---

EtherNet의 Ether type에 따라 다르게 읽음?

IP의 protocol을 보고 TCP header? 종류 찾아보기

[Ethernet, IP, TCP/UDP 헤더 소개](https://www.netmanias.com/ko/post/blog/5372/ethernet-ip-ip-routing-network-protocol/packet-header-ethernet-ip-tcp-ip)

---
