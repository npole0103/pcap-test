#include <pcap.h> //보안제품개발 트랙 김수헌
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <libnet.h>
#include "packetInfo.h"

/*
https://gitlab.com/gilgil/sns/-/wikis/pcap-programming/report-pcap-test
1. Ethernet Header의 src mac / dst mac
2. IP Header의 src ip / dst ip
3. TCP Header의 src port / dst port
4. Payload(Data)의 hexadecimal value(최대 8바이트까지만)
*/

void printInfo(const u_char packet[])
{
    struct libnet_ethernet_hdr* etherInfo = (struct libnet_ethernet_hdr*)(packet + ETHER_OFFSET);
    struct libnet_ipv4_hdr* ipInfo =(struct libnet_ipv4_hdr*)(packet + IP_OFFSET);

    // 예외처리 - IPv4나 TCP가 아니라면
    // (08 00 | 00) != 2048(0x0800) || (06 != 6)
    if((ntohs(etherInfo->ether_type) != 2048) || ipInfo->ip_p != 6) //이더 타입과 프로토콜 검사
    {
        printf("==========Packet==========\n");
        printf("This Packet is not IPv4 or TCP\n");
        printf("==========================\n");
        return;
    }

    printf("==========Packet==========\n");
    printEther(packet);
    printIP(packet);
    printTCP(packet);
    printHTTP(packet);
    printf("==========================\n");

    return;
}
void printEther(const u_char packet[])
{
    //패킷 정보 받아서 Unboxing
    struct libnet_ethernet_hdr* etherInfo = (struct libnet_ethernet_hdr*)(packet + ETHER_OFFSET);

    //Source MAC
    printf("Src MAC : ");
    for(int i = 0 ; i < MAC_SIZE - 1; i++)
        printf("%02x:", etherInfo->ether_dhost[i]);
    printf("%02x\n", etherInfo->ether_shost[MAC_SIZE - 1]);

    //Destination MAC
    printf("Des MAC : ");
    for(int i = 0 ; i < MAC_SIZE - 1; i++)
        printf("%02x:", etherInfo->ether_dhost[i]);
    printf("%02x\n", etherInfo->ether_dhost[MAC_SIZE - 1]);

    return;
}
void printIP(const u_char packet[])
{
    //패킷 정보 받아서 Unboxing
    struct libnet_ipv4_hdr* ipInfo =(struct libnet_ipv4_hdr*)(packet + IP_OFFSET);

    //inet_nota 이용해서 네트워크 주소 변환 https://mintnlatte.tistory.com/272
    printf("Src IP : %s\n",inet_ntoa(ipInfo->ip_src));
    printf("Des IP : %s\n",inet_ntoa(ipInfo->ip_dst));

    return;
}
void printTCP(const u_char packet[])
{
    //패킷 정보 받아서 Unboxing
    struct libnet_tcp_hdr* tcpInfo =(struct libnet_tcp_hdr*)(packet + TCP_OFFSET);

    printf("Src Port : %d\n", ntohs(tcpInfo->th_sport));
    printf("Des Port : %d\n", ntohs(tcpInfo->th_dport));

    return;
}
void printHTTP(const u_char packet[])
{
    //Data 8바이트 만큼 출력
    printf("PayLoad : ");
    for(int i = HTTP_OFFSET; i < HTTP_OFFSET + 8 ; i++)
        printf("%02x ", packet[i]);
    printf("\n");

    return;
}
