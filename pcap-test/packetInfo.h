#ifndef PACKETINFO_H
#define PACKETINFO_H

#pragma once
#include <pcap.h> //보안제품개발 트랙 김수헌
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <libnet.h>

/* 구조체 사용으로 안 쓰는 정보
//Ethernet Header
#define D_MAC 0
#define S_MAC 6
#define ETHER_TYPE 12

//IP Header
#define S_IP 14 + 12
#define D_IP 14 + 16
#define PROTOCOL 14 + 9

//TCP Header
#define S_PORT 14 + 20 + 0
#define D_PORT 14 + 20 + 2

//HTTP Header
#define DATA 14 + 20 + 20
*/

#define ETHER_OFFSET 0 // 0
#define IP_OFFSET 14 // 0 + 14
#define TCP_OFFSET 34 // 0 + 14 + 20
#define HTTP_OFFSET 54 // 0 + 14 + 20 + 20

#define MAC_SIZE 6

// 1 byte = 8bit

void printInfo(const u_char packet[]);
void printEther(const u_char packet[]);
void printIP(const u_char packet[]);
void printTCP(const u_char packet[]);
void printHTTP(const u_char packet[]);

#endif // PACKETINFO_H
