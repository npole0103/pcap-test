# pcap-test
pcap-test Ethernet Header / IP Header / TCP Header / HTTP Header

---

## 21.07.16

### OSI 7 계층

#### Case 1
fread(&f1, sizeof(int), 1, file1); //4바이트씩 1번 읽어라. 만약 3바이트면 0을 반환함

#### Case 2
fread(&f1, 1, sizeof(int), file1); //최대 4바이트까지 읽어라. 3바이트라면 3바이트 반환

Case 2가 더 좋다.

코드의 중복 처리 => 함수화 해야한다.

초보 개발자와 고수 개발자의 차이는 main 함수가 얼마나 짧은지.

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

EtherNet의 Ether type에 따라 다르게 읽음?

IP의 protocol을 보고 TCP header? 종류 찾아보기

[Ethernet, IP, TCP/UDP 헤더 소개](https://www.netmanias.com/ko/post/blog/5372/ethernet-ip-ip-routing-network-protocol/packet-header-ethernet-ip-tcp-ip)

---
