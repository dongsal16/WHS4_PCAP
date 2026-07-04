//PCAP 프로그램

#include <pcap.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// 리눅스·유닉스 시스템 표준 네트워크 헤더 구조체들이 정의된 파일들
#include <net/ethernet.h> // Ethernet 헤더 구조체 정의
#include <netinet/ip.h>   // IP 헤더 구조체 정의
#include <netinet/tcp.h>  // TCP 헤더 구조체 정의
#include <arpa/inet.h>    // 네트워크 바이트 순서를 호스트 순서로 바꾸는 함수 정의

// Ethernet 헤더의 고정 크기 : 14바이트임
#define ETHERNET_HEADER_LEN 14

// MAC 주소 보기 편하게 출력
void print_mac(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// 패킷 데이터 텍스트로 출력
void print_payload(const u_char *payload, int len) {
    for (int i = 0; i < len; i++) {
        if (isprint(payload[i]) || payload[i] == '\n' || payload[i] == '\r' || payload[i] == '\t') {
            putchar(payload[i]);
        } else {
            // 이미지·바이너리는 '.'으로 대체해 출력
            putchar('.');
        }
    }
    printf("\n");
}

// 캡처된 패킷 Ethernet -> IP -> TCP -> 데이터(HTTP) 순으로 분석
void analyze_packet(const struct pcap_pkthdr *header, const u_char *packet, int packet_no) {
    
    // Ethernet Header를 읽기 위해선 최소 14바이트가 필요, 그보다 짧은 패킷은 분석X
    if (header->caplen < ETHERNET_HEADER_LEN) {
        return;
    }

    // Ethernet 헤더 파싱
    const struct ether_header *eth = (const struct ether_header *)packet;

    // ntohs(): 네트워크 바이트 순서(빅 엔디안) -> 컴퓨터의 바이트 순서(리틀 엔디안)로 변환
    // IP 패킷이 아니면 넘김
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return;
    }

    // IP 헤더 파싱
    // IP헤더 시작점 : 시작 주소에서 Ethernet 크기(14바이트)만큼 건너뜀
    const struct ip *ip_header = (const struct ip *)(packet + ETHERNET_HEADER_LEN);
    
    // IP 헤더의 크기는 고정X, 헤더 안에 적힌 'ip_hl' 값에 4를 곱해야함
    int ip_header_len = ip_header->ip_hl * 4;

    // TCP 프로토콜이 아니면 넘김
    if (ip_header->ip_p != IPPROTO_TCP) {
        return;
    }

    // TCP 헤더 파싱
    // TCP 헤더의 시작점 : 시작 주소에서 Ethernet 크기 + IP 헤더 크기만큼 건너뜀
    const struct tcphdr *tcp_header = (const struct tcphdr *)(packet + ETHERNET_HEADER_LEN + ip_header_len);
    
    // TCP 헤더 크기 고정X, 헤더 안의 'th_off' 값에 4를 곱해야함
    int tcp_header_len = tcp_header->th_off * 4;

    // 페이로드 데이터(HTTP Message 등)의 위치, 크기 계산
    // ip_header->ip_len : IP헤더 + TCP헤더 + 실제데이터를 합친 총 길이
    int ip_total_len = ntohs(ip_header->ip_len);
    
    // Payload 데이터 길이 : 총 길이 - (IP 헤더 길이 + TCP 헤더 길이)
    int payload_len = ip_total_len - ip_header_len - tcp_header_len;

    // 데이터 시작점 : 시작 주소에서 모든 헤더 크기(Ethernet + IP + TCP)만큼 건너뜀
    const u_char *payload = packet + ETHERNET_HEADER_LEN + ip_header_len + tcp_header_len;

    // 출력
    printf("\n------ Packet %d ------\n", packet_no);
    // Ethernet : 출발지 MAC 주소와 목적지 MAC 주소 출력
    printf("[Ethernet Header]\n");
    printf("Src MAC: ");
    print_mac(eth->ether_shost);
    printf("\nDst MAC: ");
    print_mac(eth->ether_dhost);
    printf("\n");

    // IP : 출발지 IP 주소, 목적지 IP 주소
    printf("\n[IP Header]\n");
    printf("Src IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Dst IP: %s\n", inet_ntoa(ip_header->ip_dst));

    // TCP : 출발지 포트와 목적지 포트 출력
    printf("\n[TCP Header]\n");
    printf("Src Port: %d\n", ntohs(tcp_header->th_sport));
    printf("Dst Port: %d\n", ntohs(tcp_header->th_dport));

    // HTTP Message
    printf("\n[HTTP Message]\n");
    if (payload_len > 0) {
        print_payload(payload, payload_len);
    } else {
        printf("No HTTP payload\n"); // TCP 연결을 맺거나 끊을 때 주고받는 ACK/SYN 패킷들
    }
}

//메인
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE]; // 에러 메시지가 발생했을 때 담아둘 버퍼

    // 인자로 받은 pcap 파일을 열어 읽기 (파일 읽기 모드)
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
        return 1;
    }

    struct pcap_pkthdr *header; // 패킷의 메타데이터 저장
    const u_char *packet;       // 실제 패킷의 바이트 데이터가 들어있는 메모리를 가리킬 포인터
    int result;
    int packet_no = 1;          // 화면 출력용 패킷 번호 카운터

    // pcap_next_ex(): 패킷 한 장씩 꺼냄 (성공 시 1 반환)
    while ((result = pcap_next_ex(handle, &header, &packet)) >= 0) {
        // 패킷 하나마다 분석 함수(analyze_packet) 호출
        analyze_packet(header, packet, packet_no);
        packet_no++; // 패킷 번호 증가
    }

    pcap_close(handle);
    return 0;
}
