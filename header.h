#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
typedef struct ethernet_header{
    u_char dest[6];
    u_char source[6];
    u_short type;
} ETHER_HDR;

typedef struct ip_hdr
{
    u_char header_len :4; // 4 bit header length
    u_char version :4; //4-bit ip version
    u_char ip_tos; // 8 bit type of service
    uint16_t ip_total_length; // 2 byte total length
    uint16_t ip_id; // 2 byte Unique identifier
 
    unsigned char ip_more_fragment :1;
    unsigned char ip_dont_fragment :1;
    unsigned char ip_reserved_zero :1;
 
     unsigned char ip_frag_offset; // Fragment offset field
 
    u_char ip_ttl; // 1 byte TTL
    char protocol_id; // 1 byte protocol(TCP,UDP etc)
    uint16_t ip_checksum; // 2 byte IP checksum
    struct in_addr ip_srcaddr; // 4 byte source address
    struct in_addr ip_dstaddr; // 4 byte destination address
} IPV4_HDR;

typedef struct tcp_hdr{
    uint16_t tcp_srcport;
    uint16_t tcp_dstport;
    int tcp_seqnum;
    int tcp_acknum;
    u_char header_len1:4;
    u_char header_len2:4;
} TCP_HDR;

typedef struct tcp_payload{
    u_char data[16];
} TCP_PAY;
