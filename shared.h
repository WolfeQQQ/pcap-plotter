#ifndef COMMON_H
#define COMMON_H
#include <stdint.h>

#define MAX_PACKETS 100000
#define TOP_N 3

typedef struct { // single packet
    int proto;          // 6 tcp, 17 udp
    uint32_t src_ip;    // source ip
    uint32_t dst_ip;    // dest ip
    uint16_t src_port;  // source port
    uint16_t dst_port;  // dest port
    int len;            // d\packet length
    int is_rst;         // 1 if rst, else 0 
    long sec;           // seconds
} SimplePacket;

typedef struct { // summary data
    int total_packets;
    int tcp_packets;
    int udp_packets;
    long total_bytes;
    long tcp_bytes;
    long udp_bytes;
    int rst_count;
    int top_port;
    int top_port_hits;
    int top_ports[TOP_N];
    int top_port_counts[TOP_N];
    int suspicious_flag; // anomaly flag
} Stats;

#endif