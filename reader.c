#include "reader.h"
#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

int read_pcap(const char *filename, SimplePacket *out_packets, int max_packets) {
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename, errbuf); // open pcap
    
    struct pcap_pkthdr *header; // packet header
    const u_char *packet; // raw packet
    int count = 0; // saved count
    int res; // status

    // read loop 
    while (count < max_packets && (res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue; // timeout

        // skip ethernet header
        if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
            continue;
        }


        const struct ether_header *eth = (const struct ether_header *)packet;
        if (ntohs(eth->ether_type) != ETHERTYPE_IP) { 
            continue; // skip non ip v4
        }

        const struct ip *ip_hdr = (const struct ip *)(packet + sizeof(struct ether_header)); // cast ip header
        int ip_len = ip_hdr->ip_hl * 4;
        if (ip_len < 20 || header->caplen < sizeof(struct ether_header) + ip_len) {
            continue; // skip bad ip
        }

        SimplePacket sp; 

        // set packet stats 
        sp.proto = 0;
        sp.src_ip = ip_hdr->ip_src.s_addr;
        sp.dst_ip = ip_hdr->ip_dst.s_addr;
        sp.src_port = 0;
        sp.dst_port = 0;
        sp.len = header->len;
        sp.is_rst = 0;
        sp.sec = header->ts.tv_sec;

        const u_char *transport = (const u_char *)ip_hdr + ip_len; // transport layer

        if (ip_hdr->ip_p == IPPROTO_TCP) { // check if tcp
            if (header->caplen >= sizeof(struct ether_header) + ip_len + sizeof(struct tcphdr)) {
                const struct tcphdr *tcp_hdr = (const struct tcphdr *)transport;
                // set stats
                sp.proto = 6; 
                sp.src_port = ntohs(tcp_hdr->th_sport);
                sp.dst_port = ntohs(tcp_hdr->th_dport);
                if (tcp_hdr->th_flags & TH_RST) {
                    sp.is_rst = 1;
                }
            }
        } else if (ip_hdr->ip_p == IPPROTO_UDP) { // check if udp
            if (header->caplen >= sizeof(struct ether_header) + ip_len + sizeof(struct udphdr)) {
                const struct udphdr *udp_hdr = (const struct udphdr *)transport;
                //sets stats
                sp.proto = 17;
                sp.src_port = ntohs(udp_hdr->uh_sport);
                sp.dst_port = ntohs(udp_hdr->uh_dport);
            }
        } else {
            continue; // skip other
        }

        out_packets[count] = sp; // store packet 
        count++;
    }

    pcap_close(handle); // close pcap
    return count; 
}