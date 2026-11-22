#include <stdio.h>
#include "shared.h"
#include "reader.h"
#include "analyzer.h"
#include "charts.h"
#include "pdf.h"

int main(int argc, char **argv) {

    if (argc < 2) {
        printf("Please use: %s <file.pcap>\n", argv[0]);
        return 1;
    }

    //gather packets from .pcap to an array
    SimplePacket packets[MAX_PACKETS]; 
    int count = read_pcap(argv[1], packets, MAX_PACKETS);
    if (count < 0) {
        return 1;
    }

    //gather and print stats
    Stats st = analyze_packets(packets, count);
    printf("Packets count: %d\n", st.total_packets);
    printf("TCP: %d, UDP: %d, RST: %d\n", st.tcp_packets, st.udp_packets, st.rst_count);
    printf("Top port: %d (%d)\n", st.top_port, st.top_port_hits);
    printf("Suspicious: %s\n", st.suspicious_flag ? "TAK" : "NIE");

    // generate charts 
    if (generate_charts(&st) != 0) {
        printf("Blad generowania wykresu\n");
    }

    // generate pdf
    if (generate_pdf("raport.pdf", argv[1], &st) != 0) {
        printf("Blad generowania PDF\n");
    }

    return 0;
}