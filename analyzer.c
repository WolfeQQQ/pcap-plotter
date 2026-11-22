#include "analyzer.h"
#include <string.h>

Stats analyze_packets(const SimplePacket *packets, int count) {
    Stats st; // stats struct w/ reset
    memset(&st, 0, sizeof(Stats)); 

    int port_counts[65536]; // ports counter w/ reset
    memset(port_counts, 0, sizeof(port_counts));

    // loop all packets
    for (int i = 0; i < count; i++) { 
        SimplePacket p = packets[i]; //analyze current packet

        // set stats 
        st.total_packets++;
        st.total_bytes += p.len;

        if (p.proto == 6) {
            st.tcp_packets++;
            st.tcp_bytes += p.len;
            if (p.is_rst) {
                st.rst_count++;
            }
        } else if (p.proto == 17) {
            st.udp_packets++;
            st.udp_bytes += p.len;
        }

        port_counts[p.dst_port]++; 
    }

    // gather top 5 ports
    for (int k = 0; k < TOP_N; k++) {
        int best_port = 0;
        int best_hits = 0;
        for (int port = 1; port < 65536; port++) {
            if (port_counts[port] > best_hits) {
                best_hits = port_counts[port];
                best_port = port;
            }
        }
        st.top_ports[k] = best_port; // save top port
        st.top_port_counts[k] = best_hits;
        // check if valid
        if (best_port > 0) { 
            port_counts[best_port] = 0; // set to 0 to find another
        }
    }
    
    // set stats
    st.top_port = st.top_ports[0];
    st.top_port_hits = st.top_port_counts[0];

    // simple anomaly test
    if (st.rst_count > 20 || st.top_port_hits > 500) {
        st.suspicious_flag = 1;
    }

    return st;
}