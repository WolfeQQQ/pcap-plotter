#ifndef READER_H
#define READER_H

#include "shared.h"

int read_pcap(const char *filename, SimplePacket *out_packets, int max_packets);

#endif