#ifndef ANALYZER_H
#define ANALYZER_H

#include "shared.h"

Stats analyze_packets(const SimplePacket *packets, int count);

#endif