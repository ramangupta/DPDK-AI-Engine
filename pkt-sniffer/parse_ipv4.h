#ifndef PARSE_IPV4_H
#define PARSE_IPV4_H

#include <stdint.h>
#include <rte_ip.h>
#include "capture.h"

// Handle IPv4 packet (already points past Ethernet header)
void handle_ipv4(pkt_view *pv, uint64_t now);

#endif
