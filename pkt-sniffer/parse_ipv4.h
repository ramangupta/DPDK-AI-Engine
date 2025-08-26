#ifndef PARSE_IPV4_H
#define PARSE_IPV4_H

#include <stdint.h>
#include <rte_ip.h>

// Handle IPv4 packet (already points past Ethernet header)
void handle_ipv4(const struct rte_ipv4_hdr *ip4, uint16_t rem);

#endif
