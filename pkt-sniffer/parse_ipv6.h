#ifndef PARSE_IPV6_H
#define PARSE_IPV6_H

#include <stdint.h>
#include <rte_ip.h>

/* IPv6 parsing entry point */
void handle_ipv6(const struct rte_ipv6_hdr *ip6, uint16_t pkt_len);

#endif // PARSE_IPV6_H
