#ifndef PARSE_IPV6_H
#define PARSE_IPV6_H

#include <stdint.h>
#include <rte_ip.h>
#include "capture.h"

/* IPv6 parsing entry point */
void handle_ipv6(pkt_view *pv, uint64_t now);

#endif // PARSE_IPV6_H
