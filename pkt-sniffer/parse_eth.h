#ifndef PARSE_ETH_H
#define PARSE_ETH_H

#include <stdint.h>
#include <rte_ether.h>

/* Entry point for parsing */
void parse_packet(pkt_view *pv, uint64_t now_tsc);

#endif // PARSE_ETH_H