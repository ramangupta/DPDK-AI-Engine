#ifndef PARSE_ETH_H
#define PARSE_ETH_H

#include <stdint.h>
#include <rte_ether.h>
#include "engine/capture.h"

/* Entry point for parsing */
void parse_packet(pkt_view *pv_full);

#endif // PARSE_ETH_H