#ifndef PARSE_ETH_H
#define PARSE_ETH_H

#include <stdint.h>
#include <rte_ether.h>

/* Entry point for parsing */
void parse_packet(const uint8_t *data, uint16_t pktlen);

#endif // PARSE_ETH_H