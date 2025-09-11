#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include "engine/capture.h"


void print_icmpv6_addr(const uint8_t a[16]);
void print_mac_flow(const uint8_t *m, const uint8_t *n);
void print_ip_flow(uint32_t src_be_addr, uint32_t dst_be_addr);
void print_ipv6_flow(const uint8_t src[16], const uint8_t dst[16]);
void pkt_view_dump(const pkt_view *pv);

void format_bandwidth(double bps, char *buf, size_t buflen);
#endif