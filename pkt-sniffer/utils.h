#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include "capture.h"

void print_mac(const uint8_t *m);
void print_ipv4(uint32_t be_addr);
void print_ipv6_addr(const uint8_t a[16]);
void pkt_view_dump(const pkt_view *pv);

void format_bandwidth(double bps, char *buf, size_t buflen);
#endif