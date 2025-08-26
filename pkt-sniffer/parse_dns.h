#ifndef PARSE_DNS_H
#define PARSE_DNS_H
#include <stdint.h>

void parse_dns_udp(const uint8_t *payload, uint16_t len, int is_response);

#endif
