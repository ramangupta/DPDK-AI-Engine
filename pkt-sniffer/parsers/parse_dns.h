#ifndef PARSE_DNS_H
#define PARSE_DNS_H
#include <stdint.h>

const char* rcode_str(int rcode);

// DNS header (12 bytes)
struct dns_hdr {
    uint16_t id, flags, qdcount, ancount, nscount, arcount;
} __attribute__((__packed__));

void parse_dns_udp(const uint8_t *payload, uint16_t len, int is_response, uint64_t now);

#endif
