#ifndef STATS_H
#define STATS_H

#include <stdint.h>

#define REPORT_INTERVAL 5


// Enum for protocol classification
enum proto_type {
    PROTO_NONE,
    PROTO_IPV4,
    PROTO_IPV6,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_DNS
};

// Define stats structure
struct stats {
    uint64_t ipv4;
    uint64_t ipv6;
    uint64_t tcp;
    uint64_t udp;
    uint64_t icmp;
    uint64_t dns;
};

// Function prototypes

void stats_update(enum proto_type p, uint16_t pktlen);
void stats_poll(void);   // <--- new
void stats_report(void); // prints only

#endif
