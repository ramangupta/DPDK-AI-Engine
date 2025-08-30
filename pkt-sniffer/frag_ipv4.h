// frag_ipv4.h
#pragma once
#include <stdint.h>
#include <rte_ip.h>
#include "capture.h"   // pkt_view

struct rte_ipv6_frag_hdr {
    uint8_t  nexthdr;
    uint8_t  reserved;
    uint16_t fragment_offset; // upper 13 bits = offset, lower 3 = flags
    uint32_t identification;
} __attribute__((__packed__));

// Try to reassemble fragment
// Returns full packet (pkt_view*) if complete, NULL otherwise
pkt_view *frag_reass_ipv4(const struct rte_ipv4_hdr *ip4,
                          const pkt_view *frag,
                          uint64_t now);

/* New: expire old entries while running (optional) */
void frag_ipv4_gc(uint64_t now);

/* New: flush all incomplete entries at program exit */
void frag_ipv4_flush_all(void);

// IPv6
pkt_view *frag_reass_ipv6(const uint8_t *frag_hdr, 
                          const pkt_view *pv,
                          uint32_t frag_offset,
                          int mf,
                          uint64_t now);

void frag_ipv6_flush_all(void);
