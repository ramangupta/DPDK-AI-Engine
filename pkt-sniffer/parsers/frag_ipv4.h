// frag_ipv4.h
#pragma once
#include <stdint.h>
#include <rte_ip.h>
#include <stdatomic.h>
#include "engine/capture.h"   // for pkt_view
#include "stats/stats.h"

// timeouts in nanoseconds
#define FRAG_V4_TIMEOUT_NS (30ULL * 1000000000ULL)  /* 30s for IPv4 */


// counts reclaimed stale fragment sets
extern atomic_ulong ipv6_frag_timeouts;

struct rte_ipv6_frag_hdr {
    uint8_t  nexthdr;
    uint8_t  reserved;
    uint16_t fragment_offset; // upper 13 bits = offset, lower 3 = flags
    uint32_t identification;
} __attribute__((__packed__));

void frag_reass_ipv6_init(void);
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
                          uint64_t now);

void frag_ipv6_flush_all(void);

void frag_ipv4_flush_stale(uint64_t now);
void frag_ipv6_flush_stale(uint64_t now);
