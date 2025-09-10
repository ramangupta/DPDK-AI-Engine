// capture.h
#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include "tunnel_types.h"
#include "debug.h"

extern int capture_port;

typedef enum {
    PV_KIND_STACK = 0,  // borrowed (owned by backend, e.g., static recv buffer)
    PV_KIND_HEAP  = 1,  // heap we allocated via capture_alloc()
    PV_KIND_MBUF  = 2,   // DPDK mbuf (owned by backend)
    PV_KIND_BORROWED = 3 // Borrowed such as in the case of capture_wrap
} pv_kind_t;

typedef struct pkt_view {
    const uint8_t   *data;
    uint16_t        len;
    bool            is_reassembled;
    char            src_ip[64];
    char            dst_ip[64];
    char            src_mac[32];
    char            dst_mac[32];
    uint16_t        src_port;
    uint16_t        dst_port;
    uint8_t         l4_proto;
    int             l3_proto;
    pv_kind_t       kind;
    void            *backing;

    // --- Tunnel metadata ---
    tunnel_info     tunnel;
    uint8_t         is_tunnel;
    uint8_t         tunnel_counted;
    struct pkt_view *inner_pkt;

    // --- New field for latency ---
    uint64_t        ts_ns;      // timestamp in nanoseconds
} pkt_view;

// Backend lifecycle
int capture_init(int argc, char **argv, const char *file);

pkt_view *capture_next(void);
void capture_release(pkt_view *pv);
void capture_close(void);

// For reassembly or any buffer you need to create
pkt_view* capture_alloc(size_t len); // returns heap-backed pkt_view
void capture_free(pkt_view *pv);


#ifdef USE_DPDK
#include <rte_mbuf.h>
pkt_view *capture_from_mbuf(struct rte_mbuf *mbuf);
#endif
