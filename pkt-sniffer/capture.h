// capture.h
#pragma once
#include <stdint.h>
#include <stddef.h>

typedef enum {
    PV_KIND_STACK = 0,  // borrowed (owned by backend, e.g., static recv buffer)
    PV_KIND_HEAP  = 1,  // heap we allocated via capture_alloc()
    PV_KIND_MBUF  = 2   // DPDK mbuf (owned by backend)
} pv_kind_t;

typedef struct pkt_view {
    const uint8_t   *data;     // pointer to contiguous L2/L3 data
    uint16_t   len;      // valid length
    char     src_ip[64];
    char     dst_ip[64];
    char     src_mac[32];   // NEW
    char     dst_mac[32];   // NEW
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t l4_proto;        // e.g. IPPROTO_TCP, UDP, ICMP
    int l3_proto;            // AF_INET, AF_INET6, ETH_P_ARP
    pv_kind_t  kind;     // how to free
    void      *backing;  // heap ptr or rte_mbuf*
} pkt_view;

// Backend lifecycle
int  capture_init(const char *pcap_file);
pkt_view *capture_next(void);
void capture_release(pkt_view *pv);
void capture_close(void);

// For reassembly or any buffer you need to create
pkt_view* capture_alloc(size_t len); // returns heap-backed pkt_view
pkt_view *capture_wrap(const uint8_t *data, size_t len);
void capture_free(pkt_view *pv);

#ifdef USE_DPDK
#include <rte_mbuf.h>
pkt_view *capture_from_mbuf(struct rte_mbuf *mbuf);
#endif
