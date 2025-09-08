#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef USE_DPDK
#include <rte_mbuf.h>
#endif
#include "capture.h"

int capture_port = -1;

// malloc + copy (frag reassembly etc.)
pkt_view *capture_alloc(size_t len) {
    pkt_view *pv = malloc(sizeof(pkt_view));
    if (!pv) return NULL;

    uint8_t *buf = malloc(len);
    if (!buf) {
        free(pv);
        return NULL;
    }

    pv->data    = buf;
    pv->len     = len;
    pv->kind    = PV_KIND_HEAP;
    pv->backing = buf;
    return pv;
}

// wrap borrowed memory (AF_PACKET, pcap)
pkt_view *capture_wrap(const uint8_t *data, size_t len) {
    pkt_view *pv = malloc(sizeof(pkt_view));
    if (!pv) return NULL;

    pv->data    = data;
    pv->len     = len;
    pv->kind    = PV_KIND_BORROWED;
    pv->backing = NULL;
    pv->inner_pkt = NULL;

    return pv;
}

// Free a pkt_view and its resources (recursive for inner_pkt)
void capture_free(pkt_view *pv) {
    if (!pv) return;

    DEBUG_LOG(
        DBG_DPDK, "capture_free: pv=%p kind=%d data=%p len=%u inner_pkt=%p\n",
        (void*)pv, pv->kind, (void*)pv->data, (unsigned)pv->len,
        (void*)pv->inner_pkt);

    // Recursively free any inner packet
    if (pv->inner_pkt) {
        capture_free(pv->inner_pkt);
        pv->inner_pkt = NULL;
    }

    switch (pv->kind) {
        case PV_KIND_HEAP:
            if (pv->backing) {
                free(pv->backing);
                pv->backing = NULL;
            }
            break;

        case PV_KIND_MBUF:
#ifdef USE_DPDK
            if (pv->backing) {
                rte_pktmbuf_free((struct rte_mbuf *)pv->backing);
                pv->backing = NULL;
            }
#endif
             // free the wrapper, but not pv->data (points into mbuf)
            break;

        case PV_KIND_STACK:
            // do not free pv, it's stack-allocated
            break;

        case PV_KIND_BORROWED:
            // borrowed buffer (recv/pcap) → do not free pv->data
            break;

        default:
            // Unknown kind, just free pv as a fallback
            break;
    }

    free(pv);
}



