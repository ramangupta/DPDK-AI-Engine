#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifdef USE_DPDK
#include <rte_mbuf.h>
#endif
#include "capture.h"

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
    pv->kind    = PV_KIND_STACK;
    pv->backing = NULL;
    return pv;
}

#ifdef USE_DPDK
// wrap DPDK mbuf
pkt_view *capture_from_mbuf(struct rte_mbuf *mbuf) {
    pkt_view *pv = malloc(sizeof(pkt_view));
    if (!pv) return NULL;

    pv->data    = rte_pktmbuf_mtod(mbuf, const uint8_t *);
    pv->len     = rte_pktmbuf_pkt_len(mbuf);
    pv->kind    = PV_KIND_MBUF;
    pv->backing = mbuf;
    return pv;
}
#endif

// free correctly (recursive)
void capture_free(pkt_view *pv) {
    if (!pv) return;

    // free any inner packet first
    if (pv->inner_pkt) {
        capture_free(pv->inner_pkt);
        pv->inner_pkt = NULL;
    }

    switch (pv->kind) {
        case PV_KIND_HEAP:
            free(pv->backing);
            break;
        case PV_KIND_MBUF:
        #ifdef USE_DPDK
            rte_pktmbuf_free((struct rte_mbuf *)pv->backing);
        #endif
            break;
        case PV_KIND_STACK:
        default:
            break; // nothing to free
    }
    free(pv);
}

