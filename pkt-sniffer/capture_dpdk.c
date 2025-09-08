// capture_dpdk.c — NIC bound to vfio-pci (kernel-bypass) or vdev (e.g., TAP)
// Uses the unified pkt_view API.

// capture_dpdk.c
#include "capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE     256
#define NUM_MBUFS        8191
#define MBUF_CACHE_SIZE  250
#define BURST_SIZE       32

static int burst_idx = 0;
static int burst_count = 0;
static pkt_view *pv_burst[BURST_SIZE];
static struct rte_mempool *mbuf_pool = NULL;
static uint16_t active_port = RTE_MAX_ETHPORTS;
static struct rte_mbuf *mbuf_burst[BURST_SIZE];


#if 0
/* Thin wrapper for future use in case if required */
int capture_next_batch(pkt_view **out, int max) {
    int count = 0;
    pkt_view *pv;

    while (count < max && (pv = capture_next()) != NULL) {
        out[count++] = pv;
    }
    return count;
}
#endif

int capture_init(int argc, char **argv, const char *file) 
{
    if (rte_eal_init(argc, argv) < 0) {
        fprintf(stderr, "EAL init failed\n");
        return -1;
    }

    unsigned nb_ports = rte_eth_dev_count_avail();
    DEBUG_LOG(DBG_DPDK, "DPDK reports %u available ports\n", nb_ports);
    if (nb_ports == 0) {
        printf("No DPDK ports available (did you pass --vdev?).\n");
        return -1;
    }

    RTE_ETH_FOREACH_DEV(active_port) {
        DEBUG_LOG(DBG_DPDK, "Found DPDK port %u\n", active_port);
        break;
    }
    if (active_port == RTE_MAX_ETHPORTS) {
        printf("No usable ports found\n");
        return -1;
    }

    capture_port = active_port;

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
        NUM_MBUFS, MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        printf("mbuf_pool create failed\n");
        return -1;
    }

    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));

    if (rte_eth_dev_configure(active_port, 1, 1, &port_conf) < 0) {
        printf("dev_configure failed\n");
        return -1;
    }

    if (rte_eth_rx_queue_setup(active_port, 0, RX_RING_SIZE,
                               rte_eth_dev_socket_id(active_port),
                               NULL, mbuf_pool) < 0) {
        printf("rx_queue_setup failed\n");
        return -1;
    }

    if (rte_eth_tx_queue_setup(active_port, 0, RX_RING_SIZE,
                               rte_eth_dev_socket_id(active_port),
                               NULL) < 0) {
        printf("tx_queue_setup failed\n");
        return -1;
    }

    if (rte_eth_dev_start(active_port) < 0) {
        printf("dev_start failed\n");
        return -1;
    }

    DEBUG_LOG(DBG_DPDK, "DPDK init success on port %u!\n", active_port);
    return 0;
}

#ifdef USE_DPDK
// Zero-copy wrapper around DPDK mbuf
pkt_view *capture_from_mbuf(struct rte_mbuf *mbuf) {
    pkt_view *pv = calloc(1, sizeof(pkt_view));
    if (!pv) return NULL;

    pv->data = rte_pktmbuf_mtod(mbuf, uint8_t *);   // point directly into mbuf data
    pv->len  = rte_pktmbuf_pkt_len(mbuf);           // total packet length
    pv->kind = PV_KIND_MBUF;                        // mark as mbuf-backed
    pv->backing = mbuf;                             // remember mbuf for freeing later
    pv->inner_pkt = NULL;

    DEBUG_LOG(DBG_DPDK, "pkt_view=%p from mbuf=%p pkt_len=%u\n",
        (void*)pv, (void*)mbuf, pv->len);

    return pv;
}
#endif

// Returns a heap-allocated array of pkt_view* and sets batch count.
// Caller MUST free the returned array with free() after processing
// and must call capture_free() on each pkt_view.

pkt_view *capture_next(void) {

    // If current batch exhausted, fetch new burst
    if (burst_idx >= burst_count) {
        burst_count = rte_eth_rx_burst(active_port, 0, mbuf_burst, BURST_SIZE);
        burst_idx = 0;
        if (burst_count == 0) {
            return NULL;
        }
   

        // Wrap mbufs in pkt_view (zero-copy)
        for (int i = 0; i < burst_count; i++) {
            pv_burst[i] = capture_from_mbuf(mbuf_burst[i]);
            // Do NOT free mbuf here; ownership is in pkt_view
        }
    }

    // Prefetch the next packet in burst if there is one
    if (burst_idx + 1 < burst_count) {
        rte_prefetch0(pv_burst[burst_idx + 1]->data);
        rte_prefetch0(pv_burst[burst_idx + 1]->backing);
    }

    return pv_burst[burst_idx++];  // return current packet  
}

void capture_close(void) {
    rte_eth_dev_stop(active_port);
    rte_eth_dev_close(active_port);
}

// Release only the backing buffer, not the pv wrapper itself
// Used in reassembly flows where pv may still be referenced.
void capture_release(pkt_view *pv) {
    if (!pv) return;

    switch (pv->kind) {
        case PV_KIND_MBUF:
#ifdef USE_DPDK
            if (pv->backing) {
                rte_pktmbuf_free((struct rte_mbuf *)pv->backing);
                pv->backing = NULL;
            }
#endif
            break;

        case PV_KIND_HEAP:
            if (pv->backing) {
                free(pv->backing);
                pv->backing = NULL;
            }
            // Note: pv->data may point to backing or not. 
            // Do NOT free pv or pv->data here.
            break;

        case PV_KIND_STACK:
        default:
            // nothing to do
            break;
    }

    free(pv);
}


#if 0
// For now, keep reassembly allocations simple: heap.
// (We can optimize later to allocate mbufs and append)
pkt_view* capture_alloc(size_t len) {
    pkt_view *p = (pkt_view*)malloc(sizeof(pkt_view));
    if (!p) return NULL;
    void *buf = malloc(len);
    if (!buf) { free(p); return NULL; }

    p->data    = (uint8_t*)buf;
    p->len     = (uint16_t)len;
    p->kind    = PV_KIND_HEAP;
    p->backing = buf;
    return p;
}
#endif
