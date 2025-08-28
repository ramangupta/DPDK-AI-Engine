// capture_dpdk.c — NIC bound to vfio-pci (kernel-bypass) or vdev (e.g., TAP)
// Uses the unified pkt_view API.

// capture_dpdk.c
#include "capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE     256
#define NUM_MBUFS        8191
#define MBUF_CACHE_SIZE  250
#define BURST_SIZE       1
#define PORT_ID          0

static struct rte_mempool *mbuf_pool = NULL;

int capture_init(const char *file) {
    int argc = 1;
    char *argv[] = { (char*)"dpdk-capture" };
    if (rte_eal_init(argc, argv) < 0) {
        fprintf(stderr, "EAL init failed\n");
        return -1;
    }

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
        NUM_MBUFS, MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        fprintf(stderr, "mbuf_pool create failed\n");
        return -1;
    }

    struct rte_eth_conf port_conf = {0};
    if (rte_eth_dev_configure(PORT_ID, 1, 0, &port_conf) < 0) {
        fprintf(stderr, "dev_configure failed\n");
        return -1;
    }

    if (rte_eth_rx_queue_setup(PORT_ID, 0, RX_RING_SIZE,
                               rte_eth_dev_socket_id(PORT_ID),
                               NULL, mbuf_pool) < 0) {
        fprintf(stderr, "rx_queue_setup failed\n");
        return -1;
    }

    if (rte_eth_dev_start(PORT_ID) < 0) {
        fprintf(stderr, "dev_start failed\n");
        return -1;
    }
    return 0;
}

pkt_view *capture_next(void) {
    struct rte_mbuf *m;
    uint16_t n = rte_eth_rx_burst(PORT_ID, 0, &m, BURST_SIZE);
    if (n == 0) return NULL;

    return capture_from_mbuf(mbuf);
}

void capture_close(void) {
    rte_eth_dev_stop(PORT_ID);
    rte_eth_dev_close(PORT_ID);
}

void capture_release(pkt_view *pv) {
    if (!pv) return;
    if (pv->kind == PV_KIND_MBUF && pv->backing) {
        rte_pktmbuf_free((struct rte_mbuf*)pv->backing);
        pv->backing = NULL;
    } else if (pv->kind == PV_KIND_HEAP) {
        free(pv->backing);
        free(pv);
    }
    // PV_KIND_STACK: not used in DPDK backend
}

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
