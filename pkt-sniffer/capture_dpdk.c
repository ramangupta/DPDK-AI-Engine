// works with NIC bound to vfio-pci (kernel bypass)

// capture_dpdk.c
#include "capture.h"
#include <stdio.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 128
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 1
#define PORT_ID 0

static struct rte_mempool *mbuf_pool = NULL;

int capture_init(void) {
    int argc = 1;
    char *argv[] = {"dpdk-capture"};
    if (rte_eal_init(argc, argv) < 0) {
        fprintf(stderr, "Error with EAL init\n");
        return -1;
    }

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL) {
        fprintf(stderr, "Cannot create mbuf pool\n");
        return -1;
    }

    struct rte_eth_conf port_conf = {0};
    if (rte_eth_dev_configure(PORT_ID, 1, 1, &port_conf) < 0) {
        fprintf(stderr, "Cannot configure port\n");
        return -1;
    }

    if (rte_eth_rx_queue_setup(PORT_ID, 0, RX_RING_SIZE,
        rte_eth_dev_socket_id(PORT_ID), NULL, mbuf_pool) < 0) {
        fprintf(stderr, "RX queue setup failed\n");
        return -1;
    }

    if (rte_eth_dev_start(PORT_ID) < 0) {
        fprintf(stderr, "Cannot start port\n");
        return -1;
    }

    return 0;
}

int capture_next(uint8_t *buf, uint16_t buflen) {
    struct rte_mbuf *pkts[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(PORT_ID, 0, pkts, BURST_SIZE);
    if (nb_rx == 0) return -1;

    struct rte_mbuf *m = pkts[0];
    uint16_t pktlen = rte_pktmbuf_pkt_len(m);
    if (pktlen > buflen) pktlen = buflen;

    rte_pktmbuf_read(m, 0, pktlen, buf);
    rte_pktmbuf_free(m);
    return pktlen;
}

void capture_close(void) {
    rte_eth_dev_stop(PORT_ID);
    rte_eth_dev_close(PORT_ID);
}
