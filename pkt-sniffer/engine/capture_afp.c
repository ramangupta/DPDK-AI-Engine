// Works on Wi-Fi, any NIC
// capture_afp.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "engine/capture.h"

static int sock_fd = -1;
int capture_port = -1;

// a reusable receive buffer; parse happens before next recv, so it's safe
static uint8_t rx_buf[2048];

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

int capture_init(int argc, char **argv, const char *file) {
    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        perror("socket(AF_PACKET)");
        return -1;
    }
    return 0;
}

pkt_view *capture_next(void) {
    ssize_t n = recv(sock_fd, rx_buf, sizeof(rx_buf), 0);
    if (n < 0) {
        perror("recv(AF_PACKET)");
        return NULL;
    }
    if (n == 0) return NULL;

    return capture_wrap(rx_buf, n);
}

void capture_close(void) {
    if (sock_fd >= 0) close(sock_fd);
    sock_fd = -1;
}

void capture_release(pkt_view *pv) {
    if (!pv) return;
    if (pv->kind == PV_KIND_HEAP) {
        free(pv->backing);     // data buffer
        free(pv);              // pkt_view itself
    }
    // PV_KIND_STACK: nothing to do
    // PV_KIND_MBUF: not used in AFP backend
}

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

// Free a pkt_view and its resources (recursive for inner_pkt)
// Free a pkt_view and its resources (recursive for inner_pkt)
void capture_free(pkt_view *pv) {
    if (!pv) return;

    DEBUG_LOG(DBG_DPDK,
        "capture_free: pv=%p kind=%d data=%p len=%u inner_pkt=%p\n",
        (void*)pv, pv->kind, (void*)pv->data,
        (unsigned)pv->len, (void*)pv->inner_pkt);

    // Recursively free inner packet if present
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
        free(pv);  // wrapper is heap-allocated
        break;

    case PV_KIND_MBUF:
#ifdef USE_DPDK
        if (pv->backing) {
            rte_pktmbuf_free((struct rte_mbuf *)pv->backing);
            pv->backing = NULL;
        }
#endif
        free(pv);  // wrapper was calloc()’d in capture_from_mbuf
        break;

    case PV_KIND_STACK:
        // nothing to free — wrapper is stack memory
        break;

    case PV_KIND_BORROWED:
        // borrowed buffer — don’t free wrapper or data
        free(pv);
        break;

    default:
        // unknown kind — safest is to free wrapper
        free(pv);
        break;
    }
}