#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "engine/capture.h"

static pcap_t *handle = NULL;
int capture_port = -1;

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

int capture_init(int argc, char **argv, const char *pcap_file) {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!pcap_file) {
        fprintf(stderr, "No pcap file specified!\n");
        return -1;
    }

    handle = pcap_open_offline(pcap_file, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
        return -1;
    }

    printf("pcap capture init: %s\n", pcap_file);
    return 0;
}

pkt_view *capture_next(void) {
    struct pcap_pkthdr *hdr;
    const u_char *data;

    int ret = pcap_next_ex(handle, &hdr, &data);

    if (ret == 1) {
        // normal packet
        return capture_wrap(data, hdr->caplen);
    } else if (ret == -2) {
        // EOF
        return NULL;
    } else if (ret == 0) {
        // 0 = timeout (only for live pcap)
        return NULL;
    } else {
        // ret < 0 = error
        fprintf(stderr, "pcap_next_ex error\n");
        return NULL;
    }
}

void capture_release(pkt_view *pv) {
    if (!pv) return;

    if (pv->kind == PV_KIND_HEAP && pv->backing) {
        free(pv->backing);
        pv->backing = NULL;
    }
    free(pv);   // free pkt_view itself
}

void capture_close(void) {
    if (handle) {
        pcap_close(handle);
        handle = NULL;
    }
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