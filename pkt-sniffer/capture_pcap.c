#include "capture.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pcap_t *handle = NULL;

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
