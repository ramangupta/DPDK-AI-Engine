#include "capture.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

static pcap_t *handle;

#include <stdlib.h>
#include <string.h>
#include "capture.h"


int capture_init(const char *pcap_file) {

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
    return 0;
}

pkt_view *capture_next(void) {
    struct pcap_pkthdr *hdr;
    const u_char *data;
    int ret = pcap_next_ex(handle, &hdr, &data);
    if (ret <= 0) return NULL;

    return capture_wrap(data, hdr->caplen);
}

void capture_release(pkt_view *pv) {
    (void)pv;
}

void capture_close(void) {
    if (handle) pcap_close(handle);
}
