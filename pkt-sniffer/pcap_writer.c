#include <pcap.h>
#include <stdio.h>
#include "capture.h"
#include "filter.h"   // for g_filters

static pcap_t *dead_handle = NULL;
static pcap_dumper_t *dumper = NULL;

int pcap_writer_init(void) {
    if (!g_filters.write_pcap) return 0;

    dead_handle = pcap_open_dead(DLT_EN10MB, 65535);  // Ethernet, snapshot len
    if (!dead_handle) {
        fprintf(stderr, "pcap_open_dead failed\n");
        return -1;
    }

    dumper = pcap_dump_open(dead_handle, g_filters.write_file);
    printf("RAMAN : pcap file %s \n", g_filters.write_file);
    if (!dumper) {
        fprintf(stderr, "pcap_dump_open failed: %s\n", pcap_geterr(dead_handle));
        return -1;
    }
    return 0;
}

void pcap_writer_write(const uint8_t *data, size_t len) {

    if (!dumper) return;

    struct pcap_pkthdr hdr;
    gettimeofday(&hdr.ts, NULL);  // wallclock timestamp
    hdr.caplen = len;
    hdr.len    = len;

    pcap_dump((u_char *)dumper, &hdr, data);
    pcap_dump_flush(dumper);  // force flush to disk
}

void pcap_writer_close(void) {
    if (dumper) {
        pcap_dump_flush(dumper);   // ensure buffer is written
        pcap_dump_close(dumper);
        dumper = NULL;
    }
    if (dead_handle) {
        pcap_close(dead_handle);
        dead_handle = NULL;
    }
}
