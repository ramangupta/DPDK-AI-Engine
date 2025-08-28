#include <stdio.h>
#include <stdint.h>
#include "capture.h"
#include "tsc.h"
#include "parse_eth.h"
#include "stats.h"
#include "frag_ipv4.h"

// Main packet processing loop
int main(int argc, char **argv) {
    
    const char *pcap_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pcap") == 0 && i + 1 < argc) {
            pcap_file = argv[++i];
        }
    }

    if (capture_init(pcap_file) != 0) {
        fprintf(stderr, "Failed to init capture\n");
        return 1;
    }

    pkt_view *pv = NULL;

    while ((pv = capture_next()) != NULL) {
        uint64_t now = now_tsc();

        // Parse the packet (this may do frag/reassembly internally)
        parse_packet(pv, now);

        // Update stats/talkers
        stats_poll();

        // Always free/release the packet view (whether frag, heap, or mbuf)
        capture_free(pv);
        pv = NULL;
    }

    // After processing all packets from the PCAP:
    frag_ipv4_flush_all();
    fflush(stdout);
    fflush(stderr);
    capture_close();
    return 0;
}
