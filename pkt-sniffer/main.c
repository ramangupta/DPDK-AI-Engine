#include <stdio.h>
#include <stdint.h>
#include "capture.h"
#include "tsc.h"
#include "parse_eth.h"
#include "stats.h"
#include "frag_ipv4.h"
#include "cli.h"
#include "filter.h"
#include "talkers.h"
#include "pcap_writer.h"
#include "sniffer_signal.h"
#include "utils.h"

// Main packet processing loop
int main(int argc, char **argv) 
{
    pkt_view *pv = NULL;
    filter_pktview_t fpv;
    const char *pcap_file = NULL;

    cli_parse(argc, argv);
    setup_signal_handlers();

    if (pcap_writer_init() != 0) {
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pcap") == 0 && i + 1 < argc) {
            pcap_file = argv[++i];
        }
    }

    if (capture_init(pcap_file) != 0) {
        fprintf(stderr, "Failed to init capture\n");
        return 1;
    }

    while ((pv = capture_next()) != NULL) {
        uint64_t now = now_tsc();
        if (extract_minimal_headers(&fpv, pv->data, pv->len) == 0) {
            if (filter_match(&fpv)) {

                // Parse the packet (this may do frag/reassembly internally)
                parse_packet(pv, now);

                // Just for extreme debugging ...
                // pkt_view_dump(pv);

                /* Top Talkers Update */ 
                talkers_update(pv);

                // Update stats/talkers
                stats_poll();

                pcap_writer_write(pv->data, pv->len);
            }
        }
        // Always free/release the packet view (whether frag, heap, or mbuf)
        capture_free(pv);
        pv = NULL;
    }

    // After processing all packets from the PCAP:
    frag_ipv4_flush_all();
    frag_ipv6_flush_all();
    fflush(stdout);
    fflush(stderr);
    capture_close();
    pcap_writer_close();
    return 0;
}
