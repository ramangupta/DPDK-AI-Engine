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
#include "tcp_reass.h"
#include "parse_tunnel.h"

// Main packet processing loop
int main(int argc, char **argv) 
{
    pkt_view *pv = NULL;
    filter_pktview_t fpv;

    cli_parse(argc, argv);
    setup_signal_handlers();
    tcp_reass_init();

    if (pcap_writer_init() != 0) {
        return 1;
    }

    if (capture_init(g_filters.read_pcap ? g_filters.read_file : NULL) != 0) {
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
                if (pv->is_tunnel && pv->inner_pkt) {
                    // Print tunnel metadata for debugging / top talkers
                    switch (pv->tunnel.type) {
                        case TUNNEL_GRE:
                            printf("[TOP] GRE tunnel: inner_proto=0x%04x flags=0x%04x len=%u\n",
                                pv->tunnel.inner_proto, pv->tunnel.gre_flags, pv->inner_pkt->len);
                            break;
                        case TUNNEL_VXLAN:
                            printf("[TOP] VXLAN tunnel: VNI=%u len=%u\n",
                                pv->tunnel.vni, pv->inner_pkt->len);
                            break;
                        case TUNNEL_GENEVE:
                            printf("[TOP] GENEVE tunnel: VNI=%u len=%u\n",
                                pv->tunnel.vni, pv->inner_pkt->len);
                            break;
                        default:
                            break;
                    }

                    // Update top talkers using inner packet if desired
                    talkers_update(pv->inner_pkt ? pv->inner_pkt : pv);
                }
                /* Top Talkers Update */ 
                talkers_update(pv);

                // Update stats/talkers
                stats_poll(now);

                pcap_writer_write(pv->data, pv->len);

                // Optionally, write inner payload separately
                if (pv->is_tunnel && pv->inner_pkt) {
                    // You can adapt pcap_writer_write() to accept a label or new file
                    pcap_writer_write((const uint8_t *)pv->inner_pkt, pv->inner_pkt->len);
                }
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
    tcp_reass_fini();
    return 0;
}
