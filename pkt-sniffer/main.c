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
#include "time.h"
#include "debug.h"

static inline double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

#define DBG_PARSER    (1 << 0)
#define DBG_TCP_REASS (1 << 1)
#define DBG_L4        (1 << 2)
#define DBG_IP        (1 << 3)
#define DBG_ETH       (1 << 4)
#define DBG_TCP       (1 << 5)
#define DBG_UDP       (1 << 6)
#define DBG_HTTP      (1 << 7)
#define DBG_DNS       (1 << 8)
#define DBG_DHCP      (1 << 9)
#define DBG_ARP       (1 << 10)
#define DBG_IPFRAG    (1 << 11)

// Main packet processing loop
int main(int argc, char **argv) 
{
    pkt_view *pv = NULL;
    filter_pktview_t fpv;
    uint64_t count = 0;
    double t_start = now_sec();

#if 0
    DEBUG_MASK = DBG_PARSER | DBG_ETH | DBG_TCP_REASS | DBG_ARP | DBG_DHCP | DBG_HTTP |
                 DBG_IP | DBG_IPFRAG | DBG_L4 | DBG_TCP | DBG_UDP | DBG_DNS;
#endif

    DEBUG_MASK = DBG_PARSER;
    
    cli_parse(argc, argv);
    setup_signal_handlers();
    tcp_reass_init();

    if (pcap_writer_init() != 0) {
        return 1;
    }

    if (capture_init(argc, argv, g_filters.read_pcap ? g_filters.read_file : NULL) != 0) {
        fprintf(stderr, "Failed to init capture\n");
        return 1;
    }


    while ((pv = capture_next()) != NULL) {
        count++;
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

                if (g_filters.write_pcap) {
                    pcap_writer_write(pv->data, pv->len);
                   // Optionally, write inner payload separately
                    if (pv->is_tunnel && pv->inner_pkt) {
                        // You can adapt pcap_writer_write() to accept a label or new file
                        pcap_writer_write((const uint8_t *)pv->inner_pkt->data, pv->inner_pkt->len);
                    }
                }
            }
        }
        // Always free/release the packet view (whether frag, heap, or mbuf)
        capture_free(pv);
        pv = NULL;
    }

    double t_end = now_sec();
    double duration = t_end - t_start;
    double pps = count / duration;

    printf("Processed %lu packets in %.3f sec -> %.2f PPS\n",
           count, duration, pps);
           
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
