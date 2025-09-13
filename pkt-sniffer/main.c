// main.c

// Standard / system
#include <stdio.h>
#include <stdint.h>

// Project headers
#include "tsc.h"
#include "engine/capture.h"

#include "parsers/parse_eth.h"
#include "parsers/frag_ipv4.h"
#include "parsers/tcp_reass.h"
#include "parsers/parse_tunnel.h"

#include "stats/stats.h"

#include "cli.h"
#include "utils/filter.h"
#include "utils/talkers.h"
#include "utils/pcap_writer.h"
#include "utils/sniffer_signal.h"
#include "utils/utils.h"
#include "utils/debug.h"


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


static int app_init(int argc, char **argv) {

    cli_parse(argc, argv);
    setup_signal_handlers();
    frag_reass_ipv6_init();
    tcp_reass_init();

    if (pcap_writer_init() != 0) {
        return -1;
    }

    if (capture_init(argc, argv,
                     g_filters.read_pcap ? g_filters.read_file : NULL) != 0) {
        fprintf(stderr, "Failed to init capture\n");
        return -1;
    }

    perf_init();
    perf_start();

    return 0;
}

static void app_loop(void) {
    pkt_view *pv = NULL;
    filter_pktview_t fpv;

    while ((pv = capture_next()) != NULL) {
        pv->ts_ns = now_tsc();   // stamp arrival time immediately

        if (extract_minimal_headers(&fpv, pv->data, pv->len) == 0) {
            if (filter_match(&fpv)) {

                // Parse the packet
                parse_packet(pv);

                // Latency: time spent in parsing + processing
                uint64_t latency_ns = now_tsc() - pv->ts_ns;
                perf_update(pv->len, latency_ns);

                // Update talkers and stats
                if (pv->is_tunnel && pv->inner_pkt) {
                    talkers_update(pv->inner_pkt);
                }
                talkers_update(pv);

                stats_poll();

                if (g_filters.write_pcap) {
                    pcap_writer_write(pv->data, pv->len);
                    if (pv->is_tunnel && pv->inner_pkt) {
                        pcap_writer_write((const uint8_t *)pv->inner_pkt->data,
                                          pv->inner_pkt->len);
                    }
                }
            } else {
                global_stats.drop_filter_miss++;
                global_stats.dropped++;
                capture_free(pv);
                continue;
            }
        } else {
            global_stats.drop_filter_miss++;
            global_stats.dropped++;
            capture_free(pv);
            continue;
        }

        capture_free(pv);
        pv = NULL;
    }
}

static void app_cleanup(void) {
    perf_stop();

    // Final stats + perf report
    stats_report_final();

    frag_ipv4_flush_all();
    frag_ipv6_flush_all();

    fflush(stdout);
    fflush(stderr);

    capture_close();
    pcap_writer_close();
    tcp_reass_fini();
}

// Main packet processing loop
int main(int argc, char **argv) {
    if (app_init(argc, argv) != 0) {
        return EXIT_FAILURE;
    }

    DEBUG_MASK = DBG_PARSER | DBG_TCP | DBG_TCP_REASS; 

    app_loop();

    app_cleanup();

    return EXIT_SUCCESS;
}