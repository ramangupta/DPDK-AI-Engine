#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "stats.h"
#include "talkers.h"

struct stats global_stats = {0};
static uint64_t total_pkts = 0;
static uint64_t total_bytes = 0;
static time_t last_report = 0;

void stats_update(enum proto_type p, uint16_t pktlen) {
    switch (p) {
    case PROTO_IPV4: global_stats.ipv4++; break;
    case PROTO_IPV6: global_stats.ipv6++; break;
    case PROTO_TCP:  global_stats.tcp++;  break;
    case PROTO_UDP:  global_stats.udp++;  break;
    case PROTO_ICMP: global_stats.icmp++; break;
    case PROTO_DNS:  global_stats.dns++;  break;
    default: break;
    }

    total_pkts++;
    total_bytes += pktlen;
}

void stats_poll(void) {
    time_t now = time(NULL);
    if (last_report == 0) {
        last_report = now;
        return;
    }

    if (now - last_report >= REPORT_INTERVAL) {
        stats_report();
        last_report = now;
    }
}

void stats_report(void) {
    uint64_t pkt_sum = global_stats.ipv4 + global_stats.ipv6 +
                       global_stats.tcp + global_stats.udp +
                       global_stats.icmp + global_stats.dns;

    double pps = (pkt_sum * 1.0) / REPORT_INTERVAL;
    double bps = (total_bytes * 1.0) / REPORT_INTERVAL;

    printf("\n=== Packet Summary (last %d s) ===\n", REPORT_INTERVAL);
    printf("Total=%lu (%.1f pkts/sec) Bandwidth=%.2f KB/s\n",
           pkt_sum, pps, bps / 1024.0);
    printf("IPv4=%lu  IPv6=%lu  TCP=%lu  UDP=%lu  ICMP=%lu  DNS=%lu\n",
           global_stats.ipv4, global_stats.ipv6,
           global_stats.tcp, global_stats.udp,
           global_stats.icmp, global_stats.dns);

    printf("Cumulative: pkts=%lu bytes=%lu\n", total_pkts, total_bytes);

    // Reset interval counters
    global_stats.ipv4 = global_stats.ipv6 = global_stats.tcp =
    global_stats.udp = global_stats.icmp = global_stats.dns = 0;
    total_bytes = 0;

    talkers_sort_mode = SORT_BY_BYTES; 
    talkers_report();
    talkers_reset();
}
