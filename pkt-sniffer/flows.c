/* 
 * Since DPDK can run multiple RX queues per core, if you later run multi-core, 
 * you’ll want per-core flow tables or locks. For now, single-thread is fine.
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include "flows.h"   // where we’ll put flow_key_t, flow_update(), etc.
#include "tsc.h"
#include "utils.h"

flow_entry_t flow_table[FLOW_MAX];
int flow_count;

void flow_key_build(flow_key_t *key,
                    int ip_version,
                    const char *src_ip,
                    const char *dst_ip,
                    uint8_t proto,
                    uint16_t src_port,
                    uint16_t dst_port)
{
    memset(key, 0, sizeof(*key));

    key->ip_version = ip_version;
    key->proto = proto;
    key->src_port = src_port;
    key->dst_port = dst_port;

    if (ip_version == 4) {
        inet_pton(AF_INET, src_ip, key->src_ip);   // writes 4 bytes
        inet_pton(AF_INET, dst_ip, key->dst_ip);
    } else if (ip_version == 6) {
        inet_pton(AF_INET6, src_ip, key->src_ip);  // writes 16 bytes
        inet_pton(AF_INET6, dst_ip, key->dst_ip);
    }
}


static const char* proto_name(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_ICMPV6: return "ICMPv6";
        default: return "?";
    }
}

void flow_report(void) {
    printf("\n=== Flow Stats ===\n");

    for (int i = 0; i < flow_count; i++) {
        if (!flow_table[i].in_use) continue;

        char src[64], dst[64];
        if (flow_table[i].key.ip_version == 4) {
            inet_ntop(AF_INET, flow_table[i].key.src_ip, src, sizeof(src));
            inet_ntop(AF_INET, flow_table[i].key.dst_ip, dst, sizeof(dst));
        } else {
            inet_ntop(AF_INET6, flow_table[i].key.src_ip, src, sizeof(src));
            inet_ntop(AF_INET6, flow_table[i].key.dst_ip, dst, sizeof(dst));
        }

        // append ports for TCP/UDP
        char src_full[80], dst_full[80];
        if (flow_table[i].key.proto == IPPROTO_TCP || flow_table[i].key.proto == IPPROTO_UDP) {
            snprintf(src_full, sizeof(src_full), "%s:%u", src, flow_table[i].key.src_port);
            snprintf(dst_full, sizeof(dst_full), "%s:%u", dst, flow_table[i].key.dst_port);
        } else {
            snprintf(src_full, sizeof(src_full), "%s", src);
            snprintf(dst_full, sizeof(dst_full), "%s", dst);
        }

        uint64_t first = flow_table[i].first_seen;
        uint64_t last  = flow_table[i].last_seen;
        uint64_t dur_ns = (last > first) ? (last - first) : 0;

        // format duration
        char dur_str[32];
        if (dur_ns < 1000ULL) {
            snprintf(dur_str, sizeof(dur_str), "%lu ns", dur_ns);
        } else if (dur_ns < 1000000ULL) {
            snprintf(dur_str, sizeof(dur_str), "%.3f µs", dur_ns / 1000.0);
        } else if (dur_ns < 1000000000ULL) {
            snprintf(dur_str, sizeof(dur_str), "%.3f ms", dur_ns / 1e6);
        } else {
            snprintf(dur_str, sizeof(dur_str), "%.3f s", dur_ns / 1e9);
        }

        // avg pkt size
        double avg_pkt = (flow_table[i].pkts > 0) ?
                         (double)flow_table[i].bytes / flow_table[i].pkts : 0.0;

        // throughput (bps) with guard for very short flows
        char thr_str[32];
        if (dur_ns < 1000000ULL) {
            snprintf(thr_str, sizeof(thr_str), "N/A");
        } else {
            double bps = ((double)flow_table[i].bytes * 8e9) / dur_ns;
            if (bps > 1e6)
                snprintf(thr_str, sizeof(thr_str), "%.2f Mbps", bps / 1e6);
            else if (bps > 1e3)
                snprintf(thr_str, sizeof(thr_str), "%.2f Kbps", bps / 1e3);
            else
                snprintf(thr_str, sizeof(thr_str), "%.0f bps", bps);
        }

        printf("Flow: %s -> %s\n", src_full, dst_full);
        printf("  Proto: %-6s Pkts: %-6lu Bytes: %-8lu\n",
               proto_name(flow_table[i].key.proto),
               flow_table[i].pkts,
               flow_table[i].bytes);
        printf("  Duration: %-10s AvgPkt: %.1f B  Throughput: %s\n\n",
               dur_str, avg_pkt, thr_str);
    }
}



static inline int flow_key_equal(const flow_key_t *a, const flow_key_t *b) {
    return (a->ip_version == b->ip_version &&
            a->proto   == b->proto   &&
            a->src_port == b->src_port &&
            a->dst_port == b->dst_port &&
            memcmp(a->src_ip, b->src_ip, (a->ip_version == 4 ? 4 : 16)) == 0 &&
            memcmp(a->dst_ip, b->dst_ip, (a->ip_version == 4 ? 4 : 16)) == 0);
}

void flow_update(const flow_key_t *key, uint16_t pktlen) 
{
    uint64_t now = now_tsc();
#ifdef USE_DPDK
    uint64_t hz = rte_get_tsc_hz();
    now = (now * 1000000000ULL) / hz;  // convert to ns
#endif

    for (int i = 0; i < flow_count; i++) {
        if (flow_table[i].in_use && flow_key_equal(&flow_table[i].key, key)) {
            flow_table[i].pkts++;
            flow_table[i].bytes += pktlen;
            flow_table[i].last_seen = now;
            return;
        }
    }

    // New flow
    if (flow_count < FLOW_MAX) {
        flow_table[flow_count].key = *key;
        flow_table[flow_count].pkts = 1;
        flow_table[flow_count].bytes = pktlen;
        flow_table[flow_count].first_seen = now;
        flow_table[flow_count].last_seen  = now;
        flow_table[flow_count].in_use = 1;
        flow_count++;
    } else {
        // TODO: flow eviction policy
    }   
}

void flow_expire(uint64_t now_ns) {
    for (int i = 0; i < flow_count; i++) {
        if (flow_table[i].in_use &&
            (now_ns - flow_table[i].last_seen) > FLOW_TIMEOUT_NS) {
            printf("RAMAN : Time up flow %d in flow table\n", i);
            flow_table[i].in_use = 0;  // mark expired
        }
    }
}