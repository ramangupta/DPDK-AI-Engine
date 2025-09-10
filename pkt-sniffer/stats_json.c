// stats_json.c
#include <stdio.h>
#include <json-c/json.h>
#include "stats.h"
#include "flows.h"
#include "talkers.h"
#include <json-c/json.h>
#include <arpa/inet.h>
#include "sniffer_proto.h"
#include "stats_json.h"

struct json_object *stats_build_json(void) {
    struct json_object *root = json_object_new_object();

    // --- Perf / Traffic Totals ---
    double runtime_sec = perf_stats.runtime_sec > 0 ? perf_stats.runtime_sec : 1.0;
    double pps = perf_stats.total_pkts / runtime_sec;
    double bps = perf_stats.total_bytes / runtime_sec;   // bytes/sec
    
    struct json_object *perf = json_object_new_object();
    json_object_object_add(perf, "total_pkts", json_object_new_int64(perf_stats.total_pkts));
    json_object_object_add(perf, "total_bytes", json_object_new_int64(perf_stats.total_bytes));
    json_object_object_add(perf, "pps", json_object_new_double(pps));
    json_object_object_add(perf, "bandwidth_bps", json_object_new_double(bps * 8));
    json_object_object_add(perf, "mbps", json_object_new_double(perf_stats.mbps));

    // --- Latency ---
    if (perf_stats.latency_count > 0) {

        perf_compute_percentiles(&perf_stats);

        double avg_ms = (double)perf_stats.latency_sum_ns / perf_stats.latency_count / 1e6;
        json_object_object_add(perf, "latency_min_ms", json_object_new_double(perf_stats.latency_min_ns / 1e6));
        json_object_object_add(perf, "latency_max_ms", json_object_new_double(perf_stats.latency_max_ns / 1e6));
        json_object_object_add(perf, "latency_avg_ms", json_object_new_double(avg_ms));
        json_object_object_add(perf, "latency_p95_ms", json_object_new_double(perf_stats.latency_p95_ns / 1e6));
        json_object_object_add(perf, "latency_p99_ms", json_object_new_double(perf_stats.latency_p99_ns / 1e6));
        json_object_object_add(perf, "latency_samples", json_object_new_int64(perf_stats.latency_count));
    }

    // --- Summary ---
    struct json_object *summary = json_object_new_object();
    json_object_object_add(summary, "perf", perf);

    // --- Per-Protocol ---
    struct json_object *per_proto = json_object_new_object();
    json_object_object_add(per_proto, "ipv4", json_object_new_int64(global_stats.ipv4));
    json_object_object_add(per_proto, "ipv6", json_object_new_int64(global_stats.ipv6));
    json_object_object_add(per_proto, "tcp",  json_object_new_int64(global_stats.tcp));
    json_object_object_add(per_proto, "udp",  json_object_new_int64(global_stats.udp));
    json_object_object_add(per_proto, "icmp", json_object_new_int64(global_stats.icmp));
    json_object_object_add(per_proto, "dns",  json_object_new_int64(global_stats.dns));
    json_object_object_add(per_proto, "arp",  json_object_new_int64(global_stats.arp));
    json_object_object_add(per_proto, "tls_handshake", json_object_new_int64(global_stats.tls_handshake));
    json_object_object_add(per_proto, "tls_appdata",  json_object_new_int64(global_stats.tls_appdata));
    json_object_object_add(per_proto, "http", json_object_new_int64(global_stats.http));

    json_object_object_add(summary, "per_proto", per_proto);
    json_object_object_add(root, "summary", summary);

        // --- Per-Protocol stats ---
    struct json_object *proto_arr = json_object_new_array();
    for (int p = 0; p < MAX_PROTO; p++) {
        if (proto_stats[p].pkts_interval == 0 &&
            proto_stats[p].bytes_interval == 0)
            continue;

        const char *name = protocol_name((enum proto_type)p);
        if (!name) name = "OTHER";           // belt & suspenders
        struct json_object *obj = json_object_new_object();
        json_object_object_add(obj, "proto", json_object_new_string(name));
        json_object_object_add(obj, "pkts",  json_object_new_int64(proto_stats[p].pkts_interval));
        json_object_object_add(obj, "bytes", json_object_new_int64(proto_stats[p].bytes_interval));

        // convert to bandwidth bits/sec, like stats_report does
        double bps = (proto_stats[p].bytes_interval * 8.0) / REPORT_INTERVAL;
        json_object_object_add(obj, "bandwidth_bps", json_object_new_double(bps));

        json_object_array_add(proto_arr, obj);

        // reset interval counters, like in stats_report()
        proto_stats[p].pkts_interval = 0;
        proto_stats[p].bytes_interval = 0;
    }
    json_object_object_add(root, "per_protocol", proto_arr);

    // --- DHCP ---
    int dhcp_count = stats_get_dhcp_count();
    struct dhcp_stat *dhcp_table = stats_get_dhcp_table();
    struct json_object *dhcp_arr = json_object_new_array();
    for (int i=0; i<dhcp_count; i++) {
        struct json_object *obj = json_object_new_object();
        json_object_object_add(obj, "xid", json_object_new_int(dhcp_table[i].xid));
        json_object_object_add(obj, "type", json_object_new_string(dhcp_table[i].msgtype));
        json_object_object_add(obj, "yiaddr", json_object_new_string(dhcp_table[i].yiaddr));
        json_object_array_add(dhcp_arr, obj);
    }
    json_object_object_add(root, "dhcp", dhcp_arr);

    // --- DNS ---
    int dns_count = stats_get_dns_count();
    dns_entry_t *dns_table = stats_get_dns_table();
    struct json_object *dns_arr = json_object_new_array();
    for (int i=0; i<dns_count; i++) {
        struct json_object *obj = json_object_new_object();
        json_object_object_add(obj, "qname",  json_object_new_string(dns_table[i].qname));
        json_object_object_add(obj, "answer", json_object_new_string(dns_table[i].answers[0]));
        json_object_array_add(dns_arr, obj);
    }
    json_object_object_add(root, "dns", dns_arr);

    // --- ARP ---
    int arp_count = stats_get_arp_count();
    struct arp_stat* arp_table = stats_get_arp_table();
    struct json_object *arp_arr = json_object_new_array();
    for (int i=0; i<arp_count; i++) {
        struct json_object *obj = json_object_new_object();
        json_object_object_add(obj, "ip",  json_object_new_string(arp_table[i].ip));
        json_object_object_add(obj, "mac", json_object_new_string(arp_table[i].mac));
        json_object_array_add(arp_arr, obj);
    }
    json_object_object_add(root, "arp", arp_arr);

    // --- NEW: IPv4 / IPv6 Fragments ---
    int frag_count = stats_get_frag_count();
    struct frag_stat *frag_table = stats_get_frag_table();
    struct json_object *frag_arr = json_object_new_array();
    for (int i=0; i<frag_count; i++) {
        struct json_object *obj = json_object_new_object();
        json_object_object_add(obj, "version", json_object_new_string(
            frag_table[i].version == IPV4 ? "IPv4" : "IPv6"));

        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        if (frag_table[i].version == IPV4) {
            inet_ntop(AF_INET, &frag_table[i].srcip, src, sizeof(src));
            inet_ntop(AF_INET, &frag_table[i].dstip, dst, sizeof(dst));
        } else {
            inet_ntop(AF_INET6, frag_table[i].src6, src, sizeof(src));
            inet_ntop(AF_INET6, frag_table[i].dst6, dst, sizeof(dst));
        }

        json_object_object_add(obj, "src", json_object_new_string(src));
        json_object_object_add(obj, "dst", json_object_new_string(dst));

        char idbuf[32];
        snprintf(idbuf, sizeof(idbuf), "%u/0x%04x", frag_table[i].id, frag_table[i].id);
        json_object_object_add(obj, "id", json_object_new_string(idbuf));

        json_object_object_add(obj, "count", json_object_new_int(frag_table[i].count));
        json_object_object_add(obj, "status", json_object_new_string(frag_table[i].done ? "DONE" : "IN-PROGRESS"));

        json_object_array_add(frag_arr, obj);
    }
    json_object_object_add(root, "fragments", frag_arr);

    // --- TCP Reassembly ---
    struct json_object *tcp_reass = json_object_new_object();
    json_object_object_add(tcp_reass, "segments", json_object_new_int64(global_stats.tcp_segments));
    json_object_object_add(tcp_reass, "bytes", json_object_new_int64(global_stats.tcp_bytes));
    json_object_object_add(tcp_reass, "duplicates", json_object_new_int64(global_stats.tcp_duplicates));
    json_object_object_add(tcp_reass, "overlaps", json_object_new_int64(global_stats.tcp_overlaps));
    json_object_object_add(tcp_reass, "out_of_order", json_object_new_int64(global_stats.tcp_out_of_order));
    json_object_object_add(root, "tcp_reassembly", tcp_reass);

    // --- HTTP sessions ---
    int http_session_count = stats_get_http_count();
    http_session_t *http_sessions = stats_get_http_table();
    struct json_object *http_arr = json_object_new_array();
    for (int i=0; i<http_session_count; i++) {
        struct json_object *obj = json_object_new_object();
        json_object_object_add(obj, "src",    json_object_new_string(http_sessions[i].src));
        json_object_object_add(obj, "dst",    json_object_new_string(http_sessions[i].dst));
        json_object_object_add(obj, "host",   json_object_new_string(http_sessions[i].host));
        json_object_object_add(obj, "method", json_object_new_string(http_sessions[i].method));
        json_object_object_add(obj, "uri",    json_object_new_string(http_sessions[i].uri));
        json_object_object_add(obj, "status", json_object_new_string(http_sessions[i].status));
        json_object_object_add(obj, "pkts",   json_object_new_int64(http_sessions[i].pkts));
        json_object_object_add(obj, "bytes",  json_object_new_int64(http_sessions[i].bytes));
        json_object_array_add(http_arr, obj);
    }
    json_object_object_add(root, "http_sessions", http_arr);

    // --- TLS ---
    int tls_count = stats_get_tls_count();
    tls_entry_t* tls_table = stats_get_tls_table();
    struct json_object *tls_arr = json_object_new_array();
    for (int i=0; i<tls_count; i++) {
        struct json_object *obj = json_object_new_object();
        json_object_object_add(obj, "src", json_object_new_string(tls_table[i].src));
        json_object_object_add(obj, "dst", json_object_new_string(tls_table[i].dst));
        json_object_object_add(obj, "sni", json_object_new_string(tls_table[i].sni));
        json_object_object_add(obj, "alpn", json_object_new_string(tls_table[i].alpn));
        json_object_object_add(obj, "version", json_object_new_string(tls_table[i].version));
        json_object_object_add(obj, "cipher", json_object_new_string(tls_table[i].cipher));
        json_object_object_add(obj, "subject", json_object_new_string(tls_table[i].subject));
        json_object_object_add(obj, "issuer",  json_object_new_string(tls_table[i].issuer));
        json_object_array_add(tls_arr, obj);
    }
    json_object_object_add(root, "tls_sessions", tls_arr);

    // --- Tunnel stats ---
    struct json_object *tun = json_object_new_object();
    extern tunnel_stats_t tunnel_stats;
    json_object_object_add(tun, "gre_pkts",    json_object_new_int64(tunnel_stats.gre_pkts));
    json_object_object_add(tun, "gre_bytes",   json_object_new_int64(tunnel_stats.gre_bytes));
    json_object_object_add(tun, "vxlan_pkts",  json_object_new_int64(tunnel_stats.vxlan_pkts));
    json_object_object_add(tun, "vxlan_bytes", json_object_new_int64(tunnel_stats.vxlan_bytes));
    json_object_object_add(tun, "geneve_pkts", json_object_new_int64(tunnel_stats.geneve_pkts));
    json_object_object_add(tun, "geneve_bytes",json_object_new_int64(tunnel_stats.geneve_bytes));
    json_object_object_add(root, "tunnels", tun);

    // --- Flows ---
    struct json_object *flows_arr = json_object_new_array();

    int count = (flow_count < FLOWS_MAX_DISPLAY) ? flow_count : FLOWS_MAX_DISPLAY;

    for (int i = 0; i < count; i++) {
        if (!flow_table[i].in_use) continue;

        char src[64], dst[64];
        if (flow_table[i].key.ip_version == 4) {
            inet_ntop(AF_INET, flow_table[i].key.src_ip, src, sizeof(src));
            inet_ntop(AF_INET, flow_table[i].key.dst_ip, dst, sizeof(dst));
        } else {
            inet_ntop(AF_INET6, flow_table[i].key.src_ip, src, sizeof(src));
            inet_ntop(AF_INET6, flow_table[i].key.dst_ip, dst, sizeof(dst));
        }

        char src_full[80], dst_full[80];
        if (flow_table[i].key.proto == IPPROTO_TCP || flow_table[i].key.proto == IPPROTO_UDP) {
            snprintf(src_full, sizeof(src_full), "%s:%u", src, flow_table[i].key.src_port);
            snprintf(dst_full, sizeof(dst_full), "%s:%u", dst, flow_table[i].key.dst_port);
        } else {
            snprintf(src_full, sizeof(src_full), "%s", src);
            snprintf(dst_full, sizeof(dst_full), "%s", dst);
        }

        double duration_sec = (flow_table[i].last_seen > flow_table[i].first_seen)
                            ? (flow_table[i].last_seen - flow_table[i].first_seen) / 1e9
                            : 0.0;
        double avg_pkt = (flow_table[i].pkts > 0)
                        ? (double)flow_table[i].bytes / flow_table[i].pkts
                        : 0.0;
        double throughput_bps = (duration_sec > 0)
                                ? ((double)flow_table[i].bytes * 8.0) / duration_sec
                                : 0.0;

        struct json_object *obj = json_object_new_object();
        json_object_object_add(obj, "src", json_object_new_string(src_full));
        json_object_object_add(obj, "dst", json_object_new_string(dst_full));
        json_object_object_add(obj, "proto", json_object_new_string(proto_name(flow_table[i].key.proto)));
        json_object_object_add(obj, "pkts", json_object_new_int64(flow_table[i].pkts));
        json_object_object_add(obj, "bytes", json_object_new_int64(flow_table[i].bytes));
        json_object_object_add(obj, "duration_sec", json_object_new_double(duration_sec));
        json_object_object_add(obj, "avg_pkt_bytes", json_object_new_double(avg_pkt));
        json_object_object_add(obj, "throughput_bps", json_object_new_double(throughput_bps));

        json_object_array_add(flows_arr, obj);
    }
    json_object_object_add(root, "flows", flows_arr);

    // --- Top Talkers (packets) ---
    struct json_object *talkers_arr = json_object_new_array();

    // Sort based on the chosen mode
    if (talkers_sort_mode == SORT_BY_BYTES)
        qsort(table, used, sizeof(table[0]), cmp_bytes);
    else
        qsort(table, used, sizeof(table[0]), cmp_pkts);

    
    int limit = (used < TOP_N) ? used : TOP_N;

    for (int i = 0; i < limit; i++) {
        struct json_object *obj = json_object_new_object();
        json_object_object_add(obj, "flow", json_object_new_string(table[i].flow));
        json_object_object_add(obj, "proto", json_object_new_string(table[i].proto));
        json_object_object_add(obj, "pkts", json_object_new_int64(table[i].pkts));
        json_object_object_add(obj, "bytes", json_object_new_int64(table[i].bytes));
        json_object_array_add(talkers_arr, obj);
    }

    json_object_object_add(root, "top_talkers", talkers_arr);

    // --- Cumulative ---
    struct json_object *cum = json_object_new_object();
    json_object_object_add(cum, "pkts",  json_object_new_int64(stats_get_total_pkts()));
    json_object_object_add(cum, "bytes", json_object_new_int64(stats_get_total_bytes()));
    json_object_object_add(root, "cumulative", cum);

    return root;
}


// Export stats to JSON file
void write_stats_json(void)
{
    struct json_object *root = stats_build_json();
    if (!root) {
        fprintf(stderr, "[ERROR] stats_build_json() returned NULL\n");
        return;
    }

    FILE *f = fopen("../web/stats.json", "w");
    if (!f) {
        fprintf(stderr, "[ERROR] Failed to open web/stats.json for writing\n");
        json_object_put(root);
        return;
    }

    const char *js_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    if (fprintf(f, "%s\n", js_str) < 0) {
        fprintf(stderr, "[ERROR] Failed to write to web/stats.json\n");
    }

    fclose(f);
    json_object_put(root); // free
}


