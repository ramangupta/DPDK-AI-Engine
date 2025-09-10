#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "stats.h"
#include "talkers.h"
#include <string.h>
#include <arpa/inet.h>   // for inet_ntop
#include "tcp_reass.h"
#include "flows.h"
#include "utils.h"
#include "parse_dns.h"
#include <math.h>
#include "stats_json.h"
#include "sniffer_proto.h"
#include <sys/time.h>
#include "filter.h"
#include "tsc.h"
#include <rte_ethdev.h>
#include "frag_ipv4.h"

struct stats global_stats = {0};
static uint64_t total_pkts = 0;
static uint64_t total_bytes = 0;

static struct dhcp_stat dhcp_table[MAX_DHCP];
static int dhcp_count = 0;

static struct arp_stat arp_table[MAX_ARP];
static int arp_count = 0;

static struct frag_stat frag_table[MAX_FRAG];
static int frag_count = 0;

tls_entry_t tls_table[MAX_TLS];
static int tls_count = 0;

dns_entry_t dns_table[DNS_MAX_ENTRIES];
static int dns_count = 0;

static http_session_t http_sessions[MAX_HTTP_SESSIONS];
static int http_session_count = 0;

proto_stats_t proto_stats[MAX_PROTO] = {0};
tunnel_stats_t tunnel_stats = {0};

perf_stats_t perf_stats = {0};


// ------------------- TCP Reassembly Stats -------------------
void stats_tcp_segment(uint16_t pktlen) {
    global_stats.tcp_segments++;
    global_stats.tcp_bytes += pktlen;
    stats_update(PROTO_TCP, pktlen);
}

void stats_tcp_duplicate(void) {
    global_stats.tcp_duplicates++;
}

void stats_tcp_overlap(void) {
    global_stats.tcp_overlaps++;
}

void stats_tcp_out_of_order(void) {
    global_stats.tcp_out_of_order++;
}

// ---------------- Accessor Functions -------------------------
// stats.c
uint64_t stats_get_total_pkts(void) { return total_pkts; }
uint64_t stats_get_total_bytes(void) { return total_bytes; }
int stats_get_tls_count(void) { return tls_count; }
tls_entry_t* stats_get_tls_table(void) { return tls_table; }
int stats_get_arp_count(void) { return arp_count; }
struct arp_stat* stats_get_arp_table(void) { return arp_table; }
struct dhcp_stat *stats_get_dhcp_table(void) { return dhcp_table; }
int stats_get_dhcp_count(void) { return dhcp_count; }
dns_entry_t *stats_get_dns_table(void) { return dns_table; }
int stats_get_dns_count(void) { return dns_count; }
http_session_t *stats_get_http_table(void) { return http_sessions; }
int stats_get_http_count(void) { return http_session_count; }
struct frag_stat *stats_get_frag_table(void) { return frag_table; }
int stats_get_frag_count(void) { return frag_count; }
// -------------------------------------------------------------


const char *protocol_name(enum proto_type p) {
    switch(p) {
        case PROTO_IPV4: return "IPv4";
        case PROTO_IPV6: return "IPv6";
        case PROTO_TCP:  return "TCP";
        case PROTO_UDP:  return "UDP";
        case PROTO_ICMP: return "ICMP";
        case PROTO_DNS:  return "DNS";
        case PROTO_ARP:  return "ARP";
        case PROTO_TLS_HANDSHAKE: return "TLS-HS";
        case PROTO_TLS_APPDATA: return "TLS-App";
        case PROTO_HTTP: return "HTTP";
        default: return "OTHER";
    }
}

void stats_update(enum proto_type p, uint16_t pktlen) {
    switch (p) {
    case PROTO_IPV4: global_stats.ipv4++; break;
    case PROTO_IPV6: global_stats.ipv6++; break;
    case PROTO_TCP:  global_stats.tcp++;  break;
    case PROTO_UDP:  global_stats.udp++;  break;
    case PROTO_ICMP: global_stats.icmp++; break;
    case PROTO_DNS:  global_stats.dns++;  break;
    case PROTO_ARP:  global_stats.arp++;  break;
    case PROTO_TLS_HANDSHAKE: global_stats.tls_handshake++; break; 
    case PROTO_TLS_APPDATA:   global_stats.tls_appdata++;   break;
    case PROTO_HTTP: global_stats.http++; break;
    default: break;
    }

    total_pkts++;
    total_bytes += pktlen;

    if (p >= MAX_PROTO) return;

    proto_stats[p].pkts_total++;
    proto_stats[p].bytes_total += pktlen;
    proto_stats[p].pkts_interval++;
    proto_stats[p].bytes_interval += pktlen;

}

void dns_expire(uint64_t now_ns) {
    const uint64_t TIMEOUT = 30ULL * 1000000000ULL; // 30s
    for (int i = 0; i < dns_count; i++) {
        uint64_t last = (dns_table[i].ts_resp ? dns_table[i].ts_resp
                                              : dns_table[i].ts_query);
        if (now_ns - last > TIMEOUT) {
            // Remove by shifting down
            dns_table[i] = dns_table[dns_count - 1];
            dns_count--;
            i--; // re-check this index
        }
    }
}


void stats_record_dhcp(uint32_t xid, const char *msgtype, const char *ip) {
    if (dhcp_count < MAX_DHCP) {
        dhcp_table[dhcp_count].xid = xid;
        snprintf(dhcp_table[dhcp_count].msgtype, sizeof(dhcp_table[dhcp_count].msgtype), "%s", msgtype);
        snprintf(dhcp_table[dhcp_count].yiaddr, sizeof(dhcp_table[dhcp_count].yiaddr), "%s", ip ? ip : "-");
        dhcp_count++;
    }
}


void stats_record_arp(const char *ip, const char *mac) {
    if (!ip) return;
    if (arp_count >= ARP_MAX_ENTRIES) return;

    snprintf(arp_table[arp_count].ip, sizeof arp_table[arp_count].ip, "%s", ip);
    if (mac) {
        snprintf(arp_table[arp_count].mac, sizeof arp_table[arp_count].mac, "%s", mac);
    } else {
        snprintf(arp_table[arp_count].mac, sizeof arp_table[arp_count].mac, "-");  // placeholder
    }
    arp_count++;
}


void stats_record_frag(uint32_t src, uint32_t dst, uint16_t id, int complete) {
    // Search for existing entry
    for (int i = 0; i < frag_count; i++) {
        if (frag_table[i].version == IPV4 &&
            frag_table[i].id == id &&
            frag_table[i].srcip == src &&
            frag_table[i].dstip == dst) {

            frag_table[i].count++;
            if (complete)
                frag_table[i].done = 1;
            return;
        }
    }

    // New entry
    if (frag_count < MAX_FRAG) {
        frag_table[frag_count].version = IPV4;
        frag_table[frag_count].srcip = src;
        frag_table[frag_count].dstip = dst;
        frag_table[frag_count].id = id;
        frag_table[frag_count].count = 1;
        frag_table[frag_count].done = complete;
        frag_count++;
    }
}


void stats_record_ipv6_frag(const uint8_t *src6, const uint8_t *dst6,
                            uint32_t id, uint16_t frag_off,
                            int more_frags, uint64_t now,
                            int complete)
{
    for (int i = 0; i < frag_count; i++) {
        if (frag_table[i].version == IPV6 &&
            frag_table[i].id == id) {
            frag_table[i].count++;
            if (complete)
                frag_table[i].done = 1;
            return;
        }
    }

    // new entry
    if (frag_count < MAX_FRAG) {
        frag_table[frag_count].version = IPV6;
        frag_table[frag_count].id = id;
        memcpy(frag_table[frag_count].src6, src6, 16);
        memcpy(frag_table[frag_count].dst6, dst6, 16);
        frag_table[frag_count].count = 1;
        frag_table[frag_count].done = complete;
        frag_count++;
    }
}

void stats_record_dns_query(uint16_t id, const char *qname, uint64_t now, int pktlen) {
    if (!qname || !*qname) return;

    // Look for an existing entry
    for (int i = 0; i < dns_count; i++) {
        dns_entry_t *e = &dns_table[i];
        if (e->id == id && strcmp(e->qname, qname) == 0) {
            // Refresh timestamp if query seen again
            e->ts_query = now;
            e->q_pkts++;
            e->q_bytes += pktlen;
            return;
        }
    }

    // New entry if space
    if (dns_count < DNS_MAX_ENTRIES) {
        dns_entry_t *e = &dns_table[dns_count++];
        memset(e, 0, sizeof(*e));
        e->id = id;
        snprintf(e->qname, sizeof e->qname, "%s", qname);
        e->nanswers = 0;
        e->rcode = -1;
        e->ts_query = now;
        e->ts_resp  = 0;
        e->q_pkts   = 1;
        e->q_bytes  = pktlen;
        e->r_pkts   = 0;
        e->r_bytes  = 0;

        // placeholder answer
        snprintf(e->answers[0], sizeof e->answers[0], "-");
        e->nanswers = 1;
    }
}

void stats_record_dns_answer(uint16_t id, const char *qname, const char *ans,
                             int rcode, uint64_t now_ns, int pktlen) {
    if (!qname || !ans) return;

    // Find matching entry by ID + qname
    for (int i = 0; i < dns_count; i++) {
        dns_entry_t *e = &dns_table[i];
        if (e->id == id && strcmp(e->qname, qname) == 0) {
            // First response seen
            if (e->ts_resp == 0) {
                e->ts_resp = now_ns;
                e->rcode   = rcode;
            }

            e->r_pkts++;
            e->r_bytes += pktlen;

            // Dedup check
            for (int j = 0; j < e->nanswers; j++) {
                if (strcmp(e->answers[j], ans) == 0)
                    return;
            }

            // Append answer if space
            if (e->nanswers < DNS_MAX_ANS) {
                snprintf(e->answers[e->nanswers++],
                         sizeof e->answers[0],
                         "%s", ans);
            }
            return;
        }
    }

    // If no query entry, create one with this answer (late-arrival response)
    if (dns_count < DNS_MAX_ENTRIES) {
        dns_entry_t *e = &dns_table[dns_count++];
        memset(e, 0, sizeof(*e));
        e->id = id;
        snprintf(e->qname, sizeof e->qname, "%s", qname);
        snprintf(e->answers[0], sizeof e->answers[0], "%s", ans);
        e->nanswers = 1;
        e->rcode    = rcode;
        e->ts_resp  = now_ns;   // no query seen, but response time set
        e->r_pkts   = 1;
        e->r_bytes  = pktlen;
    }
}



void stats_record_tls(const char *src, const char *dst,
                      const char *sni, const char *alpn,
                      const char *version, const char *cipher,
                      const char *subject, const char *issuer)
{
    if (tls_count >= MAX_TLS) return;

    tls_entry_t *e = &tls_table[tls_count++];

    snprintf(e->src, sizeof(e->src), "%s", src);
    snprintf(e->dst, sizeof(e->dst), "%s", dst);
    snprintf(e->sni, sizeof(e->sni), "%s", sni);
    snprintf(e->alpn, sizeof(e->alpn), "%s", alpn);
    snprintf(e->version, sizeof(e->version), "%s", version);
    snprintf(e->cipher, sizeof(e->cipher), "%s", cipher);
    snprintf(e->subject, sizeof(e->subject), "%s", subject ? subject : "-");
    snprintf(e->issuer, sizeof(e->issuer), "%s", issuer ? issuer : "-");
}


void stats_http_update(const char *src, const char *dst,
                       const char *host, const char *method,
                       const char *uri, const char *status,
                       size_t bytes)
{
    // Find existing session
    for (int i = 0; i < http_session_count; i++) {
        http_session_t *s = &http_sessions[i];
        if (strcmp(s->src, src) == 0 &&
            strcmp(s->dst, dst) == 0) {
            // Update counters
            s->pkts++;
            s->bytes += bytes;

            if (host && *host) strncpy(s->host, host, sizeof(s->host)-1);
            if (method && *method) strncpy(s->method, method, sizeof(s->method)-1);
            if (uri && *uri) strncpy(s->uri, uri, sizeof(s->uri)-1);
            if (status && *status) strncpy(s->status, status, sizeof(s->status)-1);
            return;
        }
    }

    // Otherwise create new
    if (http_session_count < MAX_HTTP_SESSIONS) {
        http_session_t *s = &http_sessions[http_session_count++];
        memset(s, 0, sizeof(*s));
        strncpy(s->src, src, sizeof(s->src)-1);
        strncpy(s->dst, dst, sizeof(s->dst)-1);
        if (host) strncpy(s->host, host, sizeof(s->host)-1);
        if (method) strncpy(s->method, method, sizeof(s->method)-1);
        if (uri) strncpy(s->uri, uri, sizeof(s->uri)-1);
        if (status) strncpy(s->status, status, sizeof(s->status)-1);
        s->pkts = 1;
        s->bytes = bytes;
    }
}

void stats_tunnel_update(pkt_view *pv) {
    if (!pv || !pv->is_tunnel) return;

    size_t pktlen = pv->inner_pkt ? pv->inner_pkt->len : pv->len;

    switch (pv->tunnel.type) {
        case TUNNEL_GRE:
            tunnel_stats.gre_pkts++;
            tunnel_stats.gre_bytes += pktlen;
            break;
        case TUNNEL_VXLAN:
            tunnel_stats.vxlan_pkts++;
            tunnel_stats.vxlan_bytes += pktlen;
            break;
        case TUNNEL_GENEVE:
            tunnel_stats.geneve_pkts++;
            tunnel_stats.geneve_bytes += pktlen;
            break;
        default:
            break;
    }
}

void stats_http_print(void)
{
    printf("\n=== HTTP Sessions ===\n");
    for (int i = 0; i < http_session_count; i++) {
        http_session_t *s = &http_sessions[i];

        // Decide if it's request or response based on Method/Status
        const char *tag = (s->method[0] != '\0') ? "[Req]" : "[Rsp]";

        // First line: metadata summary
        printf("  %-5s Method=%-6s URI=%-20s Status=%-20s pkts=%-4llu bytes=%-6llu\n",
               tag,
               s->method[0] ? s->method : "-",
               s->uri[0] ? s->uri : "-",
               s->status[0] ? s->status : "-",
               (unsigned long long)s->pkts,
               (unsigned long long)s->bytes);

        // Second line: flow + host
        printf("        %s → %s  Host=%s\n",
               s->src, s->dst,
               s->host[0] ? s->host : "-");
    }
}

void stats_report_tls(void) 
{
    printf("\n=== TLS Handshakes ===\n");
    for (int i = 0; i < tls_count; i++) {
        tls_entry_t *e = &tls_table[i];
        printf("Flow: %s → %s\n", e->src, e->dst);
        printf("   SNI=%s  ALPN=%s  Version=%s  Cipher=%s\n",
               e->sni, e->alpn, e->version, e->cipher);
        printf("   Cert: Subject=\"%s\"  Issuer=\"%s\"\n",
               e->subject, e->issuer);
    }
}

void perf_update_runtime(void) {
    struct timeval now;
    gettimeofday(&now, NULL);

    double start = perf_stats.start_time.tv_sec +
                   perf_stats.start_time.tv_usec / 1e6;
    double end   = now.tv_sec + now.tv_usec / 1e6;

    perf_stats.runtime_sec = (end - start);

    if (perf_stats.runtime_sec > 0) {
        perf_stats.pps  = perf_stats.total_pkts / perf_stats.runtime_sec;
        perf_stats.bps  = (perf_stats.total_bytes * 8) / perf_stats.runtime_sec;
        perf_stats.mbps = perf_stats.bps / 1e6;
    }
}

void stats_poll(void) {
    static uint64_t last_report = 0;
    static uint64_t last_maint  = 0;

    uint64_t curr_tsc = now_tsc();  // call the function
    uint64_t now_sec;
    uint64_t now_ns;

#ifdef USE_DPDK
    uint64_t hz = rte_get_tsc_hz();
    now_sec = curr_tsc / hz;
    now_ns  = (curr_tsc * 1000000000ULL) / hz;
#else
    now_sec = curr_tsc / 1000000000ULL;
    now_ns  = curr_tsc;
#endif

    if (last_report == 0) {
        last_report = now_sec;
        last_maint  = now_sec;
        return;
    }

   if (now_sec - last_report >= REPORT_INTERVAL) {

#ifdef USE_DPDK
        if (capture_port >= 0) {
            struct rte_eth_stats eth_stats;
            if (rte_eth_stats_get(capture_port, &eth_stats) == 0) {
                global_stats.dropped_hw = eth_stats.ierrors + eth_stats.rx_nombuf;
            }
        }
#endif

        struct timespec start_ts, end_ts;
        clock_gettime(CLOCK_MONOTONIC, &start_ts);

        perf_update_runtime();
        // Periodic JSON/machine output
        write_stats_json();

        clock_gettime(CLOCK_MONOTONIC, &end_ts);

        // Update cumulative stats write time (ns)
        perf_stats.stats_write_ns +=
            (end_ts.tv_sec - start_ts.tv_sec) * 1e9 + (end_ts.tv_nsec - start_ts.tv_nsec);
        // Optional console summary
        if (g_filters.console_stats) {
            stats_report();   // prints human-readable summary
        }

        last_report = now_sec;
    }

    if (now_sec - last_maint >= 1) {
        tcp_reass_periodic_maintenance(now_sec);
        flow_expire(now_ns);
        dns_expire(now_ns);

        // --- Flush stale IPv4/IPv6 fragments ---
        frag_ipv4_flush_stale(now_ns);
        frag_ipv6_flush_stale(now_ns);
        last_maint = now_sec;
    }
}


static void format_bytes(uint64_t bytes, char *buf, size_t buflen) {
    if (bytes > (1024ULL * 1024 * 1024))
        snprintf(buf, buflen, "%.2f GB", bytes / (1024.0 * 1024 * 1024));
    else if (bytes > (1024ULL * 1024))
        snprintf(buf, buflen, "%.2f MB", bytes / (1024.0 * 1024));
    else if (bytes > 1024ULL)
        snprintf(buf, buflen, "%.2f KB", bytes / 1024.0);
    else
        snprintf(buf, buflen, "%lu B", bytes);
}

void stats_report_dns(void) 
{
    printf("\n=== DNS Transactions ===\n");
    for (int i = 0; i < dns_count; i++) {
        dns_entry_t *e = &dns_table[i];

        const char *rcode_strv = (e->rcode == -1) ? "PENDING" : rcode_str(e->rcode);

        double latency_ms = NAN;
        if (e->ts_query && e->ts_resp)
            latency_ms = (e->ts_resp - e->ts_query) / 1e6;

        printf("ID=0x%04x Q=%s RCODE=%s Latency=%s",
            e->id, e->qname, rcode_strv,
            isnan(latency_ms) ? "N/A" : 
                ({ static char buf[32]; snprintf(buf, sizeof(buf), "%.2f ms", latency_ms); buf; }));

        printf(" pkts=%d/%d bytes=%d/%d\n",
            e->q_pkts, e->r_pkts,
            e->q_bytes, e->r_bytes);

        for (int j = 0; j < e->nanswers; j++) {
            printf("   A=%s\n", e->answers[j]);
        }
    }
}


void stats_tunnel_report(void) 
{
    printf("\n=== Tunnel Stats ===\n");
    printf("%-10s %-10s %-12s\n", "Tunnel", "Pkts", "Bytes");
    char buf[32];

#define PRINT_TUNNEL(name, pkts, bytes) \
        format_bytes(bytes, buf, sizeof(buf)); \
        printf("%-10s %-10lu %-12s\n", name, pkts, buf);

    PRINT_TUNNEL("GRE", tunnel_stats.gre_pkts, tunnel_stats.gre_bytes);
    PRINT_TUNNEL("VXLAN", tunnel_stats.vxlan_pkts, tunnel_stats.vxlan_bytes);
    PRINT_TUNNEL("GENEVE", tunnel_stats.geneve_pkts, tunnel_stats.geneve_bytes);

}

void stats_report(void) 
{

    uint64_t pkt_sum = global_stats.ipv4 + global_stats.ipv6 +
                       global_stats.tcp + global_stats.udp +
                       global_stats.icmp + global_stats.dns +
                       global_stats.arp;

    double pps = (pkt_sum * 1.0) / REPORT_INTERVAL;
    double bps = (total_bytes * 1.0) / REPORT_INTERVAL;

    printf("\n=== Packet Summary (last %d s) ===\n", REPORT_INTERVAL);
    printf("Total=%lu (%.1f pkts/sec) Bandwidth=%.2f KB/s\n",
           pkt_sum, pps, bps / 1024.0);
    printf("IPv4=%lu  IPv6=%lu  TCP=%lu  UDP=%lu  ICMP=%lu  DNS=%lu  ARP=%lu  TLS-HS=%lu  TLS-App=%lu  HTTP=%lu\n",
            global_stats.ipv4, global_stats.ipv6,
            global_stats.tcp, global_stats.udp,
            global_stats.icmp, global_stats.dns,
            global_stats.arp, global_stats.tls_handshake,
            global_stats.tls_appdata, global_stats.http);


    printf("\n=== DHCP Transactions ===\n");
    for (int i=0; i<dhcp_count; i++) {
        printf("xid=0x%x type=%s yiaddr=%s\n",
            dhcp_table[i].xid,
            dhcp_table[i].msgtype,
            dhcp_table[i].yiaddr);
    }

    stats_report_dns();

    printf("\n=== ARP Seen ===\n");
    for (int i=0; i<arp_count; i++) {
        printf("%s is-at %s\n", arp_table[i].ip, arp_table[i].mac);
    }

    printf("\n=== IPv4 Fragments ===\n");
    printf("%-18s %-18s %-20s %-7s %-12s\n",
        "Source", "Destination", "ID (dec/hex)", "Count", "Status");

    for (int i = 0; i < frag_count; i++) {
        if (frag_table[i].version == IPV4) {
            char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
            char idbuf[32];
            snprintf(idbuf, sizeof(idbuf), "%u/0x%04x", frag_table[i].id, frag_table[i].id);

            inet_ntop(AF_INET, &frag_table[i].srcip, src, sizeof(src));
            inet_ntop(AF_INET, &frag_table[i].dstip, dst, sizeof(dst));

            printf("%-18s %-18s %-20s %-8u %-12s\n",
                    src, dst, idbuf,
                    frag_table[i].count,
                    frag_table[i].done ? "DONE" : "IN-PROGRESS");

        }
    }

    printf("\n=== IPv6 Fragments ===\n");
    printf("%-39s %-39s %-25s %-10s %-12s\n",
        "Source", "Destination", "ID (dec/hex)", "Count", "Status");

    for (int i = 0; i < frag_count; i++) {
        if (frag_table[i].version == IPV6) {
            char src[40], dst[40];
            inet_ntop(AF_INET6, frag_table[i].src6, src, sizeof(src));
            inet_ntop(AF_INET6, frag_table[i].dst6, dst, sizeof(dst));

            printf("%-39s %-39s %10u (0x%08x) %-10u %-12s\n",
                src, dst,
                frag_table[i].id,
                frag_table[i].id,
                frag_table[i].count,
                frag_table[i].done ? "DONE" : "IN-PROGRESS");
        }
    }

    // ------------------- TCP Reassembly Stats -------------------
    printf("\n=== TCP Reassembly Stats ===\n");
    printf("Segments received    : %lu\n", global_stats.tcp_segments);
    printf("Bytes delivered      : %lu\n", global_stats.tcp_bytes);
    printf("Duplicate segments   : %lu\n", global_stats.tcp_duplicates);
    printf("Overlapping segments : %lu\n", global_stats.tcp_overlaps);
    printf("Out-of-order segments: %lu\n", global_stats.tcp_out_of_order);

    stats_http_print();

    stats_report_tls();

    printf("\n=== Per Protocol Stats (%d sec) ===\n", REPORT_INTERVAL);
    printf("%-15s %-10s %-12s %-12s\n",
           "Protocol", "Pkts", "Bytes", "Bandwidth");

    for (int p = 0; p < MAX_PROTO; p++) {
        if (proto_stats[p].pkts_interval == 0 &&
            proto_stats[p].bytes_interval == 0)
            continue;

        char bwbuf[32], bytebuf[32];

        double bps = (proto_stats[p].bytes_interval * 8.0) / REPORT_INTERVAL;
        format_bandwidth(bps, bwbuf, sizeof(bwbuf));
        format_bytes(proto_stats[p].bytes_interval, bytebuf, sizeof(bytebuf));
        printf("%-15s %-10lu %-12s %-12s\n",
               protocol_name(p),
               proto_stats[p].pkts_interval,
               bytebuf,
               bwbuf);

        // reset interval counters
        proto_stats[p].pkts_interval = 0;
        proto_stats[p].bytes_interval = 0;
    }

    flow_report();

    stats_tunnel_report();
    
    printf("\nCumulative: pkts=%lu bytes=%lu\n", total_pkts, total_bytes);

    // Reset interval counters
    dhcp_count = dns_count = arp_count = frag_count = 0;

    global_stats.ipv4 = global_stats.ipv6 = global_stats.tcp =
    global_stats.udp = global_stats.icmp = global_stats.dns = 
    global_stats.arp = 0;
    global_stats.tls_handshake = global_stats.tls_appdata = 0;
    global_stats.http = 0;
    global_stats.tcp_segments = global_stats.tcp_bytes = 0;
    global_stats.tcp_duplicates = global_stats.tcp_overlaps = 0;
    global_stats.tcp_out_of_order = 0;
    tls_count = 0;  
    total_bytes = 0;

    tunnel_stats.gre_pkts = tunnel_stats.gre_bytes = 0;
    tunnel_stats.vxlan_pkts = tunnel_stats.vxlan_bytes = 0;
    tunnel_stats.geneve_pkts = tunnel_stats.geneve_bytes = 0;

    talkers_sort_mode = SORT_BY_PKTS; 
    talkers_report();
    talkers_reset();

}

void perf_init(void) {
    memset(&perf_stats, 0, sizeof(perf_stats));
}

void perf_start(void) {
    gettimeofday(&perf_stats.start_time, NULL);
}

void perf_stop(void) {
    gettimeofday(&perf_stats.end_time, NULL);

    double start = perf_stats.start_time.tv_sec +
                   perf_stats.start_time.tv_usec / 1e6;
    double end   = perf_stats.end_time.tv_sec +
                   perf_stats.end_time.tv_usec / 1e6;

    perf_stats.runtime_sec = (end - start);

    if (perf_stats.runtime_sec > 0) {
        perf_stats.pps  = perf_stats.total_pkts / perf_stats.runtime_sec;
        perf_stats.bps  = perf_stats.total_bytes / perf_stats.runtime_sec;
        perf_stats.mbps = (perf_stats.bps * 8) / 1e6;
    }
}

int cmp_uint64(const void *a, const void *b) {
    uint64_t va = *(uint64_t*)a;
    uint64_t vb = *(uint64_t*)b;
    return (va > vb) - (va < vb);
}

void perf_compute_percentiles(perf_stats_t *stats) {
    if (stats->latency_count == 0) {
        stats->latency_p95_ns = 0;
        stats->latency_p99_ns = 0;
        return;
    }

    // Sort the samples in-place
    qsort(stats->latency_samples, stats->latency_count, sizeof(uint64_t), cmp_uint64);

    // Compute P95 and P99 indices
    size_t idx95 = (size_t)(0.95 * (stats->latency_count - 1));
    size_t idx99 = (size_t)(0.99 * (stats->latency_count - 1));

    stats->latency_p95_ns = (double)stats->latency_samples[idx95];
    stats->latency_p99_ns = (double)stats->latency_samples[idx99];
}

void perf_update(uint16_t pktlen, uint64_t pkt_ns) 
{
    perf_stats.total_pkts++;
    perf_stats.total_bytes += pktlen;

    if(pkt_ns > 0) {
        perf_stats.latency_sum_ns += pkt_ns;
        if(pkt_ns < perf_stats.latency_min_ns || perf_stats.latency_count == 0)
            perf_stats.latency_min_ns = pkt_ns;
        if(pkt_ns > perf_stats.latency_max_ns)
            perf_stats.latency_max_ns = pkt_ns;

        if(perf_stats.latency_count < MAX_LATENCY_SAMPLES)
            perf_stats.latency_samples[perf_stats.latency_count++] = pkt_ns;
    }
}

void stats_report_final(void) {
    char start_buf[64], end_buf[64];
    struct tm tm_info;

    // Format start/end times
    localtime_r(&perf_stats.start_time.tv_sec, &tm_info);
    strftime(start_buf, sizeof(start_buf), "%Y-%m-%d %H:%M:%S", &tm_info);
    localtime_r(&perf_stats.end_time.tv_sec, &tm_info);
    strftime(end_buf, sizeof(end_buf), "%Y-%m-%d %H:%M:%S", &tm_info);

    printf("\n==== Final Performance Report ====\n");
    printf("Capture Start       : %s\n", start_buf);
    printf("Capture End         : %s\n", end_buf);
    printf("Duration (sec)      : %.3f\n", perf_stats.runtime_sec);

    // --- Traffic Totals ---
    printf("\n--- Traffic Totals ---\n");
    printf("Total Packets       : %lu\n", perf_stats.total_pkts);
    printf("Total Bytes         : %lu\n", perf_stats.total_bytes);
    printf("Throughput (pps)    : %.2f\n", perf_stats.pps);
    printf("Throughput (Mbps)   : %.2f\n", perf_stats.mbps);

    // Per-protocol throughput
    // printf("IPv4 Throughput (Mbps) : %.2f\n", global_stats.ipv4_bytes * 8.0 / perf_stats.runtime_sec / 1e6);
    // printf("IPv6 Throughput (Mbps) : %.2f\n", global_stats.ipv6_bytes * 8.0 / perf_stats.runtime_sec / 1e6);
    printf("TCP PPS                : %.2f\n", global_stats.tcp / perf_stats.runtime_sec);
    printf("UDP PPS                : %.2f\n", global_stats.udp / perf_stats.runtime_sec);

    // --- Protocol Counters ---
    printf("\n--- Protocol Counters ---\n");
    printf("IPv4 Packets        : %lu\n", global_stats.ipv4);
    printf("IPv6 Packets        : %lu\n", global_stats.ipv6);
    printf("TCP Packets         : %lu\n", global_stats.tcp);
    printf("UDP Packets         : %lu\n", global_stats.udp);
    printf("ICMP Packets        : %lu\n", global_stats.icmp);
    printf("DNS Packets         : %lu\n", global_stats.dns);
    printf("ARP Packets         : %lu\n", global_stats.arp);
    printf("TLS Handshake       : %lu\n", global_stats.tls_handshake);
    printf("TLS AppData         : %lu\n", global_stats.tls_appdata);
    printf("HTTP Packets        : %lu\n", global_stats.http);

    // IPv4 Fragmentation
    printf("\n--- IPv4 Fragmentation ---\n");
    printf("Contexts Allocated          : %lu\n", global_stats.ipv4_frag_allocs);
    printf("Fragments Received          : %lu\n", global_stats.ipv4_frag_received);
    printf("Successfully Reassembled    : %lu\n", global_stats.ipv4_frag_reassembled);
    printf("Payload Expansions          : %lu\n", global_stats.ipv4_frag_expands);
    printf("Drops (alloc/realloc)       : %lu\n", global_stats.ipv4_frag_drops);
    printf("Stale Timeouts              : %lu\n", global_stats.ipv4_frag_timeouts);
    printf("Flushed at Shutdown         : %lu\n", global_stats.ipv4_frag_flushes);

    // IPv6 Fragmentation
    printf("\n--- IPv6 Fragmentation ---\n");
    printf("Contexts Allocated          : %lu\n", global_stats.ipv6_frag_allocs);
    printf("Fragments Received          : %lu\n", global_stats.ipv6_frag_received);
    printf("Successfully Reassembled    : %lu\n", global_stats.ipv6_frag_reassembled);
    printf("Payload Expansions          : %lu\n", global_stats.ipv6_frag_expands);
    printf("Drops (alloc/realloc)       : %lu\n", global_stats.ipv6_frag_drops);
    printf("Stale Timeouts              : %lu\n", global_stats.ipv6_frag_timeouts);
    printf("Flushed at Shutdown         : %lu\n", global_stats.ipv6_frag_flushes);

    // --- TCP Reassembly ---
    printf("\n--- TCP Reassembly ---\n");
    printf("Segments            : %lu\n", global_stats.tcp_segments);
    printf("Bytes Reassembled   : %lu\n", global_stats.tcp_bytes);
    printf("Duplicates          : %lu (%.2f%%)\n", global_stats.tcp_duplicates,
           (double)global_stats.tcp_duplicates / global_stats.tcp_segments * 100.0);
    printf("Overlaps            : %lu\n", global_stats.tcp_overlaps);
    printf("Out-of-Order        : %lu (%.2f%%)\n", global_stats.tcp_out_of_order,
           (double)global_stats.tcp_out_of_order / global_stats.tcp_segments * 100.0);

    printf("\n--- TCP Segment Pool ---\n");
    printf("Segments in use       : %lu\n", atomic_load(&tcp_segments_in_use));
    printf("Segment bytes         : %lu\n", atomic_load(&tcp_segments_bytes));
    printf("Pool exhausted count  : %lu\n", atomic_load(&tcp_seg_pool_exhausted));

    // --- Latency ---
    if (perf_stats.latency_count > 0) {

        perf_compute_percentiles(&perf_stats);

        printf("\n--- Latency (ms) ---\n");
        printf("Latency (ms) : min %.3f, max %.3f, avg %.3f, p95 %.3f, p99 %.3f\n",
                perf_stats.latency_min_ns / 1e6,
                perf_stats.latency_max_ns / 1e6,
                (double)perf_stats.latency_sum_ns / perf_stats.latency_count / 1e6,
                perf_stats.latency_p95_ns / 1e6,
                perf_stats.latency_p99_ns / 1e6);
        printf("Samples          : %lu\n", perf_stats.latency_count);
    }

    // --- Stats Reporting / Overhead ---
    printf("\n--- Stats Overhead ---\n");
    printf("Stats write time (ms) : %.3f\n", perf_stats.stats_write_ns / 1e6);

    printf("\n--- Drops / Errors ---\n");
    printf("Dropped Packets (HW)   : %lu\n", global_stats.dropped_hw);
    printf("Dropped Packets (App)  : %lu\n", global_stats.dropped);
    printf("   Truncated Ethernet  : %lu\n", global_stats.drop_truncated_eth);
    printf("   Invalid Ethertype   : %lu\n", global_stats.drop_invalid_ethertype);
    printf("   Invalid IPv4        : %lu\n", global_stats.drop_invalid_ipv4);
    printf("   Invalid IPv6        : %lu\n", global_stats.drop_invalid_ipv6);
    printf("   Invalid L4          : %lu\n", global_stats.drop_invalid_l4);
    printf("   UDP Truncated       : %lu\n", global_stats.drop_truncated_udp);
    printf("   TCP Truncated       : %lu\n", global_stats.drop_truncated_tcp);
    printf("   TCP Bad Header      : %lu\n", global_stats.drop_bad_header_tcp); 
    printf("   Non UDP/TCP pkt     : %lu\n", global_stats.drop_non_udp_tcp);   
    printf("   Unknown L7          : %lu\n", global_stats.drop_unknown_l7);
    printf("   Invalid Tunnel      : %lu\n", global_stats.drop_invalid_tunnel);
    printf("   Invalid DNS         : %lu\n", global_stats.drop_invalid_dns);
    printf("   Bad Checksums       : %lu\n", global_stats.drop_checksum);
    printf("   Filter Miss         : %lu\n", global_stats.drop_filter_miss);
    printf("   Other               : %lu\n", global_stats.drop_other);
    printf("Dropped TCP Segments   : %lu\n", global_stats.tcp_seg_dropped);


    printf("=================================\n");
}
