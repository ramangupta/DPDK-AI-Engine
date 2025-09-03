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

struct stats global_stats = {0};
static uint64_t total_pkts = 0;
static uint64_t total_bytes = 0;

static struct dhcp_stat dhcp_table[MAX_DHCP];
static int dhcp_count = 0;

static struct arp_stat arp_table[MAX_ARP];
static int arp_count = 0;

static struct frag_stat frag_table[MAX_FRAG];
static int frag_count = 0;

static struct tls_stat tls_table[MAX_TLS];
static int tls_count = 0;

dns_entry_t dns_table[DNS_MAX_ENTRIES];
static int dns_count = 0;

static http_session_t http_sessions[MAX_HTTP_SESSIONS];
static int http_session_count = 0;

proto_stats_t proto_stats[MAX_PROTO] = {0};
static tunnel_stats_t tunnel_stats = {0};

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
// -------------------------------------------------------------

const char *proto_name(enum proto_type p) {
    switch (p) {
    case PROTO_IPV4: return "IPv4";
    case PROTO_IPV6: return "IPv6";
    case PROTO_TCP: return "TCP";
    case PROTO_UDP: return "UDP";
    case PROTO_ICMP: return "ICMP";
    case PROTO_DNS: return "DNS";
    case PROTO_ARP: return "ARP";
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
                      const char *version, const char *cipher)
{
    if (tls_count < MAX_TLS) {
        snprintf(tls_table[tls_count].src, sizeof(tls_table[tls_count].src), "%s", src);
        snprintf(tls_table[tls_count].dst, sizeof(tls_table[tls_count].dst), "%s", dst);
        snprintf(tls_table[tls_count].sni, sizeof(tls_table[tls_count].sni), "%s", sni ? sni : "-");
        snprintf(tls_table[tls_count].alpn, sizeof(tls_table[tls_count].alpn), "%s", alpn ? alpn : "-");
        snprintf(tls_table[tls_count].version, sizeof(tls_table[tls_count].version), "%s", version ? version : "-");
        snprintf(tls_table[tls_count].cipher, sizeof(tls_table[tls_count].cipher), "%s", cipher ? cipher : "-");
        tls_count++;
    }
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

void stats_poll(uint64_t now_tsc) {
    static uint64_t last_report = 0;
    static uint64_t last_maint  = 0;
    uint64_t now_sec;
    uint64_t now_ns;

#ifdef USE_DPDK
    uint64_t hz = rte_get_tsc_hz();
    now_sec = now_tsc / hz;
    now_ns  = (now_tsc * 1000000000ULL) / hz;  // convert cycles → ns
#else
    now_sec = now_tsc / 1000000000ULL;  // convert ns → sec
    now_ns  = now_tsc;                  // already ns
#endif

    if (last_report == 0) {
        last_report = now_sec;
        last_maint  = now_sec;
        return;
    }

    if (now_sec - last_report >= REPORT_INTERVAL) {
        stats_report();
        last_report = now_sec;
    }

    if (now_sec - last_maint >= 1) {
        // TCP reassembly maintenance can stay on seconds
        tcp_reass_periodic_maintenance(now_sec);
        // Expire old flows (pass nanoseconds!)
        flow_expire(now_ns);
        dns_expire(now_ns);
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


void stats_tunnel_report(void) {
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

void stats_report(void) {
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

    printf("\n=== TLS Sessions ===\n");
    for (int i=0; i<tls_count; i++) {
        printf("%s → %s  SNI=%s  Version=%s  ALPN=%s  Cipher=%s\n",
            tls_table[i].src, tls_table[i].dst,
            tls_table[i].sni, tls_table[i].version,
            tls_table[i].alpn, tls_table[i].cipher);
    }

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
               proto_name(p),
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
