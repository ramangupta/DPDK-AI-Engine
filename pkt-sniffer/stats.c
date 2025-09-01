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

static struct dns_entry dns_table[DNS_MAX_ENTRIES];
static int dns_count = 0;

static http_session_t http_sessions[MAX_HTTP_SESSIONS];
static int http_session_count = 0;

proto_stats_t proto_stats[MAX_PROTO] = {0};

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

void stats_record_dns_query(uint16_t id, const char *qname) {
    if (!qname || !*qname) return;
    if (dns_count >= DNS_MAX_ENTRIES) return;

    // Create new entry
    dns_table[dns_count].id = id;
    snprintf(dns_table[dns_count].qname,
             sizeof dns_table[dns_count].qname,
             "%s", qname);
    dns_table[dns_count].nanswers = 0;

    // Put placeholder answer
    snprintf(dns_table[dns_count].answers[0],
             sizeof dns_table[dns_count].answers[0],
             "-");
    dns_table[dns_count].nanswers = 1;

    dns_count++;
}


void stats_record_dns_answer(uint16_t id, const char *qname, const char *ans) {
    if (!qname || !ans) return;

    // Find matching entry by ID + qname
    for (int i = 0; i < dns_count; i++) {
        if (dns_table[i].id == id &&
            strcmp(dns_table[i].qname, qname) == 0) {
            // Dedup check
            for (int j = 0; j < dns_table[i].nanswers; j++) {
                if (strcmp(dns_table[i].answers[j], ans) == 0)
                    return;
            }

            // Append answer if space
            if (dns_table[i].nanswers < DNS_MAX_ANS) {
                int n = dns_table[i].nanswers++;
                snprintf(dns_table[i].answers[n],
                         sizeof dns_table[i].answers[n],
                         "%s", ans);
            }
            return;
        }
    }

    // If no query entry, create one with this answer
    if (dns_count < DNS_MAX_ENTRIES) {
        dns_table[dns_count].id = id;
        snprintf(dns_table[dns_count].qname,
                 sizeof dns_table[dns_count].qname,
                 "%s", qname);
        snprintf(dns_table[dns_count].answers[0],
                 sizeof dns_table[dns_count].answers[0],
                 "%s", ans);
        dns_table[dns_count].nanswers = 1;
        dns_count++;
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

    printf("\n=== DNS Transactions ===\n");
    for (int i = 0; i < dns_count; i++) {
        for (int j = 0; j < dns_table[i].nanswers; j++) {
            printf("ID=0x%04x Q=%s A=%s\n",
                dns_table[i].id,
                dns_table[i].qname,
                dns_table[i].answers[j]);
        }
    }

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

    talkers_sort_mode = SORT_BY_PKTS; 
    talkers_report();
    talkers_reset();
}
