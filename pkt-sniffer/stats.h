#ifndef STATS_H
#define STATS_H

#include <stdint.h>
#include <netinet/in.h>
#include "capture.h"

#define REPORT_INTERVAL 5
#define MAX_DHCP 64
#define MAX_DNS  64
#define MAX_ARP  64
#define MAX_FRAG 64
#define MAX_NAME_LEN 256
#define MAX_ANSWERS 4
#define MAX_TLS 64
#define DNS_MAX_ANS 8
#define DNS_MAX_ENTRIES 1024
#define MAX_HTTP_SESSIONS 1024
#define ARP_MAX_ENTRIES 64

enum ip_version { IPV4 = 4, IPV6 = 6 };

// Enum for protocol classification
enum proto_type {
    PROTO_NONE,
    PROTO_IPV4,
    PROTO_IPV6,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_DNS,
    PROTO_ARP,
    PROTO_TLS_HANDSHAKE,
    PROTO_TLS_APPDATA,
    PROTO_HTTP,
    MAX_PROTO
};

const char *protocol_name(enum proto_type p); 

// ---------------- Global Stats ----------------
struct stats {
    uint64_t ipv4;
    uint64_t ipv6;
    uint64_t tcp;
    uint64_t udp;
    uint64_t icmp;
    uint64_t dns;
    uint64_t arp;
    uint64_t tls_handshake;
    uint64_t tls_appdata;
    uint64_t http;

    // TCP reassembly
    uint64_t tcp_segments;
    uint64_t tcp_bytes;
    uint64_t tcp_duplicates;
    uint64_t tcp_overlaps;
    uint64_t tcp_out_of_order;

    uint64_t dropped_total;         // total app drops
    uint64_t drop_truncated_eth;    // too short for ethernet header
    uint64_t drop_invalid_ipv4;     // bad/short IPv4
    uint64_t drop_invalid_ipv6;     // bad/short IPv6
    uint64_t drop_invalid_l4;       // bad/short L4
    uint64_t drop_truncated_udp;    // UDP Truncated
    uint64_t drop_truncated_tcp;    // TCP Truncated
    uint64_t drop_bad_header_tcp;   // TCP bad header
    uint64_t drop_non_udp_tcp;      // Not an UDP or TCP proto
    uint64_t drop_unknown_l7;       // Unknown L7
    uint64_t drop_invalid_tunnel;   // Invalid Tunnel
    uint64_t drop_invalid_dns;      // Invalid DNS
    uint64_t drop_checksum;         // L3/L4 checksum failures
    uint64_t drop_filter_miss;      // didn’t pass filter
    uint64_t drop_invalid_ethertype; // Ethertype not decoded
    uint64_t drop_other;            // catch-all
    unsigned long dropped;      // total dropped packets
    unsigned long dropped_hw;
    unsigned long tcp_seg_dropped; // dropped TCP segments (preallocated pool overflow)

    // IPv4 frag/reassembly stats
    uint64_t ipv4_frag_allocs;        // new contexts allocated
    uint64_t ipv4_frag_timeouts;      // stale contexts flushed
    uint64_t ipv4_frag_flushes;       // flush_all at shutdown
    uint64_t ipv4_frag_expands;       // payload buffer grew
    uint64_t ipv4_frag_drops;         // dropped due to alloc/realloc failure
    uint64_t ipv4_frag_received;      // fragments seen
    uint64_t ipv4_frag_reassembled;   // successful reassemblies

    // IPv6 frag/reassembly stats
    uint64_t ipv6_frag_allocs;        // new contexts allocated
    uint64_t ipv6_frag_timeouts;      // stale contexts flushed
    uint64_t ipv6_frag_flushes;       // flush_all at shutdown
    uint64_t ipv6_frag_expands;       // payload buffer grew
    uint64_t ipv6_frag_drops;         // dropped due to alloc/realloc failure
    uint64_t ipv6_frag_received;      // fragments seen
    uint64_t ipv6_frag_reassembled;   // successful reassemblies

};

// ---------------- Protocol Stats ----------------
typedef struct {
    uint64_t pkts_total;
    uint64_t bytes_total;
    uint64_t pkts_interval;
    uint64_t bytes_interval;
} proto_stats_t;

// DHCP transaction
struct dhcp_stat {
    uint32_t xid;
    char msgtype[16];
    char yiaddr[16];
};

// DNS transaction
struct dns_stat {
    char qname[256];
    char answer[256];
};

// ARP stat
struct arp_stat {
    char ip[16];
    char mac[18];
};

// Fragmentation
struct frag_stat {
    enum ip_version version;   // new field
    uint32_t srcip;   // For IPv4
    uint32_t dstip;   // For IPv4
    uint8_t src6[16]; // For IPv6
    uint8_t dst6[16]; // For IPv6
    uint32_t id;               // Fragment ID
    uint32_t count;            // Fragments received so far
    int done;
};

typedef struct {
    char src[64], dst[64];
    char sni[256];
    char alpn[64];
    char version[16];
    char cipher[64];
    char subject[128];
    char issuer[128];
} tls_entry_t;


typedef struct {
    uint16_t id;
    char qname[256];
    char answers[DNS_MAX_ANS][256];
    int nanswers;
    int rcode;             // response code
    uint64_t ts_query;     // ns timestamp of query
    uint64_t ts_resp;      // ns timestamp of response
    int q_pkts, q_bytes;   // query counters
    int r_pkts, r_bytes;   // response counters
} dns_entry_t;

typedef struct {
    char src[64];
    char dst[64];
    char host[128];
    char method[16];
    char uri[128];
    char status[16];
    uint64_t pkts;
    uint64_t bytes;
} http_session_t;


// ---------------- Tunnel Stats ----------------
typedef struct {
    uint64_t gre_pkts;
    uint64_t gre_bytes;
    uint64_t vxlan_pkts;
    uint64_t vxlan_bytes;
    uint64_t geneve_pkts;
    uint64_t geneve_bytes;
} tunnel_stats_t;


// ---------------- Perf Stats ----------------
typedef struct {
    struct timeval start_time;
    struct timeval end_time;

    uint64_t total_pkts;
    uint64_t total_bytes;

    // Derived metrics
    double runtime_sec;
    double pps;       // Packets per second
    double bps;       // Bytes per second
    double mbps;      // Megabits per second

    // Latency (if collected)
    uint64_t latency_samples;
    uint64_t latency_min_ns;
    uint64_t latency_max_ns;
    uint64_t latency_sum_ns;

    uint64_t stats_write_ns;
} perf_stats_t;

// ---------------- Externs ----------------
extern struct stats global_stats;
extern proto_stats_t proto_stats[MAX_PROTO];
extern tunnel_stats_t tunnel_stats;
extern perf_stats_t perf_stats;


// Function prototypes

void stats_update(enum proto_type p, uint16_t pktlen);
void stats_poll(void);
void stats_report(void); // prints only
void stats_report_final(void);

void perf_init(void);
void perf_start(void);
void perf_stop(void);
void perf_update(uint16_t pktlen, uint64_t pkt_ns);
void perf_record_latency(uint64_t ns);

// Flow-specific recorders
void stats_record_dhcp(uint32_t xid, const char *msgtype, const char *ip);
void stats_record_arp(const char *ip, const char *mac);
void stats_record_tls(const char *src, const char *dst,
                      const char *sni, const char *alpn,
                      const char *version, const char *cipher,
                      const char *subject, const char *issuer);


void stats_record_dns_query(uint16_t id, const char *qname, uint64_t now, int pktlen);
void stats_record_dns_answer(uint16_t id, const char *qname, 
                             const char *ans, int rcode, 
                             uint64_t now_ns, int pktlen);
void stats_report_dns(void);

void stats_http_update(const char *src, const char *dst,
                       const char *host, const char *method,
                       const char *uri, const char *status,
                       size_t bytes);

void stats_http_print(void);

void stats_record_frag(uint32_t src, uint32_t dst, 
                       uint16_t id, int complete);
void stats_record_ipv6_frag(const uint8_t *src6, const uint8_t *dst6,
                            uint32_t id, uint16_t frag_off,
                            int more_frags, uint64_t now,
                            int complete);

void stats_tcp_segment(uint16_t pktlen);
void stats_tcp_duplicate(void);
void stats_tcp_overlap(void);
void stats_tcp_out_of_order(void);

void stats_tunnel_update(pkt_view *pv);

uint64_t stats_get_total_pkts(void);
uint64_t stats_get_total_bytes(void);
int stats_get_tls_count(void);
tls_entry_t* stats_get_tls_table(void);
int stats_get_arp_count(void);
struct arp_stat* stats_get_arp_table(void);
struct dhcp_stat *stats_get_dhcp_table(void);
int stats_get_dhcp_count(void);
dns_entry_t *stats_get_dns_table(void);
int stats_get_dns_count(void);
http_session_t *stats_get_http_table(void);
int stats_get_http_count(void);
struct frag_stat *stats_get_frag_table(void);
int stats_get_frag_count(void);
#endif
