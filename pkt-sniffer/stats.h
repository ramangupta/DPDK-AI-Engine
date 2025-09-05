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

extern struct stats global_stats;

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

/* Per protocol Bandwidth */
typedef struct {
    uint64_t pkts_total;
    uint64_t bytes_total;
    uint64_t pkts_interval;
    uint64_t bytes_interval;
} proto_stats_t;

extern proto_stats_t proto_stats[MAX_PROTO];

// Define stats structure
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
    uint64_t tcp_segments;
    uint64_t tcp_bytes;
    uint64_t tcp_duplicates;
    uint64_t tcp_overlaps;
    uint64_t tcp_out_of_order;
};

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

typedef struct tunnel_stats_s {
    uint64_t gre_pkts;
    uint64_t gre_bytes;

    uint64_t vxlan_pkts;
    uint64_t vxlan_bytes;

    uint64_t geneve_pkts;
    uint64_t geneve_bytes;
} tunnel_stats_t;

// Function prototypes

void stats_update(enum proto_type p, uint16_t pktlen);
void stats_poll(uint64_t now_tsc);
void stats_report(void); // prints only

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
