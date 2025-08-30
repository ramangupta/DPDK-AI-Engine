#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#define MAX_HOST_ADDRS 8

// ----------------- Packet view abstraction -----------------

typedef struct {
    int l3_proto;   // AF_INET, AF_INET6, ETH_P_ARP, etc.
    int l4_proto;   // IPPROTO_TCP, UDP, ICMP, etc.

    struct in_addr  src4, dst4;
    struct in6_addr src6, dst6;

    uint16_t src_port, dst_port;

    const uint8_t *data; // raw packet ptr
    size_t len;
} filter_pktview_t;

// ----------------- Filter options -----------------

typedef struct {
    bool filter_proto;
    char proto[16];

    bool filter_port;
    uint16_t port;

    // IPv4 filter
    bool has_ip4;
    struct in_addr ip4;

    // IPv6 filter
    bool has_ip6;
    struct in6_addr ip6;

    bool filter_host;
    char host_str[128];  // original hostname (for logging)
    int host_addr_count;
    struct in_addr host_v4[MAX_HOST_ADDRS];
    struct in6_addr host_v6[MAX_HOST_ADDRS];

    bool write_pcap;
    char write_file[256];

} filter_opts_t;

extern filter_opts_t g_filters;

// ----------------- API -----------------
void filter_init();
bool filter_match(const filter_pktview_t *fpv);

// Helper to set IP filter safely
int filter_set_ip(const char *ipstr);

/**
 * Parse Ethernet/IP/TCP/UDP headers and fill fpv
 * @return 0 on success, -1 if not supported or malformed
 */
int extract_minimal_headers(filter_pktview_t *fpv,
                            const uint8_t *data, size_t len);
