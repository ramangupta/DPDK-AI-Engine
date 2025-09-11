
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <linux/if_ether.h>   // ETH_P_ARP
#include <rte_ether.h>        // DPDK ether header

#include "utils/filter.h"

filter_opts_t g_filters;

void filter_init() {
    memset(&g_filters, 0, sizeof(g_filters));
}

// -----------------------------------------------------------------
// Packet parser → fills filter_pktview_t
// -----------------------------------------------------------------
int extract_minimal_headers(filter_pktview_t *pv, 
                            const uint8_t *data, size_t len)
{
    if (len < sizeof(struct rte_ether_hdr))
        return -1;

    const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)data;
    uint16_t eth_type = ntohs(eth->ether_type);
    size_t offset = sizeof(struct rte_ether_hdr);

    // reset defaults
    pv->l3_proto  = 0;
    pv->l4_proto  = 0;
    pv->src_port  = 0;
    pv->dst_port  = 0;
    pv->src4.s_addr = 0;
    pv->dst4.s_addr = 0;
    memset(&pv->src6, 0, sizeof(pv->src6));
    memset(&pv->dst6, 0, sizeof(pv->dst6));

    pv->data = data;
    pv->len  = len;

    if (eth_type == RTE_ETHER_TYPE_IPV4) {
        if (len < offset + sizeof(struct ip))
            return -1;

        const struct ip *iph = (const struct ip *)(data + offset);
        pv->l3_proto = AF_INET;
        pv->l4_proto = iph->ip_p;

        pv->src4 = iph->ip_src;
        pv->dst4 = iph->ip_dst;

        offset += iph->ip_hl * 4;
        if (offset > len) return -1;

        if (pv->l4_proto == IPPROTO_TCP) {
            if (len < offset + sizeof(struct tcphdr)) return -1;
            const struct tcphdr *tcp = (const struct tcphdr *)(data + offset);
            pv->src_port = ntohs(tcp->source);
            pv->dst_port = ntohs(tcp->dest);
        } else if (pv->l4_proto == IPPROTO_UDP) {
            if (len < offset + sizeof(struct udphdr)) return -1;
            const struct udphdr *udp = (const struct udphdr *)(data + offset);
            pv->src_port = ntohs(udp->source);
            pv->dst_port = ntohs(udp->dest);
        }

    } else if (eth_type == RTE_ETHER_TYPE_IPV6) {
        if (len < offset + sizeof(struct ip6_hdr))
            return -1;

        const struct ip6_hdr *ip6h = (const struct ip6_hdr *)(data + offset);
        pv->l3_proto = AF_INET6;
        pv->l4_proto = ip6h->ip6_nxt;

        pv->src6 = ip6h->ip6_src;
        pv->dst6 = ip6h->ip6_dst;

        offset += sizeof(struct ip6_hdr);
        if (offset > len) return -1;

        if (pv->l4_proto == IPPROTO_TCP) {
            if (len < offset + sizeof(struct tcphdr)) return -1;
            const struct tcphdr *tcp = (const struct tcphdr *)(data + offset);
            pv->src_port = ntohs(tcp->source);
            pv->dst_port = ntohs(tcp->dest);
        } else if (pv->l4_proto == IPPROTO_UDP) {
            if (len < offset + sizeof(struct udphdr)) return -1;
            const struct udphdr *udp = (const struct udphdr *)(data + offset);
            pv->src_port = ntohs(udp->source);
            pv->dst_port = ntohs(udp->dest);
        }
    } else if (eth_type == RTE_ETHER_TYPE_ARP) {
        pv->l3_proto = ETH_P_ARP;   // from <linux/if_ether.h>
        pv->l4_proto = 0;
        pv->src_port = pv->dst_port = 0;
        return 0;
    }

    return 0;
}


// -----------------------------------------------------------------
// Filtering logic
// -----------------------------------------------------------------
bool filter_match(const filter_pktview_t *pv) {
    // Proto filter
    if (g_filters.filter_proto) {
        if (strcmp(g_filters.proto, "tcp") == 0 && pv->l4_proto != IPPROTO_TCP) return false;
        if (strcmp(g_filters.proto, "udp") == 0 && pv->l4_proto != IPPROTO_UDP) return false;
        if (strcmp(g_filters.proto, "icmp") == 0 && pv->l4_proto != IPPROTO_ICMP) return false;
        if (strcmp(g_filters.proto, "icmp6") == 0 && pv->l4_proto != IPPROTO_ICMPV6) return false;
        if (strcmp(g_filters.proto, "arp") == 0 && pv->l3_proto != ETH_P_ARP) return false;
    }

    // Port filter
    if (g_filters.filter_port) {
        if (pv->src_port != g_filters.port && pv->dst_port != g_filters.port)
            return false;
    }

    // IPv4 filter
    if (g_filters.has_ip4) {
        if (!(pv->l3_proto == AF_INET &&
              (pv->src4.s_addr == g_filters.ip4.s_addr ||
               pv->dst4.s_addr == g_filters.ip4.s_addr)))
            return false;
    }

    // IPv6 filter
    if (g_filters.has_ip6) {
        if (!(pv->l3_proto == AF_INET6 &&
              (memcmp(&pv->src6, &g_filters.ip6, sizeof(struct in6_addr)) == 0 ||
               memcmp(&pv->dst6, &g_filters.ip6, sizeof(struct in6_addr)) == 0)))
            return false;
    }

    // Host filter (string match for now)
    if (g_filters.filter_host) {
        bool matched = false;

        // IPv4 compare
        for (int i = 0; i < g_filters.host_addr_count; i++) {
            if (pv->l3_proto == AF_INET) {
                if (memcmp(&pv->src4, &g_filters.host_v4[i], sizeof(struct in_addr)) == 0 ||
                    memcmp(&pv->dst4, &g_filters.host_v4[i], sizeof(struct in_addr)) == 0) {
                    matched = true;
                    break;
                }
            }
            if (pv->l3_proto == AF_INET6) {
                if (memcmp(&pv->src6, &g_filters.host_v6[i], sizeof(struct in6_addr)) == 0 ||
                    memcmp(&pv->dst6, &g_filters.host_v6[i], sizeof(struct in6_addr)) == 0) {
                    matched = true;
                    break;
                }
            }
        }
        if (!matched)
            return false;
        }

    return true; // matched
}
