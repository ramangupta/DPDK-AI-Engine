// parse_packet.c
#include <stdio.h>
#include <inttypes.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_arp.h>
#include "capture.h"      // for pkt_view
#include "parse_eth.h"
#include "parse_ipv4.h"
#include "parse_ipv6.h"
#include "parse_l4.h"
#include "utils.h"
#include "stats.h"
#include "talkers.h"
#include "parse_arp.h"
#include <linux/if_ether.h>   // ETH_P_ARP

static void parse_ethernet(const struct rte_ether_hdr *eth,
                           uint16_t pktlen,
                           uint16_t etype)
{
    printf("[len=%" PRIu16 "] ETH ", pktlen);
    print_mac(eth->src_addr.addr_bytes);
    printf(" → ");
    print_mac(eth->dst_addr.addr_bytes);
    printf(" type=0x%04x\n", etype);
}

void parse_packet(pkt_view *pv_full, uint64_t now_tsc)
{
    if (!pv_full || pv_full->len < sizeof(struct rte_ether_hdr)) {
        if (pv_full) {
            printf("[len=%" PRIu16 "] <truncated ethernet>\n", pv_full->len);
        }
        return;
    }

    const uint8_t *data = pv_full->data;
    uint16_t pktlen = pv_full->len;

    const struct rte_ether_hdr *eth = (const struct rte_ether_hdr*)data;
    uint16_t etype = rte_be_to_cpu_16(eth->ether_type);

    parse_ethernet(eth, pktlen, etype);

    // const uint8_t *p = data + sizeof(struct rte_ether_hdr);
    uint16_t rem = pktlen - sizeof(struct rte_ether_hdr);

    if (etype == RTE_ETHER_TYPE_IPV4) {
        stats_update(PROTO_IPV4, pktlen);
        if (rem < sizeof(struct rte_ipv4_hdr)) {
            printf("      IPv4 <truncated>\n");
            return;
        }
        pkt_view ipview = {
            .data = (uint8_t *)eth + sizeof(*eth),
            .len  = pv_full->len - sizeof(*eth),
            .l3_proto = AF_INET
        };

        pv_full->l3_proto = AF_INET;

        handle_ipv4(pv_full, &ipview, now_tsc);
    } else if (etype == RTE_ETHER_TYPE_IPV6) {
        stats_update(PROTO_IPV6, pktlen);
        if (rem < sizeof(struct rte_ipv6_hdr)) {
            printf("      IPv6 <truncated>\n");
            return;
        }
        pkt_view ipview = {
            .data = (uint8_t *)eth + sizeof(*eth),
            .len  = pv_full->len - sizeof(*eth),
            .l3_proto = AF_INET6
        };
        pv_full->l3_proto = AF_INET6;

        // const struct rte_ipv6_hdr *ip6 = (const struct rte_ipv6_hdr*)p;
        handle_ipv6(pv_full, &ipview, now_tsc);
    } else if (etype == RTE_ETHER_TYPE_ARP) {
        if (pv_full->len >= sizeof(*eth) + sizeof(struct rte_arp_hdr)) {
            pkt_view arpview = {
                .data = (uint8_t *)eth + sizeof(*eth),
                .len  = pv_full->len - sizeof(*eth),
                .l3_proto = ETH_P_ARP
            };
            pv_full->l3_proto = ETH_P_ARP;
            stats_update(PROTO_ARP, arpview.len);
            handle_arp(pv_full, &arpview);
        } else {
            printf("ARP <truncated>\n");
        }
    } else if (etype == RTE_ETHER_TYPE_VLAN) {
        printf("      VLAN (not decoded in this sample)\n");
    } else {
        printf("      EtherType 0x%04x not decoded\n", etype);
    }
    // talkers_report();
}
