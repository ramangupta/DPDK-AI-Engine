// parse_packet.c
#include <stdio.h>
#include <inttypes.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_arp.h>
#include <linux/if_ether.h>   // ETH_P_ARP

// local project headers
#include "engine/capture.h"   // for pkt_view
#include "parsers/parse_eth.h"
#include "parsers/parse_ipv4.h"
#include "parsers/parse_ipv6.h"
#include "parsers/parse_l4.h"
#include "parsers/parse_arp.h"
#include "utils/utils.h"
#include "utils/talkers.h"
#include "stats/stats.h"

static void parse_ethernet(const struct rte_ether_hdr *eth,
                           uint16_t pktlen,
                           uint16_t etype)
{
    PARSER_LOG_LAYER("ETH", COLOR_ETH, "[len=%" PRIu16 "]", pktlen);
    print_mac_flow(eth->src_addr.addr_bytes, eth->dst_addr.addr_bytes);
    PARSER_LOG_LAYER("ETH", COLOR_ETH, " type=0x%04x\n", etype);
}

void parse_packet(pkt_view *pv_full)
{
    uint64_t now_tsc = pv_full->ts_ns;

    if (!pv_full || pv_full->len < sizeof(struct rte_ether_hdr)) {
        if (pv_full) {
            DEBUG_LOG(DBG_ETH, "[len=%" PRIu16 "] <truncated ethernet>\n", pv_full->len);
        }
        global_stats.drop_truncated_eth++;
        global_stats.dropped++;
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
            DEBUG_LOG(DBG_ETH, "      IPv4 <truncated>\n");
            global_stats.drop_invalid_ipv4++;
            global_stats.dropped++;
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
            DEBUG_LOG(DBG_ETH, "      IPv6 <truncated>\n");
            global_stats.drop_invalid_ipv6++;
            global_stats.dropped++;
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
            DEBUG_LOG(DBG_ETH, "ARP <truncated>\n");
            global_stats.drop_truncated_eth++;
            global_stats.dropped++;
        }
    } else if (etype == RTE_ETHER_TYPE_VLAN) {
        DEBUG_LOG(DBG_ETH, "      VLAN (not decoded in this sample)\n");
        global_stats.drop_other++;
        global_stats.dropped++;
    } else {
        DEBUG_LOG(DBG_ETH, "      EtherType 0x%04x not decoded\n", etype);
        global_stats.drop_invalid_ethertype++;
        global_stats.dropped++;
    }
    // talkers_report();
}
