// parse_ipv4.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <rte_ip.h>

#include "utils/utils.h"
#include "utils/talkers.h"
#include "parsers/frag_ipv4.h"
#include "engine/capture.h"
#include "stats/stats.h"
#include "parsers/parse_tunnel.h"
#include "parsers/parse_ipv4.h"
#include "parsers/parse_l4.h"
#include "parsers/parse_eth.h"
#include "parsers/parse_ipv6.h"

void handle_ipv4(pkt_view *pv_full, pkt_view *pv_slice, uint64_t now)
{
    if (!pv_full) return;

    if (!pv_slice) {
        DEBUG_LOG(DBG_IP, "      [WARN] handle_ipv4: NULL slice\n");
        return;
    }

    const struct rte_ipv4_hdr *ip4 = (const struct rte_ipv4_hdr *)pv_slice->data;
    uint16_t rem = pv_slice->len;

    if (rem < sizeof(struct rte_ipv4_hdr)) {
        DEBUG_LOG(DBG_IP, "      IPv4 <truncated>\n");
        global_stats.drop_invalid_ipv4++;
        global_stats.dropped++;
        return;
    }

    uint8_t ihl = (ip4->version_ihl & 0x0F) * 4;
    if (ihl < sizeof(struct rte_ipv4_hdr) || ihl > rem) {
        DEBUG_LOG(DBG_IP, "      IPv4 <bad IHL>\n");
        global_stats.drop_invalid_ipv4++;
        global_stats.dropped++;
        return;
    }

    uint16_t tot = rte_be_to_cpu_16(ip4->total_length);
    if (tot < ihl || tot > rem) tot = rem; // tolerate mismatch

    // --- Fragmentation check ---
    uint16_t frag_off = rte_be_to_cpu_16(ip4->fragment_offset);
    int more_frags = frag_off & RTE_IPV4_HDR_MF_FLAG;
    int offset     = (frag_off & RTE_IPV4_HDR_OFFSET_MASK) << 3;

    // printf("[ipv4] saw packet id=%u, total_length=%u, ihl=%u, proto=%u\n",
    //    rte_be_to_cpu_16(ip4->packet_id),
    //    rte_be_to_cpu_16(ip4->total_length),
    //    (ip4->version_ihl & 0x0F) * 4,
    //    ip4->next_proto_id);

    pkt_view *full = NULL;
    if (more_frags || offset > 0) {
        full = frag_reass_ipv4(ip4, pv_slice, now);  // returns full pkt_view if done
        if (!full) {
            PARSER_LOG_LAYER("IP-FRAG", COLOR_IP_FRAG, 
                            "IPv4 fragment buffered (id=%u)",
                            rte_be_to_cpu_16(ip4->packet_id));
            // done, but still need to free original fragment
            // capture_free(pv);
            stats_record_frag(ip4->src_addr, ip4->dst_addr, 
                          rte_be_to_cpu_16(ip4->packet_id), 0);
            return;
        }

        // Free original fragment (it’s no longer needed)
        // capture_free(pv);
        stats_record_frag(ip4->src_addr, ip4->dst_addr, 
                          rte_be_to_cpu_16(ip4->packet_id), 1);

        // Swap: work on reassembled
        full->is_reassembled = 1;
        pv_slice  = full;
        ip4 = (const struct rte_ipv4_hdr*)pv_slice->data;
        rem = pv_slice->len;

        // >>> IMPORTANT: recompute tot from the reassembled header
        tot = rte_be_to_cpu_16(ip4->total_length);
        PARSER_LOG_LAYER("IP-FRAG", COLOR_IP_FRAG,
                         "IPv4 reassembled (id=%u len=%u)\n",
                         rte_be_to_cpu_16(ip4->packet_id), pv_slice->len);
    }

    // --- Print header ---
    PARSER_LOG_LAYER("IP", COLOR_IP, "      IPv4 ");
    print_ip_flow(ip4->src_addr, ip4->dst_addr);
    PARSER_LOG_LAYER("IP", COLOR_IP, " proto=%u ihl=%u tot=%u ttl=%u\n",
                     ip4->next_proto_id, ihl, tot, ip4->time_to_live);

    // --- Fill pv_full metadata ---
    snprintf(pv_full->src_ip, sizeof(pv_full->src_ip), "%u.%u.%u.%u",
            ip4->src_addr & 0xff, (ip4->src_addr >> 8) & 0xff,
            (ip4->src_addr >> 16) & 0xff, (ip4->src_addr >> 24) & 0xff);
    snprintf(pv_full->dst_ip, sizeof(pv_full->dst_ip), "%u.%u.%u.%u",
            ip4->dst_addr & 0xff, (ip4->dst_addr >> 8) & 0xff,
            (ip4->dst_addr >> 16) & 0xff, (ip4->dst_addr >> 24) & 0xff);

    pv_full->l3_proto = pv_slice->l3_proto;
    pv_full->l4_proto = ip4->next_proto_id;

    // --- Slice payload after IPv4 header (L4 or tunnel start) ---
    pkt_view pv_payload = {
        .data     = (const uint8_t*)ip4 + ihl,
        .len      = (tot > ihl) ? (tot - ihl) : 0,
        .l3_proto = pv_slice->l3_proto,
        .l4_proto = ip4->next_proto_id,
        .kind     = PV_KIND_STACK,
        .backing  = pv_slice->backing,
        .inner_pkt = NULL
    };

    // --- Call Tunnel Parser (works on pkt_view) ---
    if (parse_tunnel(&pv_payload)) {
        // parse_tunnel must have allocated pv_payload.inner_pkt (heap) and set tinfo
        pv_full->is_tunnel = 1;
        pv_full->tunnel = pv_payload.tunnel;
        pv_full->inner_pkt = pv_payload.inner_pkt;

        PARSER_LOG_LAYER("Tunnel", COLOR_TUNNEL, "      IPv4 Tunnel detected: %s",
               (pv_full->tunnel.type == TUNNEL_GRE)    ? "GRE" :
               (pv_full->tunnel.type == TUNNEL_VXLAN)  ? "VXLAN" :
               (pv_full->tunnel.type == TUNNEL_GENEVE) ? "GENEVE" : "OTHER");

        if (!pv_full->tunnel_counted) {
            stats_tunnel_update(pv_full);
            pv_full->tunnel_counted = 1;
        }
        
        // Recursive parsing depending on tunnel type
        switch (pv_full->tunnel.type) {
            case TUNNEL_GRE:
                if (pv_payload.inner_pkt) {
                    if (pv_full->tunnel.inner_proto == 0x0800) {
                        handle_ipv4(pv_full, pv_payload.inner_pkt, now);
                    } else if (pv_full->tunnel.inner_proto == 0x86DD) {
                        handle_ipv6(pv_full, pv_payload.inner_pkt, now);
                    } else {
                        DEBUG_LOG(DBG_IP,"      GRE unsupported inner proto=0x%04x\n", pv_full->tunnel.inner_proto);
                        // Do not attempt parse_l4() on outer GRE header — GRE is not L4 for us.
                        global_stats.drop_invalid_tunnel++;
                        global_stats.dropped++;
                    }
                } else {
                    DEBUG_LOG(DBG_IP,"      [WARN] GRE inner packet missing\n");
                    global_stats.drop_invalid_tunnel++;
                    global_stats.dropped++;
                }
                break;
            case TUNNEL_VXLAN:
            case TUNNEL_GENEVE:
                if (pv_payload.inner_pkt) 
                    // inner_pkt must point to an Ethernet frame
                    parse_packet(pv_payload.inner_pkt);
                else {
                    DEBUG_LOG(DBG_IP,"      [WARN] VXLAN/GENEVE inner packet missing\n");
                    global_stats.drop_invalid_tunnel++;
                    global_stats.dropped++;
                }
                break;
            default:
                // Unknown tunnel type — log and fall back to parsing payload as L4 if sensible
                DEBUG_LOG(DBG_IP,"      Unknown tunnel type=%d\n", pv_full->tunnel.type);
                if (pv_payload.inner_pkt) 
                    parse_l4(pv_full, pv_payload.inner_pkt, now);
                global_stats.drop_invalid_tunnel++;
                global_stats.dropped++;
                break;
        }
    } else {
        pv_full->is_tunnel = 0;

        // Not a tunnel -> normal L4 parsing of payload
        pkt_view pv_l4 = {
            .data     = pv_payload.data,
            .len      = pv_payload.len,
            .l3_proto = pv_payload.l3_proto,
            .l4_proto = pv_payload.l4_proto,
            .src_port = 0,
            .dst_port = 0,
            .kind     = PV_KIND_STACK,
            .backing  = pv_payload.backing,
            .inner_pkt = NULL
        };
        snprintf(pv_l4.src_ip, sizeof(pv_l4.src_ip), "%s", pv_full->src_ip);
        snprintf(pv_l4.dst_ip, sizeof(pv_l4.dst_ip), "%s", pv_full->dst_ip);

        parse_l4(pv_full, &pv_l4, now);
    }

    // Free if this was a reassembled buffer (AFP case)
    if (pv_slice->is_reassembled) {
        capture_release(pv_slice); // AFP: free malloc, DPDK: free mbufs
    }
}
