#include <stdio.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <arpa/inet.h>
#include "parse_ipv6.h"
#include "parse_l4.h"
#include "parse_eth.h"
#include "utils.h"
#include "talkers.h"
#include "frag_ipv4.h"   // new frag reassembly API
#include "stats.h"
#include "parse_ipv4.h"
#include "parse_tunnel.h"
#include "parse_eth.h"
#include <rte_udp.h>

// ---------------- IPv6 Extensions Parsing ----------------

// Walk IPv6 extensions, handle fragments, return final next_header
uint8_t parse_ipv6_extensions(const uint8_t *data, uint16_t len,
                              uint8_t next_header,
                              pkt_view *pv_full, pkt_view **pv_slice,
                              uint64_t now)
{
    const uint8_t *ptr = data;
    uint16_t remaining = len;
    uint8_t nh = next_header;
    pkt_view *slice = *pv_slice;

    while (1) {
        if (nh == IPPROTO_HOPOPTS || nh == IPPROTO_ROUTING ||
            nh == IPPROTO_DSTOPTS || nh == IPPROTO_FRAGMENT ||
            nh == IPPROTO_AH || nh == IPPROTO_ESP) {

            if (remaining < 2) {
                DEBUG_LOG(DBG_IP,"      IPv6 ext <truncated>\n");
                return nh;
            }

            uint8_t ext_len;
            if (nh == IPPROTO_AH)
                ext_len = (ptr[1] + 2) * 4;  // AH header special length
            else
                ext_len = (ptr[1] + 1) * 8;

            if (ext_len > remaining) {
                DEBUG_LOG(DBG_IP,"      IPv6 ext <bad len>\n");
                return nh;
            }

            // --- Handle Fragment Header ---
            if (nh == IPPROTO_FRAGMENT) {
                const struct rte_ipv6_hdr *ip6 =
                    (const struct rte_ipv6_hdr *)slice->data;
                const struct rte_ipv6_frag_hdr *fh =
                    (const struct rte_ipv6_frag_hdr *)ptr;

                uint32_t frag_id = rte_be_to_cpu_32(fh->identification);
                uint16_t raw_off = rte_be_to_cpu_16(fh->fragment_offset);
                uint32_t off = (raw_off & 0xFFF8);
                int more_frags = (raw_off & 0x1);

                pkt_view *full = frag_reass_ipv6(ptr, slice, now);
                if (!full) {
                    PARSER_LOG_LAYER("IPv6-FRAG", COLOR_IP_FRAG,
                                     "IPv6 fragment buffered");
                    stats_record_ipv6_frag((const uint8_t *)&ip6->src_addr,
                                           (const uint8_t *)&ip6->dst_addr,
                                           frag_id, off, more_frags, now, 0);
                    return nh; // wait for more fragments
                }

                stats_record_ipv6_frag((const uint8_t *)&ip6->src_addr,
                                       (const uint8_t *)&ip6->dst_addr,
                                       frag_id, off, more_frags, now, 1);

                // Reassembled packet replaces slice
                full->is_reassembled = 1;   // <--- mark it for cleanup
                *pv_slice = full;
                pv_full = full;
                slice = full;

                ptr = slice->data + sizeof(struct rte_ipv6_hdr);
                remaining = slice->len - sizeof(struct rte_ipv6_hdr);
                nh = ((struct rte_ipv6_hdr*)slice->data)->proto;
                PARSER_LOG_LAYER("IP-FRAG", COLOR_IP_FRAG, "IPv6 reassembled");
                continue;
            }

            nh = ptr[0]; // next header
            ptr += ext_len;
            remaining -= ext_len;

        } else {
            // reached L4 / tunnel proto
            return nh;
        }
    }
}


// ---------------- Handle IPv6 ----------------
void handle_ipv6(pkt_view *pv_full, pkt_view *pv_slice, uint64_t now)
{
    if (pv_slice->len < sizeof(struct rte_ipv6_hdr)) {
        DEBUG_LOG(DBG_IP,"      IPv6 <truncated>\n");
        global_stats.drop_invalid_ipv6++;
        global_stats.dropped++;
        return;
    }

    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr*)pv_slice->data;

    // Fill pkt_view src/dst IPs
    inet_ntop(AF_INET6, &ip6->src_addr, pv_slice->src_ip, sizeof(pv_slice->src_ip));
    inet_ntop(AF_INET6, &ip6->dst_addr, pv_slice->dst_ip, sizeof(pv_slice->dst_ip));
    inet_ntop(AF_INET6, &ip6->src_addr, pv_full->src_ip, sizeof(pv_full->src_ip));
    inet_ntop(AF_INET6, &ip6->dst_addr, pv_full->dst_ip, sizeof(pv_full->dst_ip));

    PARSER_LOG_LAYER("IPv6", COLOR_IP, "      IPv6 ");
    print_ipv6_flow((const uint8_t *)&ip6->src_addr, (const uint8_t *)&ip6->dst_addr);
    PARSER_LOG_LAYER("IPv6", COLOR_IP, " next=%u hlim=%u\n", ip6->proto, ip6->hop_limits);

    // Walk extension headers
    const uint8_t *payload = (const uint8_t*)(ip6 + 1);
    uint16_t plen = pv_slice->len - sizeof(struct rte_ipv6_hdr);

    uint8_t nh = parse_ipv6_extensions(payload, plen, ip6->proto,
                                       pv_full, &pv_slice, now);

    // Update L4 proto
    pv_slice->l4_proto = nh;
    pv_full->l4_proto  = nh;

    // --- Offset for UDP VXLAN/GENEVE tunnels ---
    if (nh == IPPROTO_UDP && pv_slice->len >= sizeof(struct rte_udp_hdr)) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr*)payload;
        uint16_t sport = rte_be_to_cpu_16(udp->src_port);
        uint16_t dport = rte_be_to_cpu_16(udp->dst_port);

        // Adjust payload for tunnel parsing
        payload += sizeof(struct rte_udp_hdr);
        plen    -= sizeof(struct rte_udp_hdr);

        // Store UDP ports in pkt_view (optional, for parse_tunnel)
        pv_slice->src_port = sport;
        pv_slice->dst_port = dport;
    }

    pkt_view pv_payload = {
        .data     = payload,
        .len      = plen,
        .l3_proto = pv_slice->l3_proto,
        .l4_proto = nh,
    };

    // Try tunnel parsing
    if (parse_tunnel(&pv_payload)) {
        pv_full->is_tunnel = 1;
        pv_full->tunnel    = pv_payload.tunnel;
        pv_full->inner_pkt = pv_payload.inner_pkt;

        PARSER_LOG_LAYER("IPv6", COLOR_IP, "      IPv6 Tunnel detected: %s\n",
               (pv_full->tunnel.type == TUNNEL_GRE)    ? "GRE" :
               (pv_full->tunnel.type == TUNNEL_VXLAN)  ? "VXLAN" :
               (pv_full->tunnel.type == TUNNEL_GENEVE) ? "GENEVE" : "OTHER");

        if (!pv_full->tunnel_counted) {
            stats_tunnel_update(pv_full);
            pv_full->tunnel_counted = 1;
        }

        switch (pv_full->tunnel.type) {
        case TUNNEL_GRE:
            if (pv_full->tunnel.inner_proto == 0x0800)
                handle_ipv4(pv_full, pv_payload.inner_pkt, now);
            else if (pv_full->tunnel.inner_proto == 0x86DD)
                handle_ipv6(pv_full, pv_payload.inner_pkt, now);
            else {
                DEBUG_LOG(DBG_IP,"      GRE unsupported inner proto=0x%04x\n",
                       pv_full->tunnel.inner_proto);
                global_stats.drop_invalid_tunnel++;
                global_stats.dropped++;
            }
            break;

        case TUNNEL_VXLAN:
        case TUNNEL_GENEVE:
            parse_packet(pv_payload.inner_pkt);
            break;

        default:
            parse_l4(pv_full, &pv_payload, now);
            break;
        }
    } else {
        parse_l4(pv_full, &pv_payload, now);
    }

    // Free if this was a reassembled buffer
    if (pv_slice->is_reassembled) {
        capture_release(pv_slice);
    }
}
