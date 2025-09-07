// parse_tunnel.c
#include "parse_tunnel.h"
#include <stdio.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include "capture.h"

// ------------------------------
// GRE Header Definition
// ------------------------------
struct rte_gre_hdr {
    uint16_t flags; // C, K, S, Recur, Protocol type high bits
    uint16_t proto; // Protocol type (ETHERTYPE)
} __attribute__((packed));

// ------------------------------
// Generic Tunnel Parser
// ------------------------------
int parse_tunnel(pkt_view *outer)
{
    const uint8_t *pkt = outer->data;
    size_t len = outer->len;
    uint8_t l4_proto_hint = outer->l4_proto;

    if (!pkt || len < 4) return 0;

    memset(&outer->tunnel, 0, sizeof(outer->tunnel));
    outer->is_tunnel = 0;
    outer->inner_pkt = NULL;

    // --- GRE Tunnel ---
    if (l4_proto_hint == IPPROTO_GRE) {
        if (len < sizeof(struct rte_gre_hdr)) return 0;

        const struct rte_gre_hdr *gre = (const struct rte_gre_hdr *)pkt;
        uint16_t flags = rte_be_to_cpu_16(gre->flags);
        uint16_t proto = rte_be_to_cpu_16(gre->proto);

        int gre_hdr_len = sizeof(struct rte_gre_hdr);
        if (flags & 0x2000) gre_hdr_len += 4; // Key present
        if (flags & 0x1000) gre_hdr_len += 4; // Sequence present
        if (len < gre_hdr_len) return 0;

        outer->tunnel.type        = TUNNEL_GRE;
        outer->tunnel.inner_proto = proto;
        outer->tunnel.vni         = 0;
        outer->tunnel.gre_flags   = flags;

        pkt_view *inner = calloc(1, sizeof(pkt_view));
        inner->data = pkt + gre_hdr_len;
        inner->len  = len - gre_hdr_len;
        inner->kind = PV_KIND_HEAP;

        outer->inner_pkt = inner;
        outer->is_tunnel = 1;

        return 1;
    }

    // --- UDP-based tunnels (VXLAN / GENEVE) ---
    if (l4_proto_hint == IPPROTO_UDP && len >= sizeof(struct rte_udp_hdr)) {
        const struct rte_udp_hdr *udp = (const struct rte_udp_hdr *)pkt;
        uint16_t dst_port = rte_be_to_cpu_16(udp->dst_port);
        const uint8_t *payload = pkt + sizeof(struct rte_udp_hdr);
        size_t payload_len = len - sizeof(struct rte_udp_hdr);

        // VXLAN
        if (dst_port == 4789 && payload_len >= 8) {
            uint32_t vni = (payload[4] << 16) | (payload[5] << 8) | payload[6];

            outer->tunnel.type = TUNNEL_VXLAN;
            outer->tunnel.vni  = vni;

            pkt_view *inner = calloc(1, sizeof(pkt_view));
            inner->data = payload + 8;
            inner->len  = payload_len - 8;
            inner->kind = PV_KIND_HEAP;

            outer->inner_pkt = inner;
            outer->is_tunnel = 1;

            return 1;
        }

        // GENEVE
        if (dst_port == 6081 && payload_len >= 8) {
            uint8_t ver_opt = payload[0];
            uint8_t opt_len = (ver_opt & 0x3F) * 4;
            if (payload_len < 8 + opt_len) return 0;

            uint32_t vni = (payload[4] << 16) | (payload[5] << 8) | payload[6];

            outer->tunnel.type = TUNNEL_GENEVE;
            outer->tunnel.vni  = vni;

            pkt_view *inner = calloc(1, sizeof(pkt_view));
            inner->data = payload + 8 + opt_len;
            inner->len  = payload_len - 8 - opt_len;
            inner->kind = PV_KIND_HEAP;

            outer->inner_pkt = inner;
            outer->is_tunnel = 1;

            return 1;
        }
    }

    return 0; // no tunnel detected
}
