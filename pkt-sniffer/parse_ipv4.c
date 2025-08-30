// parse_ipv4.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <rte_ip.h>
#include "parse_ipv4.h"
#include "parse_l4.h"
#include "utils.h"
#include "talkers.h"
#include "frag_ipv4.h"   // new module: buffering + reassembly
#include "capture.h"     // for pkt_view
#include "stats.h"

void handle_ipv4(pkt_view *pv_full, pkt_view *pv_slice, uint64_t now)
{
    const struct rte_ipv4_hdr *ip4 = (const struct rte_ipv4_hdr *)pv_slice->data;
    uint16_t rem = pv_slice->len;

    if (rem < sizeof(struct rte_ipv4_hdr)) {
        printf("      IPv4 <truncated>\n");
        return;
    }

    uint8_t ihl = (ip4->version_ihl & 0x0F) * 4;
    if (ihl < sizeof(struct rte_ipv4_hdr) || ihl > rem) {
        printf("      IPv4 <bad IHL>\n");
        return;
    }

    uint16_t tot = rte_be_to_cpu_16(ip4->total_length);
    if (tot < ihl || tot > rem) tot = rem; // tolerate mismatch

    // --- Fragmentation check ---
    uint16_t frag_off = rte_be_to_cpu_16(ip4->fragment_offset);
    int more_frags = frag_off & RTE_IPV4_HDR_MF_FLAG;
    int offset     = (frag_off & RTE_IPV4_HDR_OFFSET_MASK) << 3;

    printf("[ipv4] saw packet id=%u, total_length=%u, ihl=%u, proto=%u\n",
           rte_be_to_cpu_16(ip4->packet_id),
           rte_be_to_cpu_16(ip4->total_length),
           (ip4->version_ihl & 0x0F) * 4,
           ip4->next_proto_id);

    pkt_view *full = NULL;
    if (more_frags || offset > 0) {
        full = frag_reass_ipv4(ip4, pv_slice, now);  // returns full pkt_view if done
        if (!full) {
            printf("IPv4 fragment buffered (id=%u)\n",
                    rte_be_to_cpu_16(ip4->packet_id));
            // done, but still need to free original fragment
            // capture_free(pv);
            return;
        }

        // Free original fragment (it’s no longer needed)
        // capture_free(pv);
        stats_record_frag(ip4->src_addr, ip4->dst_addr, 
                          rte_be_to_cpu_16(ip4->packet_id));

        // Swap: work on reassembled
        pv_slice  = full;
        ip4 = (const struct rte_ipv4_hdr*)pv_slice->data;
        rem = pv_slice->len;

        // >>> IMPORTANT: recompute tot from the reassembled header
        tot = rte_be_to_cpu_16(ip4->total_length);
        printf("IPv4 reassembled (id=%u len=%u)\n",
               rte_be_to_cpu_16(ip4->packet_id), pv_slice->len);
    }

    // --- Print header ---
    printf("      IPv4 ");
    print_ipv4(ip4->src_addr);
    printf(" → ");
    print_ipv4(ip4->dst_addr);
    printf(" proto=%u ihl=%u tot=%u ttl=%u\n",
        ip4->next_proto_id, ihl, tot, ip4->time_to_live);

    // --- L4 ---
    // const uint8_t *l4 = (const uint8_t*)ip4 + ihl;
    // uint16_t l4len = (tot > ihl) ? (tot - ihl) : 0;
    char srcbuf[64], dstbuf[64];
    snprintf(srcbuf, sizeof(srcbuf), "%u.%u.%u.%u",
            ip4->src_addr & 0xff, (ip4->src_addr >> 8) & 0xff,
            (ip4->src_addr >> 16) & 0xff, (ip4->src_addr >> 24) & 0xff);
    snprintf(dstbuf, sizeof(dstbuf), "%u.%u.%u.%u",
            ip4->dst_addr & 0xff, (ip4->dst_addr >> 8) & 0xff,
            (ip4->dst_addr >> 16) & 0xff, (ip4->dst_addr >> 24) & 0xff);

    pkt_view pv_l4 = {
        .data   = (uint8_t*)ip4 + ihl,
        .len    = (tot > ihl) ? (tot - ihl) : 0,
        .l3_proto = pv_slice->l3_proto,
        .l4_proto = ip4->next_proto_id,
        .src_port = 0, // will be filled later in parse_l4 if TCP/UDP
        .dst_port = 0,
    };
    snprintf(pv_l4.src_ip, sizeof(pv_l4.src_ip), "%s", srcbuf);
    snprintf(pv_l4.dst_ip, sizeof(pv_l4.dst_ip), "%s", dstbuf);

    snprintf(pv_full->src_ip, sizeof(pv_full->src_ip), "%s", srcbuf);
    snprintf(pv_full->dst_ip, sizeof(pv_full->dst_ip), "%s", dstbuf);
    pv_full->l3_proto = pv_l4.l3_proto;
    pv_full->l4_proto = pv_l4.l4_proto;

    parse_l4(pv_full, &pv_l4);

    // Free if this was a reassembled buffer (AFP case)
    if (full) {
        capture_release(full); // AFP: free malloc, DPDK: free mbufs
    }
}
