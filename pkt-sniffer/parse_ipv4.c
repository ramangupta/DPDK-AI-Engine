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

void handle_ipv4(pkt_view *pv, uint64_t now)
{
    const struct rte_ipv4_hdr *ip4 = (const struct rte_ipv4_hdr *)pv->data;
    uint16_t rem = pv->len;
    char ipbuf[INET_ADDRSTRLEN];

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
        full = frag_reass_ipv4(ip4, pv, now);  // returns full pkt_view if done
        if (!full) {
            printf("IPv4 fragment buffered (id=%u)\n",
                    rte_be_to_cpu_16(ip4->packet_id));
            // done, but still need to free original fragment
            // capture_free(pv);
            return;
        }

        // Free original fragment (it’s no longer needed)
        // capture_free(pv);

        // Swap: work on reassembled
        pv  = full;
        ip4 = (const struct rte_ipv4_hdr*)pv->data;
        rem = pv->len;

        // >>> IMPORTANT: recompute tot from the reassembled header
        tot = rte_be_to_cpu_16(ip4->total_length);
        printf("IPv4 reassembled (id=%u len=%u)\n",
               rte_be_to_cpu_16(ip4->packet_id), pv->len);
    }

    // --- Talkers update ---
    inet_ntop(AF_INET, &ip4->src_addr, ipbuf, sizeof(ipbuf));
    talkers_update(ipbuf, tot);
    inet_ntop(AF_INET, &ip4->dst_addr, ipbuf, sizeof(ipbuf));
    talkers_update(ipbuf, tot);

    // --- Print header ---
    printf("      IPv4 ");
    print_ipv4(ip4->src_addr);
    printf(" → ");
    print_ipv4(ip4->dst_addr);
    printf(" proto=%u ihl=%u tot=%u ttl=%u\n",
        ip4->next_proto_id, ihl, tot, ip4->time_to_live);

    // --- L4 ---
    const uint8_t *l4 = (const uint8_t*)ip4 + ihl;
    uint16_t l4len = (tot > ihl) ? (tot - ihl) : 0;
    parse_l4(l4, l4len, ip4->next_proto_id);

    // Free if this was a reassembled buffer (AFP case)
    if (full) {
        capture_release(full); // AFP: free malloc, DPDK: free mbufs
    }
}
