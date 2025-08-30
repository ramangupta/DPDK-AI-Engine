#include <stdio.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <arpa/inet.h>
#include "parse_ipv6.h"
#include "parse_l4.h"
#include "utils.h"
#include "talkers.h"
#include "frag_ipv4.h"   // new frag reassembly API

// ---------------- IPv6 Extensions Parsing ----------------
void parse_ipv6_extensions(const uint8_t *data, uint16_t len,
                           uint8_t next_header, pkt_view *pv_full,
                           pkt_view *pv_slice,
                           uint64_t now)
{
    const uint8_t *ptr = data;
    uint16_t remaining = len;
    uint8_t nh = next_header;

    while (1) {
        if (nh == IPPROTO_HOPOPTS || nh == IPPROTO_ROUTING ||
            nh == IPPROTO_DSTOPTS || nh == IPPROTO_FRAGMENT ||
            nh == IPPROTO_AH || nh == IPPROTO_ESP) {

            if (remaining < 2) {
                printf("      IPv6 ext <truncated>\n");
                return;
            }

            uint8_t ext_len;
            if (nh == IPPROTO_AH) {
                ext_len = (ptr[1] + 2) * 4;  // AH header special length
            } else {
                ext_len = (ptr[1] + 1) * 8;
            }

            if (ext_len > remaining) {
                printf("      IPv6 ext <bad len>\n");
                return;
            }

            // --- Handle Fragment Header ---
            if (nh == IPPROTO_FRAGMENT) {
                uint16_t frag_off = rte_be_to_cpu_16(*(uint16_t*)(ptr + 2));
                int more_frags = (frag_off & 0x1) != 0;
                uint32_t offset = (frag_off & 0xfff8) << 3;

                pkt_view *full = frag_reass_ipv6(ptr, pv_slice, offset, more_frags, now);
                if (!full) {
                    printf("IPv6 fragment buffered\n");
                    return; // wait for more fragments
                }

                // Replace pv with reassembled packet
                pv_slice = full;
                ptr = pv_slice->data + sizeof(struct rte_ipv6_hdr);
                remaining = pv_slice->len - sizeof(struct rte_ipv6_hdr);
                nh = ((struct rte_ipv6_hdr*)pv_slice->data)->proto;
                printf("IPv6 reassembled\n");
                continue;
            }

            nh = ptr[0]; // next header
            ptr += ext_len;
            remaining -= ext_len;

        } else {
            // reached L4 header
            parse_l4(pv_full, pv_slice);
            return;
        }
    }
}

// ---------------- Handle IPv6 ----------------
void handle_ipv6(pkt_view *pv_full, pkt_view *pv_slice, uint64_t now)
{
    if (pv_slice->len < sizeof(struct rte_ipv6_hdr)) {
        printf("      IPv6 <truncated>\n");
        return;
    }

    const struct rte_ipv6_hdr *ip6 = (const struct rte_ipv6_hdr*)pv_slice->data;

    // Fill pkt_view src/dst IPs
    inet_ntop(AF_INET6, &ip6->src_addr, pv_slice->src_ip, sizeof(pv_slice->src_ip));
    inet_ntop(AF_INET6, &ip6->dst_addr, pv_slice->dst_ip, sizeof(pv_slice->dst_ip));
    inet_ntop(AF_INET6, &ip6->src_addr, pv_full->src_ip, sizeof(pv_full->src_ip));
    inet_ntop(AF_INET6, &ip6->dst_addr, pv_full->dst_ip, sizeof(pv_full->dst_ip));
    pv_slice->l4_proto = ip6->proto;
    pv_full->l4_proto = ip6->proto;

    printf("      IPv6 ");
    print_ipv6_addr((const uint8_t *)&ip6->src_addr);
    printf(" → ");
    print_ipv6_addr((const uint8_t *)&ip6->dst_addr);
    printf(" next=%u hlim=%u\n", ip6->proto, ip6->hop_limits);

    // Walk extension headers, handle fragment, and parse L4
    const uint8_t *payload = (const uint8_t*)(ip6 + 1);
    uint16_t plen = pv_slice->len - sizeof(struct rte_ipv6_hdr);

    parse_ipv6_extensions(payload, plen, ip6->proto, pv_full, pv_slice, now);
}
