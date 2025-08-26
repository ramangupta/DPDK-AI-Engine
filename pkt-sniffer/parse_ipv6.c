#include <stdio.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include "parse_ipv6.h"
#include "parse_l4.h"
#include "utils.h"

void parse_ipv6_extensions(const uint8_t *data, uint16_t len, uint8_t next_header)
{
    const uint8_t *ptr = data;
    uint16_t remaining = len;
    uint8_t nh = next_header;

    // Walk through extension headers
    while (1) {
        if (nh == IPPROTO_HOPOPTS || nh == IPPROTO_ROUTING ||
            nh == IPPROTO_DSTOPTS || nh == IPPROTO_FRAGMENT ||
            nh == IPPROTO_AH || nh == IPPROTO_ESP) {

            if (remaining < 2) {
                printf("      IPv6 ext <truncated>\n");
                return;
            }

            uint8_t ext_len = (ptr[1] + 1) * 8; // extension header length
            printf("      IPv6 ext hdr=%u len=%u\n", nh, ext_len);

            if (ext_len > remaining) {
                printf("      IPv6 ext <bad len>\n");
                return;
            }

            nh = ptr[0];  // next header field of ext hdr
            ptr += ext_len;
            remaining -= ext_len;

        } else {
            // reached L4 header
            parse_l4(ptr, remaining, nh);
            return;
        }
    }
}

void handle_ipv6(const struct rte_ipv6_hdr *ip6, uint16_t pktlen)
{
    if (pktlen < sizeof(struct rte_ipv6_hdr)) {
        printf("      IPv6 <truncated>\n");
        return;
    }

    printf("      IPv6 ");
    print_ipv6_addr((const uint8_t *)&ip6->src_addr);
    printf(" → ");
    print_ipv6_addr((const uint8_t *)&ip6->dst_addr);
    printf(" next=%u hlim=%u\n", ip6->proto, ip6->hop_limits);

    const uint8_t *payload = (const uint8_t*)(ip6 + 1);
    uint16_t plen = pktlen - sizeof(struct rte_ipv6_hdr);

    parse_ipv6_extensions(payload, plen, ip6->proto);
}

