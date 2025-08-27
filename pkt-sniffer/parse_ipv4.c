#include <stdio.h>
#include <inttypes.h>
#include <rte_ip.h>
#include "parse_ipv4.h"
#include "parse_l4.h"
#include "utils.h"
#include "talkers.h"

void handle_ipv4(const struct rte_ipv4_hdr *ip4, uint16_t rem)
{
    char ipbuf[INET_ADDRSTRLEN];

    // Source IP
    inet_ntop(AF_INET, &ip4->src_addr, ipbuf, sizeof(ipbuf));
    talkers_update(ipbuf, rte_be_to_cpu_16(ip4->total_length));

    // Destination IP
    inet_ntop(AF_INET, &ip4->dst_addr, ipbuf, sizeof(ipbuf));
    talkers_update(ipbuf, rte_be_to_cpu_16(ip4->total_length));

    uint8_t ihl = (ip4->version_ihl & 0x0F) * 4;
    if (ihl < sizeof(struct rte_ipv4_hdr) || ihl > rem) {
        printf("      IPv4 <bad IHL>\n");
        return;
    }

    uint16_t tot = rte_be_to_cpu_16(ip4->total_length);
    if (tot < ihl || tot > rem) tot = rem; // tolerate mismatch

    printf("      IPv4 ");
    print_ipv4(ip4->src_addr);
    printf(" → ");
    print_ipv4(ip4->dst_addr);
    printf(" proto=%u ihl=%u tot=%u ttl=%u\n",
        ip4->next_proto_id, ihl, tot, ip4->time_to_live);

    const uint8_t *l4 = (const uint8_t*)ip4 + ihl;
    uint16_t l4len = (tot > ihl) ? (tot - ihl) : 0;
    parse_l4(l4, l4len, ip4->next_proto_id);
}
