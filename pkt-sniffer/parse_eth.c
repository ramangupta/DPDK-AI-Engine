#include <stdio.h>
#include <inttypes.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include "parse_eth.h"
#include "parse_ipv4.h"
#include "parse_ipv6.h"
#include "parse_l4.h"
#include "utils.h"

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

void parse_packet(const uint8_t *data, uint16_t pktlen)
{
    if (pktlen < sizeof(struct rte_ether_hdr)) {
        printf("[len=%" PRIu16 "] <truncated ethernet>\n", pktlen);
        return;
    }

    const struct rte_ether_hdr *eth = (const struct rte_ether_hdr*)data;
    uint16_t etype = rte_be_to_cpu_16(eth->ether_type);

    parse_ethernet(eth, pktlen, etype);

    const uint8_t *p = data + sizeof(struct rte_ether_hdr);
    uint16_t rem = pktlen - sizeof(struct rte_ether_hdr);

    if (etype == RTE_ETHER_TYPE_IPV4) {
        if (rem < sizeof(struct rte_ipv4_hdr)) {
            printf("      IPv4 <truncated>\n");
            return;
        }
        const struct rte_ipv4_hdr *ip4 = (const struct rte_ipv4_hdr*)p;
        handle_ipv4(ip4, rem);
    } else if (etype == RTE_ETHER_TYPE_IPV6) {
        if (rem < sizeof(struct rte_ipv6_hdr)) {
            printf("      IPv6 <truncated>\n");
            return;
        }
        const struct rte_ipv6_hdr *ip6 = (const struct rte_ipv6_hdr*)p;
        handle_ipv6(ip6, rem);
    } else if (etype == RTE_ETHER_TYPE_ARP) {
        printf("      ARP (not decoded)\n");
    } else if (etype == RTE_ETHER_TYPE_VLAN) {
        printf("      VLAN (not decoded in this sample)\n");
    } else {
        printf("      EtherType 0x%04x not decoded\n", etype);
    }
}
