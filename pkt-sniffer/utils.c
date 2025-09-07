#include <stdio.h>
#include "utils.h"
#include <rte_byteorder.h>
#include "debug.h"

void print_mac_flow(const uint8_t *m, const uint8_t *n) {
    PARSER_LOG_LAYER("ETH", COLOR_ETH, 
                    "%02x:%02x:%02x:%02x:%02x:%02x → %02x:%02x:%02x:%02x:%02x:%02x", 
                    m[0], m[1], m[2], m[3], m[4], m[5],
                    n[0], n[1], n[2], n[3], n[4], n[5]);
}

void print_ip_flow(uint32_t src_be_addr, uint32_t dst_be_addr) {

    uint32_t a = rte_be_to_cpu_32(src_be_addr);
    uint32_t b = rte_be_to_cpu_32(dst_be_addr);

    PARSER_LOG_LAYER("IP", COLOR_IP, 
                    "%u.%u.%u.%u → %u.%u.%u.%u", 
                    (a>>24)&0xff, (a>>16)&0xff, (a>>8)&0xff, a&0xff,
                    (b>>24)&0xff, (b>>16)&0xff, (b>>8)&0xff, b&0xff);
}

void print_icmpv6_addr(const uint8_t a[16]) 
{ 
    for (int i = 0; i < 16; i += 2) 
    { 
        PARSER_LOG_LAYER("ICMPv6", COLOR_ICMP, "%02x%02x", 
            a[i], a[i+1]); 
        if (i < 14) 
        printf(":"); 
    } 
}

void print_ipv6_flow(const uint8_t src[16], const uint8_t dst[16]) {
    char src_buf[64], dst_buf[64];

    // format IPv6 address into string
    snprintf(src_buf, sizeof(src_buf),
             "%x:%x:%x:%x:%x:%x:%x:%x",
             (src[0] << 8) | src[1], (src[2] << 8) | src[3],
             (src[4] << 8) | src[5], (src[6] << 8) | src[7],
             (src[8] << 8) | src[9], (src[10] << 8) | src[11],
             (src[12] << 8) | src[13], (src[14] << 8) | src[15]);

    snprintf(dst_buf, sizeof(dst_buf),
             "%x:%x:%x:%x:%x:%x:%x:%x",
             (dst[0] << 8) | dst[1], (dst[2] << 8) | dst[3],
             (dst[4] << 8) | dst[5], (dst[6] << 8) | dst[7],
             (dst[8] << 8) | dst[9], (dst[10] << 8) | dst[11],
             (dst[12] << 8) | dst[13], (dst[14] << 8) | dst[15]);

    // unified log like IPv4 flow
    PARSER_LOG_LAYER("IPV6", COLOR_IP, "%s → %s", src_buf, dst_buf);
}


void pkt_view_dump(const pkt_view *pv) {
    printf("=== Packet View Dump ===\n");
    printf("len       : %u bytes\n", pv->len);
    printf("kind      : %d\n", pv->kind);
    printf("l3_proto  : %d\n", pv->l3_proto);
    printf("l4_proto  : %u\n", pv->l4_proto);

    if (pv->src_ip[0] && pv->dst_ip[0]) {
        printf("src_ip    : %s\n", pv->src_ip);
        printf("dst_ip    : %s\n", pv->dst_ip);
    }

    if (pv->src_port || pv->dst_port) {
        printf("src_port  : %u\n", pv->src_port);
        printf("dst_port  : %u\n", pv->dst_port);
    }

    // Optional: dump first 64 bytes of payload for debugging
    printf("payload   : ");
    for (int i = 0; i < pv->len && i < 64; i++) {
        printf("%02x ", pv->data[i]);
    }
    if (pv->len > 64)
        printf("... (%u bytes total)", pv->len);
    printf("\n");

    printf("=========================\n\n");
}

void format_bandwidth(double bps, char *buf, size_t buflen) {
    if (bps > 1e9)
        snprintf(buf, buflen, "%.2f Gbps", bps / 1e9);
    else if (bps > 1e6)
        snprintf(buf, buflen, "%.2f Mbps", bps / 1e6);
    else if (bps > 1e3)
        snprintf(buf, buflen, "%.2f Kbps", bps / 1e3);
    else
        snprintf(buf, buflen, "%.0f bps", bps);
}