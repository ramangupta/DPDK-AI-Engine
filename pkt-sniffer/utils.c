#include <stdio.h>
#include "utils.h"
#include <rte_byteorder.h>

void print_mac(const uint8_t *m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void print_ipv4(uint32_t be_addr) {
    uint32_t a = rte_be_to_cpu_32(be_addr);
    printf("%u.%u.%u.%u", (a>>24)&0xff, (a>>16)&0xff, (a>>8)&0xff, a&0xff);
}

void print_ipv6_addr(const uint8_t a[16]) {
    for (int i = 0; i < 16; i += 2) {
        printf("%02x%02x", a[i], a[i+1]);
        if (i < 14) printf(":");
    }
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
