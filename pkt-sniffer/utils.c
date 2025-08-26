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