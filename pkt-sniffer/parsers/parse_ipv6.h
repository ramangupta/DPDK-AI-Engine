#ifndef PARSE_IPV6_H
#define PARSE_IPV6_H

#include <stdint.h>
#include <rte_ip.h>
#include "engine/capture.h"

typedef struct {
    const uint8_t *l4_ptr;
    uint16_t l4_len;
    uint8_t  l4_proto;
} ipv6_ext_result_t;

/* IPv6 parsing entry point */
void handle_ipv6(pkt_view *pv_full, pkt_view *pv_slice, uint64_t now);

#endif // PARSE_IPV6_H
