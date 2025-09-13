#include "parse_data.h"
#include "engine/capture.h"
#include "parsers/parse_l4.h"
#include "utils/debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tsc.h" 
#include <time.h>
#include <arpa/inet.h>  // for htons, htonl

#include "utils/sniffer_signal.h"
#include "parsers/frag_ipv4.h"
#include "parsers/tcp_reass.h"
#include "parsers/parse_eth.h"

#define FIX_SOH 0x01
#define ETH_MTU 3000
#define ETH_HDR_LEN 14
#define IP_HDR_LEN  20
#define TCP_HDR_LEN 20
#define MAX_PAYLOAD 4096

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t tcp_seq;
} flow_ctx_t;

struct eth_hdr {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
};

struct ipv4_hdr {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t checksum;
    uint32_t saddr;
    uint32_t daddr;
};

struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  data_off; // upper 4 bits
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};

// Generators
size_t generate_FIX(uint8_t *buf, size_t buf_size);
size_t generate_ITCH(uint8_t *buf, size_t buf_size);
size_t generate_SBE(uint8_t *buf, size_t buf_size);
