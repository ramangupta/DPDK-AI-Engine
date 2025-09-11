#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define FLOW_MAX  10240   /* arbitrary limit for now */
#define FLOW_TIMEOUT_NS (30ULL * 1000000000ULL)  // 30s

typedef struct {
    int ip_version;     // 4 or 6
    uint8_t proto;
    uint8_t src_ip[16];
    uint8_t dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
} flow_key_t;

typedef struct {
    flow_key_t key;
    uint64_t pkts;
    uint64_t bytes;
    uint64_t first_seen;
    uint64_t last_seen;
    bool     in_use;    // active slot or not
} flow_entry_t;

extern flow_entry_t flow_table[FLOW_MAX];
extern int flow_count;

void flow_key_build(flow_key_t *key,
                    int ip_version,
                    const char *src_ip,
                    const char *dst_ip,
                    uint8_t proto,
                    uint16_t src_port,
                    uint16_t dst_port);

void flow_update(const flow_key_t *key, uint16_t pktlen);
void flow_report(void);
void flow_reset(void);
void flow_expire(uint64_t now_ns);
