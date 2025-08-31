// tcp_reass.h
#ifndef TCP_REASS_H
#define TCP_REASS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#define MAX_TCP_STREAMS   1024      // number of concurrent streams
#define TCP_TIMEOUT_SEC   60        // idle timeout
#define TCP_REASS_HASH_BUCKETS 4096
#define TCP_REASS_FLOW_TIMEOUT_SEC 120

typedef struct tcp_seg {
    uint32_t seq;            // host order
    uint32_t len;
    uint8_t *data;
    time_t ts;
    struct tcp_seg *next;
} tcp_seg_t;

typedef struct {
    bool in_use;
    char src_ip[64];
    char dst_ip[64];
    uint16_t src_port;
    uint16_t dst_port;

    uint32_t next_seq;              // next expected sequence
    tcp_seg_t *frags;               // out-of-order fragments

    uint64_t last_activity;         // for cleanup
} tcp_stream_t;

struct tcp_flow {
    char src_ip[64];
    char dst_ip[64];
    uint16_t src_port;
    uint16_t dst_port;
    tcp_seg_t *s2d_head; // src->dst buffered segments (where src==pv_full->src_ip)
    tcp_seg_t *d2s_head; // dst->src
    uint32_t next_s2d;   // next expected seq for s->d
    uint32_t next_d2s;   // next expected seq for d->s
    time_t last_seen;
    int seen_syn;
    int seen_fin;
    struct tcp_flow *next; // hash chain
};

// global stream table
extern tcp_stream_t streams[MAX_TCP_STREAMS];

typedef struct tcp_flow tcp_flow_t;

// deliver callback invoked when contiguous bytes are ready
// dir: 0 = src->dst (pv_full direction), 1 = dst->src
typedef void (*tcp_reass_deliver_cb)(tcp_flow_t *flow, int dir,
                                     const uint8_t *data, uint32_t len,
                                     time_t ts, void *user_ctx);

// initialize/cleanup
int tcp_reass_init(void);
void tcp_reass_fini(void);

// Process an incoming TCP segment
// src_ip/dst_ip are null-terminated printable ip strings (from pv_full)
// seq is host order (caller should use rte_be_to_cpu_32(th->sent_seq))
// flags are raw tcp flags (th->tcp_flags)
void tcp_reass_process_segment(const char *src_ip, const char *dst_ip,
                               uint16_t src_port, uint16_t dst_port,
                               const uint8_t *payload, uint32_t payload_len,
                               uint32_t seq, uint8_t flags, time_t ts,
                               tcp_reass_deliver_cb deliver_cb, void *user_ctx);

// periodic maintenance; call once per second (or so)
// tcp_reass.h
void tcp_reass_periodic_maintenance(uint64_t now_sec);

void tcp_reass_flush_stream(tcp_stream_t *st);

#endif // TCP_REASS_H
