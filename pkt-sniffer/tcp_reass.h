#ifndef TCP_REASS_H
#define TCP_REASS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#define TCP_REASS_HASH_BUCKETS       4096
#define TCP_REASS_FLOW_TIMEOUT_SEC   120

/* Opaque tcp_flow type exposed to callers */
typedef struct tcp_flow tcp_flow_t;

/* TCP segment node (exported because it may be used elsewhere for debug) */
typedef struct tcp_seg {
    uint32_t seq;            /* host order */
    uint32_t len;
    uint8_t *data;
    time_t ts;
    struct tcp_seg *next;
} tcp_seg_t;

/* deliver callback invoked when contiguous bytes are ready.
 * dir: 0 = src->dst (initiator → responder), 1 = dst->src
 * NOTE: 'flow' pointer is valid during callback but callers must not free it there.
 */
typedef void (*tcp_reass_deliver_cb)(tcp_flow_t *flow, int dir,
                                     const uint8_t *data, uint32_t len,
                                     time_t ts, void *user_ctx);

/* Initialize / finalize */
int  tcp_reass_init(void);
void tcp_reass_fini(void);

/* Main entry: process an incoming TCP segment.
 * - src_ip/dst_ip: printable null-terminated IP strings (caller-owned)
 * - payload: caller-owned memory (reassembler copies when buffering)
 * - seq: host-order sequence (caller converts from network order)
 * - ts: seconds (time_t) — typically time(NULL) or now_tsc converted to sec
 */
void tcp_reass_process_segment(const char *src_ip, const char *dst_ip,
                               uint16_t src_port, uint16_t dst_port,
                               const uint8_t *payload, uint32_t payload_len,
                               uint32_t seq, uint8_t flags, time_t ts,
                               tcp_reass_deliver_cb deliver_cb, void *user_ctx);

/* Periodic maintenance — call roughly once a second with current seconds (time_t) */
void tcp_reass_periodic_maintenance(time_t now_sec);

// Getter functions to keep tcp_flow opaque
const char *tcp_flow_src_ip(const tcp_flow_t *flow);
uint16_t    tcp_flow_src_port(const tcp_flow_t *flow);
const char *tcp_flow_dst_ip(const tcp_flow_t *flow);
uint16_t    tcp_flow_dst_port(const tcp_flow_t *flow);


#endif /* TCP_REASS_H */
