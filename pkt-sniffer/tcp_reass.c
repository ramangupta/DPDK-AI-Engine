// tcp_reass.c
#define _GNU_SOURCE
#include "tcp_reass.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "capture.h"
#include "parse_http.h"
#include "parse_tls.h"
#include "stats.h"

// Debug toggle
#ifndef TCP_DEBUG
#define TCP_DEBUG 1
#endif

#if TCP_DEBUG
#define DEBUG_PRINT(fmt, ...) \
    fprintf(stderr, "[TCP_REASS][%s:%d] " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) do {} while (0)
#endif

/* Config knobs (override at compile time if needed) */
#ifndef TCP_REASS_FLOW_TIMEOUT_SEC
#define TCP_REASS_FLOW_TIMEOUT_SEC 120
#endif

#ifndef TCP_FIN_LINGER_SEC
#define TCP_FIN_LINGER_SEC 10
#endif

#ifndef TCP_PER_FLOW_CAP_BYTES
#define TCP_PER_FLOW_CAP_BYTES (1024*1024) /* 1 MiB per direction */
#endif

/* ---------- Internal tcp_flow definition (opaque externally) ---------- */
struct tcp_flow {
    char src_ip[64];
    char dst_ip[64];
    uint16_t src_port;
    uint16_t dst_port;

    tcp_seg_t *s2d_head;     /* src->dst buffered segments */
    tcp_seg_t *d2s_head;     /* dst->src buffered segments */

    uint32_t next_s2d;       /* next expected seq src->dst */
    uint32_t next_d2s;       /* next expected seq dst->src */

    uint32_t s2d_bytes_buf;  /* buffered bytes in s->d queue */
    uint32_t d2s_bytes_buf;  /* buffered bytes in d->s queue */

    time_t last_seen;
    time_t close_mark_ts;    /* non-zero when FIN/RST seen; used for linger */
    int seen_syn;
    int seen_fin;

    struct tcp_flow *next;   /* hash chain */
};

// -------- Globals --------
static tcp_flow_t *flow_table[TCP_REASS_HASH_BUCKETS];

// -------- Getters --------
// tcp_reass.c
const char *tcp_flow_src_ip(const tcp_flow_t *flow) { return flow->src_ip; }
uint16_t    tcp_flow_src_port(const tcp_flow_t *flow) { return flow->src_port; }
const char *tcp_flow_dst_ip(const tcp_flow_t *flow) { return flow->dst_ip; }
uint16_t    tcp_flow_dst_port(const tcp_flow_t *flow) { return flow->dst_port; }

// -------- Helpers --------
static inline uint32_t flow_hash(const char *saddr, const char *daddr,
                                 uint16_t sport, uint16_t dport) {
    uint32_t h = 5381;
    const char *p = saddr;
    while (*p) h = ((h << 5) + h) ^ *p++;
    p = daddr;
    while (*p) h = ((h << 5) + h) ^ *p++;
    h ^= sport; h ^= dport;
    return h % TCP_REASS_HASH_BUCKETS;
}

static inline int seq_lt(uint32_t a, uint32_t b) {
    return (int32_t)(a - b) < 0;
}
static inline int seq_gt(uint32_t a, uint32_t b) {
    return (int32_t)(a - b) > 0;
}

// -------- Segment handling --------
static tcp_seg_t *seg_new(const uint8_t *data, uint32_t len, uint32_t seq, time_t ts) {
    tcp_seg_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->seq = seq;
    s->len = len;
    s->ts  = ts;
    s->next = NULL;
    if (len > 0) {
        s->data = malloc(len);
        if (!s->data) { free(s); return NULL; }
        memcpy(s->data, data, len);
    } else {
        s->data = NULL;
    }
    return s;
}

// Insert segment in sorted order, trimming overlaps
static void insert_seg_sorted(tcp_seg_t **head, tcp_seg_t *s) {
    if (!*head) { 
        *head = s; 
        DEBUG_PRINT("Inserted first segment: seq=%u len=%u", s->seq, s->len);
        return; 
    }

    tcp_seg_t **cur = head;
    while (*cur && seq_lt((*cur)->seq, s->seq)) 
        cur = &(*cur)->next;

    // Trim overlap with previous
    if (cur != head) {
        tcp_seg_t *prev = *head;
        while (prev->next != *cur) prev = prev->next;
        uint32_t prev_end = prev->seq + prev->len;
        if (prev_end > s->seq) {
            uint32_t ov = prev_end - s->seq;
            if (ov >= s->len) {
                DEBUG_PRINT("Dropped fully duplicate segment at seq=%u len=%u", s->seq, s->len);
                free(s->data); free(s); return;
            }
            DEBUG_PRINT("Trimmed %u bytes overlap with previous (seq=%u)", ov, s->seq);
            memmove(s->data, s->data + ov, s->len - ov);
            s->seq += ov;
            s->len -= ov;
        }
    }

    // Trim overlap with next
    if (*cur) {
        uint32_t cur_start = (*cur)->seq;
        if (s->seq + s->len > cur_start) {
            uint32_t ov = (s->seq + s->len) - cur_start;
            if (ov >= s->len) {
                DEBUG_PRINT("Dropped segment fully overlapped by next at seq=%u len=%u", s->seq, s->len);
                free(s->data); free(s); return;
            }
            DEBUG_PRINT("Trimmed %u bytes overlap with next (seq=%u)", ov, s->seq);
            s->len -= ov;
        }
    }

    s->next = *cur;
    *cur = s;

    // update per-flow buffer accounting (caller's context must provide which queue)

    DEBUG_PRINT("inserted seg seq=%u len=%u", s->seq, s->len);
    // NOTE: we cannot access flow directly here, so update counters from caller

    DEBUG_PRINT("Queue after insert:");
    tcp_seg_t *tmp = *head;
    while (tmp) {
        DEBUG_PRINT("   seg seq=%u len=%u", tmp->seq, tmp->len);
        tmp = tmp->next;
    }

}

// Try to deliver in-order segments to callback
static void try_deliver(tcp_flow_t *f, tcp_seg_t **head, uint32_t *next_expected,
                        int dir, tcp_reass_deliver_cb cb, void *user_ctx)
{
    while (*head) {
        tcp_seg_t *h = *head;

        // Stop if the next segment starts after what we expect → gap
        if (seq_gt(h->seq, *next_expected)) {
            /* Waiting for missing bytes */
            DEBUG_PRINT("Gap detected: seg_seq=%u next_expected=%u dir=%d",
                        h->seq, *next_expected, dir);
            stats_tcp_out_of_order();
            break;
        }

        uint32_t off = 0;
        if (seq_lt(h->seq, *next_expected)) {
            // Segment starts before our expected seq (overlap/duplicate)
            off = *next_expected - h->seq;
            if (off >= h->len) {
                // Entire segment already delivered → drop
                DEBUG_PRINT("Dropping fully duplicate seg: seq=%u len=%u dir=%d",
                            h->seq, h->len, dir);
                stats_tcp_duplicate();
                *head = h->next;
                free(h->data);
                free(h);
                continue;
            }
            stats_tcp_overlap();
            DEBUG_PRINT("Partial overlap: seg_seq=%u off=%u adjusted_len=%u dir=%d",
                        h->seq, off, h->len - off, dir);
        }

        uint32_t deliver_len = h->len - off;
        const uint8_t *deliver_ptr = h->data + off;

        // Deliver payload if non-empty
        if (deliver_len && cb) {
            DEBUG_PRINT("Delivering %u bytes dir=%d seq=%u (expected=%u)",
                        deliver_len, dir, h->seq + off, *next_expected);
            cb(f, dir, deliver_ptr, deliver_len, f->last_seen, user_ctx);
        }

        // Advance expected sequence number
        *next_expected = h->seq + h->len;
        DEBUG_PRINT("Updated next_expected=%u dir=%d", *next_expected, dir);

        // adjust per-flow buffer accounting
        if (dir == 0) {
            if (f->s2d_bytes_buf >= (h->len - off)) f->s2d_bytes_buf -= (h->len - off);
            else f->s2d_bytes_buf = 0;
        } else {
            if (f->d2s_bytes_buf >= (h->len - off)) f->d2s_bytes_buf -= (h->len - off);
            else f->d2s_bytes_buf = 0;
        }

        // Remove from list
        *head = h->next;
        free(h->data);
        free(h);
    }
}

/* ---------- Flow management ---------- */
/* Lookup forward bucket first; if not found try reverse bucket */
static tcp_flow_t *flow_lookup_bidir(const char *src, const char *dst,
                                     uint16_t sport, uint16_t dport) {
    uint32_t h = flow_hash(src, dst, sport, dport);
    for (tcp_flow_t *f = flow_table[h]; f; f = f->next) {
        if (f->src_port == sport && f->dst_port == dport &&
            strcmp(f->src_ip, src) == 0 && strcmp(f->dst_ip, dst) == 0) {
            return f;
        }
    }
    /* not found in forward bucket — try reverse key */
    uint32_t hr = flow_hash(dst, src, dport, sport);
    for (tcp_flow_t *f = flow_table[hr]; f; f = f->next) {
        if (f->src_port == dport && f->dst_port == sport &&
            strcmp(f->src_ip, dst) == 0 && strcmp(f->dst_ip, src) == 0) {
            return f;
        }
    }
    return NULL;
}

static tcp_flow_t *flow_create(const char *src, const char *dst,
                               uint16_t sport, uint16_t dport, time_t ts) {
    tcp_flow_t *f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    strncpy(f->src_ip, src, sizeof(f->src_ip) - 1);
    strncpy(f->dst_ip, dst, sizeof(f->dst_ip) - 1);
    f->src_port = sport;
    f->dst_port = dport;
    f->next_s2d = f->next_d2s = 0;
    f->s2d_head = f->d2s_head = NULL;
    f->s2d_bytes_buf = f->d2s_bytes_buf = 0;
    f->last_seen = ts;
    f->close_mark_ts = 0;
    f->seen_syn = f->seen_fin = 0;

    uint32_t h = flow_hash(src, dst, sport, dport);
    f->next = flow_table[h];
    flow_table[h] = f;
    DEBUG_PRINT("Created new flow %s:%u -> %s:%u", src, sport, dst, dport);
    return f;
}

static void flow_free(tcp_flow_t *f) {
    if (!f) return;
    tcp_seg_t *s, *n;
    for (s = f->s2d_head; s; s = n) { n = s->next; free(s->data); free(s); }
    for (s = f->d2s_head; s; s = n) { n = s->next; free(s->data); free(s); }
    free(f);
}

// -------- Public API --------
int tcp_reass_init(void) {
    memset(flow_table, 0, sizeof(flow_table));
    DEBUG_PRINT("TCP reassembly initialized");
    return 0;
}

void tcp_reass_fini(void) {
    for (size_t i = 0; i < TCP_REASS_HASH_BUCKETS; i++) {
        tcp_flow_t *f = flow_table[i];
        while (f) {
            tcp_flow_t *n = f->next;
            flow_free(f);
            f = n;
        }
        flow_table[i] = NULL;
    }
    DEBUG_PRINT("TCP reassembly finalized, all flows freed");
}

// --- Main entry ---
void tcp_reass_process_segment(const char *src_ip, const char *dst_ip,
                               uint16_t src_port, uint16_t dst_port,
                               const uint8_t *payload, uint32_t payload_len,
                               uint32_t seq, uint8_t flags, time_t ts,
                               tcp_reass_deliver_cb deliver_cb, void *user_ctx)
{
    // Log every segment arrival
    DEBUG_PRINT("Segment %s:%u → %s:%u | seq=%u | len=%u | flags=0x%x",
                src_ip, src_port, dst_ip, dst_port, seq, payload_len, flags);

    stats_tcp_segment(payload_len);

    // Lookup or create flow
    tcp_flow_t *f = flow_lookup_bidir(src_ip, dst_ip, src_port, dst_port);
    int created = 0;
    if (!f) {
        f = flow_create(src_ip, dst_ip, src_port, dst_port, ts);
        created = 1;
        DEBUG_PRINT("Flow created for %s:%u ↔ %s:%u", 
                    src_ip, src_port, dst_ip, dst_port);
    }
    if (!f) return;
    f->last_seen = ts;

    // Direction: dir=0 means src→dst matches flow's tuple, otherwise 1
    int dir = (strcmp(f->src_ip, src_ip) == 0 && strcmp(f->dst_ip, dst_ip) == 0 &&
               f->src_port == src_port && f->dst_port == dst_port) ? 0 : 1;
    DEBUG_PRINT("Flow %p dir=%d", (void*)f, dir);

    // Handle new flow initialization
    if (created && (flags & 0x02)) {  // SYN seen
        if (dir == 0) f->next_s2d = seq + 1;
        else f->next_d2s = seq + 1;
        DEBUG_PRINT("New flow with SYN: dir=%d ISN=%u", dir, seq);

    } else if (created && payload_len > 0) {
        // Flow created mid-stream (no SYN) → treat seq+len as starting point
        if (dir == 0) f->next_s2d = seq + payload_len;
        else f->next_d2s = seq + payload_len;
        DEBUG_PRINT("New flow mid-stream: dir=%d start_seq=%u", dir, seq);
    }

    // update syn/fin markers
    if (flags & 0x02) f->seen_syn = 1;
    if (flags & 0x01) {
        f->seen_fin = 1;
        if (f->close_mark_ts == 0) f->close_mark_ts = ts;
        DEBUG_PRINT("FIN seen, mark close_ts=%ld", (long)f->close_mark_ts);
    }

    if (flags & 0x04) { // RST
        f->seen_fin = 1;
        if (f->close_mark_ts == 0) f->close_mark_ts = ts;
        DEBUG_PRINT("RST seen, mark close_ts=%ld", (long)f->close_mark_ts);
    }

    if (payload_len == 0) {
        DEBUG_PRINT("Control packet (no payload) return");
        return;
    }

    tcp_seg_t *seg = seg_new(payload, payload_len, seq, ts);
    if (!seg) return;

    if (dir == 0) {
        // s2d direction
        insert_seg_sorted(&f->s2d_head, seg);

        /* Update accounting using the final seg->len (insert may have trimmed it) */
        f->s2d_bytes_buf += seg->len;
        if (f->s2d_bytes_buf > TCP_PER_FLOW_CAP_BYTES) {
            // drop the inserted seg to protect memory
            DEBUG_PRINT("Per-flow s2d cap exceeded (%u bytes) — dropping seg seq=%u len=%u",
                        f->s2d_bytes_buf, seg->seq, seg->len);
            // remove the seg we just inserted (it will be at correct position; easiest: traverse and remove first match)
            // simple remove of the exact pointer `seg`
            tcp_seg_t **pp = &f->s2d_head;
            while (*pp && *pp != seg) pp = &(*pp)->next;
            if (*pp == seg) {
                *pp = seg->next;
                free(seg->data); free(seg);
            }
            // reduce counter conservatively (we dropped seg->len)
            if (f->s2d_bytes_buf >= seg->len) f->s2d_bytes_buf -= seg->len;
            else f->s2d_bytes_buf = 0;
            return;
        }

        try_deliver(f, &f->s2d_head, &f->next_s2d, 0, deliver_cb, user_ctx);
        // after try_deliver, some segs delivered — recompute buffer counter by scanning list or subtract delivered bytes inside try_deliver
        // (we'll subtract delivered bytes in try_deliver later)
    } else {
        // d2s direction
        insert_seg_sorted(&f->d2s_head, seg);
        f->d2s_bytes_buf += seg->len;
        if (f->d2s_bytes_buf > TCP_PER_FLOW_CAP_BYTES) {
            DEBUG_PRINT("Per-flow d2s cap exceeded (%u bytes) — dropping seg seq=%u len=%u",
                        f->d2s_bytes_buf, seg->seq, seg->len);
            tcp_seg_t **pp = &f->d2s_head;
            while (*pp && *pp != seg) pp = &(*pp)->next;
            if (*pp == seg) {
                *pp = seg->next;
                free(seg->data); free(seg);
            }
            if (f->d2s_bytes_buf >= seg->len) f->d2s_bytes_buf -= seg->len;
            else f->d2s_bytes_buf = 0;
            return;
        }

        try_deliver(f, &f->d2s_head, &f->next_d2s, 1, deliver_cb, user_ctx);
    }
}

/* Periodic maintenance: expire idle or closed flows */
void tcp_reass_periodic_maintenance(time_t now_sec) {
    for (size_t i = 0; i < TCP_REASS_HASH_BUCKETS; ++i) {
        tcp_flow_t **pf = &flow_table[i];
        while (*pf) {
            tcp_flow_t *f = *pf;
            int removed = 0;

            if (f->close_mark_ts != 0 && (now_sec - f->close_mark_ts) > TCP_FIN_LINGER_SEC) {
                DEBUG_PRINT("Expiring closed flow %s:%u <-> %s:%u", f->src_ip, f->src_port, f->dst_ip, f->dst_port);
                *pf = f->next;
                flow_free(f);
                removed = 1;
            } else if ((now_sec - f->last_seen) > TCP_REASS_FLOW_TIMEOUT_SEC) {
                DEBUG_PRINT("Expiring idle flow %s:%u <-> %s:%u (last_seen=%ld now=%ld)",
                            f->src_ip, f->src_port, f->dst_ip, f->dst_port,
                            (long)f->last_seen, (long)now_sec);
                *pf = f->next;
                flow_free(f);
                removed = 1;
            }

            if (!removed) pf = &(*pf)->next;
        }
    }
}

