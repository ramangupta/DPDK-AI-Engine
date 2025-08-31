// tcp_reass.c
#define _GNU_SOURCE
#include "tcp_reass.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

tcp_stream_t streams[MAX_TCP_STREAMS];

// hash table
static tcp_flow_t *buckets[TCP_REASS_HASH_BUCKETS];

static inline int32_t seq_cmp(int32_t a, int32_t b) { return (int32_t)(a - b); }
static inline int seq_lt(uint32_t a, uint32_t b)  { return seq_cmp((int32_t)a, (int32_t)b) < 0; }
static inline int seq_le(uint32_t a, uint32_t b)  { return seq_cmp((int32_t)a, (int32_t)b) <= 0; }
static inline int seq_gt(uint32_t a, uint32_t b)  { return seq_cmp((int32_t)a, (int32_t)b) > 0; }

static uint32_t key_hash(const char *a, const char *b, uint16_t p1, uint16_t p2) {
    // simple FNV-like over strings + ports
    uint32_t h = 2166136261u;
    for (const char *s = a; *s; ++s) h = (h ^ (uint8_t)*s) * 16777619u;
    h ^= 0x9e3779b9;
    for (const char *s = b; *s; ++s) h = (h ^ (uint8_t)*s) * 16777619u;
    h ^= ((uint32_t)p1 << 16) ^ p2;
    return h & (TCP_REASS_HASH_BUCKETS - 1);
}

int tcp_reass_init(void) 
{ 
    memset(buckets, 0, sizeof(buckets)); 
    return 0; 
}

void tcp_reass_fini(void) {
    for (int i=0;i<TCP_REASS_HASH_BUCKETS;i++) {
        tcp_flow_t *f = buckets[i];
        while (f) {
            tcp_flow_t *nx = f->next;
            tcp_seg_t *s = f->s2d_head;
            while (s) { tcp_seg_t *sn = s->next; free(s->data); free(s); s = sn; }
            s = f->d2s_head;
            while (s) { tcp_seg_t *sn = s->next; free(s->data); free(s); s = sn; }
            free(f);
            f = nx;
        }
        buckets[i] = NULL;
    }
}

static tcp_flow_t *flow_create(const char *src, const char *dst, uint16_t sp, uint16_t dp, time_t ts) {
    tcp_flow_t *f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    strncpy(f->src_ip, src, sizeof(f->src_ip)-1);
    strncpy(f->dst_ip, dst, sizeof(f->dst_ip)-1);
    f->src_port = sp;
    f->dst_port = dp;
    f->s2d_head = f->d2s_head = NULL;
    f->next_s2d = f->next_d2s = 0;
    f->last_seen = ts;
    f->seen_syn = f->seen_fin = 0;
    uint32_t h = key_hash(src, dst, sp, dp);
    f->next = buckets[h];
    buckets[h] = f;
    return f;
}

static tcp_flow_t *flow_lookup(const char *src, const char *dst, uint16_t sp, uint16_t dp) {
    uint32_t h = key_hash(src, dst, sp, dp);
    for (tcp_flow_t *f = buckets[h]; f; f = f->next) {
        if (f->src_port == sp && f->dst_port == dp &&
            strcmp(f->src_ip, src) == 0 && strcmp(f->dst_ip, dst) == 0) return f;
    }
    return NULL;
}

static tcp_flow_t *flow_lookup_bidir(const char *src, const char *dst, uint16_t sp, uint16_t dp) {
    tcp_flow_t *f = flow_lookup(src,dst,sp,dp);
    if (f) return f;
    // try reverse mapping
    uint32_t h = key_hash(dst, src, dp, sp);
    for (tcp_flow_t *x = buckets[h]; x; x = x->next) {
        if (x->src_port == dp && x->dst_port == sp &&
            strcmp(x->src_ip, dst) == 0 && strcmp(x->dst_ip, src) == 0) return x;
    }
    return NULL;
}

static tcp_seg_t *seg_new(const uint8_t *payload, uint32_t len, uint32_t seq, time_t ts) {
    tcp_seg_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->seq = seq;
    s->len = len;
    s->ts = ts;
    if (len) {
        s->data = malloc(len);
        if (!s->data) { free(s); return NULL; }
        memcpy(s->data, payload, len);
    } else s->data = NULL;
    s->next = NULL;
    return s;
}

// Insert sorted by seq into head list, with left-trim of overlap (prefer existing bytes)
static void insert_seg_sorted(tcp_seg_t **head, tcp_seg_t *s) {
    if (!*head) { *head = s; return; }
    tcp_seg_t **cur = head;
    while (*cur && seq_lt((*cur)->seq, s->seq)) cur = &(*cur)->next;

    // trim left overlap with previous
    if (cur != head) {
        tcp_seg_t *prev = *head;
        while (prev->next != *cur) prev = prev->next;
        uint32_t prev_end = prev->seq + prev->len;
        if (prev_end > s->seq) {
            uint32_t ov = prev_end - s->seq;
            if (ov >= s->len) { free(s->data); free(s); return; } // fully duplicate
            // trim left ov bytes
            memmove(s->data, s->data + ov, s->len - ov);
            s->seq += ov;
            s->len -= ov;
        }
    }

    // trim right overlap with *cur
    if (*cur) {
        uint32_t cur_start = (*cur)->seq;
        if (s->seq + s->len > cur_start) {
            uint32_t ov = (s->seq + s->len) - cur_start;
            if (ov >= s->len) { free(s->data); free(s); return; }
            s->len -= ov;
            // shrink data (optional): keep left part only
            // no memmove needed because left part already at data[0..len-1]
        }
    }

    s->next = *cur;
    *cur = s;
}

// Deliver contiguous bytes from head while head.seq <= next_expected
static void try_deliver(tcp_flow_t *f, tcp_seg_t **head, uint32_t *next_expected,
                        int dir, tcp_reass_deliver_cb cb, void *user_ctx)
{
    while (*head) {
        tcp_seg_t *h = *head;
        if (seq_gt(h->seq, *next_expected)) break;
        uint32_t off = 0;
        if (seq_lt(h->seq, *next_expected)) {
            off = *next_expected - h->seq;
            if (off >= h->len) {
                // fully duplicate
                *head = h->next;
                free(h->data); free(h);
                continue;
            }
        }
        uint32_t deliver_len = h->len - off;
        const uint8_t *deliver_ptr = h->data + off;
        if (deliver_len && cb) cb(f, dir, deliver_ptr, deliver_len, f->last_seen, user_ctx);
        // advance next_expected to end of this segment
        *next_expected = h->seq + h->len;
        // remove head
        *head = h->next;
        free(h->data); free(h);
    }
}

void tcp_reass_process_segment(const char *src_ip, const char *dst_ip,
                               uint16_t src_port, uint16_t dst_port,
                               const uint8_t *payload, uint32_t payload_len,
                               uint32_t seq, uint8_t flags, time_t ts,
                               tcp_reass_deliver_cb deliver_cb, void *user_ctx)
{
    tcp_flow_t *f = flow_lookup_bidir(src_ip, dst_ip, src_port, dst_port);
    int created = 0;
    if (!f) {
        f = flow_create(src_ip, dst_ip, src_port, dst_port, ts);
        created = 1;
    }
    if (!f) return;
    f->last_seen = ts;

    // determine direction: if keys match exactly => s->d, else it's reverse
    int dir = (strcmp(f->src_ip, src_ip) == 0 && strcmp(f->dst_ip, dst_ip) == 0 &&
               f->src_port == src_port && f->dst_port == dst_port) ? 0 : 1;

    // set seq base if newly created and SYN present
    if (created && (flags & 0x02)) {
        if (dir == 0) f->next_s2d = seq + 1;
        else f->next_d2s = seq + 1;
    } else if (created && payload_len > 0) {
        if (dir == 0) f->next_s2d = seq;
        else f->next_d2s = seq;
    }

    // update syn/fin markers
    if (flags & 0x02) f->seen_syn = 1;
    if (flags & 0x01) f->seen_fin = 1;

    if (payload_len == 0) {
        // pure ack or control: nothing to buffer for now
        return;
    }

    tcp_seg_t *seg = seg_new(payload, payload_len, seq, ts);
    if (!seg) return;

    if (dir == 0) {
        insert_seg_sorted(&f->s2d_head, seg);
        try_deliver(f, &f->s2d_head, &f->next_s2d, 0, deliver_cb, user_ctx);
    } else {
        insert_seg_sorted(&f->d2s_head, seg);
        try_deliver(f, &f->d2s_head, &f->next_d2s, 1, deliver_cb, user_ctx);
    }
}

// tcp_reass.c
void tcp_reass_periodic_maintenance(uint64_t now_sec) {
    for (int i = 0; i < MAX_TCP_STREAMS; i++) {
        tcp_stream_t *st = &streams[i];
        if (!st->in_use)
            continue;

        if (now_sec - st->last_activity > TCP_TIMEOUT_SEC) {
            tcp_reass_flush_stream(st);
        }
    }
}

void tcp_reass_flush_stream(tcp_stream_t *st) {
    // Free all fragments
    tcp_seg_t *seg = st->frags;
    while (seg) {
        tcp_seg_t *next = seg->next;
        free(seg->data);
        free(seg);
        seg = next;
    }
    st->frags = NULL;
    st->in_use = false;
}
