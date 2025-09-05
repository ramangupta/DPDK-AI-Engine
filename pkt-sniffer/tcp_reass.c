// tcp_reass.c
#define _GNU_SOURCE
#include "tcp_reass.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdatomic.h>
#include "capture.h"
#include "parse_http.h"
#include "parse_tls.h"
#include "stats.h"

/* -------- Lock abstraction (per-flow) --------
+ * Default: pthread mutex. If building with DPDK, define USE_RTE to use spinlocks.
+ */
#ifdef USE_DPDK
#include <rte_spinlock.h>
typedef rte_spinlock_t flow_lock_t;
#define flow_lock_init(L)     rte_spinlock_init((L))
#define flow_lock_acquire(L)  rte_spinlock_lock((L))
#define flow_lock_release(L)  rte_spinlock_unlock((L))
#define flow_lock_destroy(L)  ((void)0)
#else
#include <pthread.h>
typedef pthread_mutex_t flow_lock_t;
#define flow_lock_init(L)     pthread_mutex_init((L), NULL)
#define flow_lock_acquire(L)  pthread_mutex_lock((L))
#define flow_lock_release(L)  pthread_mutex_unlock((L))
#define flow_lock_destroy(L)  pthread_mutex_destroy((L))
#endif

// Debug toggle
#ifndef TCP_DEBUG
#define TCP_DEBUG 0
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

    int l7_proto;
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

    /* reference count: prevents freeing while in use by workers */
    atomic_int refcnt;
    /* If set, flow was removed from table and should be freed once refcnt==0 */
    int marked_free;

    flow_lock_t lock;         /* per-flow lock for TCP+L7 parsing */
    struct tcp_flow *next;   /* hash chain */
};

// -------- Globals --------
static tcp_flow_t *flow_table[TCP_REASS_HASH_BUCKETS];
/* bucket locks to protect flow_table[] chains */
static flow_lock_t bucket_locks[TCP_REASS_HASH_BUCKETS];

// -------- Getters --------
// tcp_reass.c
const char *tcp_flow_src_ip(const tcp_flow_t *flow) { return flow->src_ip; }
uint16_t    tcp_flow_src_port(const tcp_flow_t *flow) { return flow->src_port; }
const char *tcp_flow_dst_ip(const tcp_flow_t *flow) { return flow->dst_ip; }
uint16_t    tcp_flow_dst_port(const tcp_flow_t *flow) { return flow->dst_port; }
int         tcp_flow_l7_proto(const tcp_flow_t *flow) { return flow->l7_proto; }
void        tcp_flow_set_l7_proto(tcp_flow_t *flow, int l7_proto) {
    if (flow) {
        flow->l7_proto = l7_proto;
    }
}

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

/* Assumes caller holds bucket locks as necessary.
 * We do not modify refcounts here.
 */
static tcp_flow_t *flow_lookup_bidir_nolock(const char *src, const char *dst,
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

    /* init per-flow lock */
    flow_lock_init(&f->lock);
    /* init refcnt (caller receives one reference) */
    atomic_init(&f->refcnt, 1);
    f->marked_free = 0;      

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

    /* destroy per-flow lock (safe only if no one else holds it) */
    flow_lock_destroy(&f->lock);

    free(f);
}

/* Increment a flow reference */
static inline void flow_get_ref(tcp_flow_t *f) {
    atomic_fetch_add_explicit(&f->refcnt, 1, memory_order_relaxed);
}

/* Release a flow reference; free if marked and refcount reaches 0 */
static inline void flow_put_ref(tcp_flow_t *f) {
    int prev = atomic_fetch_sub_explicit(&f->refcnt, 1, memory_order_acq_rel);
    if (prev == 1 && f->marked_free) {
        /* last reference and marked for free — safe to free */
        flow_free(f);
    }
}

// -------- Public API --------
int tcp_reass_init(void) {
    memset(flow_table, 0, sizeof(flow_table));
    /* init bucket locks */
    for (size_t i = 0; i < TCP_REASS_HASH_BUCKETS; ++i) {
        flow_lock_init(&bucket_locks[i]);
    }

    DEBUG_PRINT("TCP reassembly initialized");
    return 0;
}

void tcp_reass_fini(void) {
    for (size_t i = 0; i < TCP_REASS_HASH_BUCKETS; i++) {
        /* take bucket lock while tearing down */
        flow_lock_acquire(&bucket_locks[i]);
        tcp_flow_t *f = flow_table[i];
        while (f) {
            tcp_flow_t *n = f->next;
            /* mark for free and free if no refs */
            f->marked_free = 1;
            if (atomic_load(&f->refcnt) == 0) flow_free(f);
            f = n;
        }
        flow_table[i] = NULL;
        flow_lock_release(&bucket_locks[i]);
        flow_lock_destroy(&bucket_locks[i]);
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

    uint32_t h = flow_hash(src_ip, dst_ip, src_port, dst_port);
    uint32_t hr = flow_hash(dst_ip, src_ip, dst_port, src_port);
    /* lock buckets in address order to avoid deadlock */
    if (h <= hr) {
        flow_lock_acquire(&bucket_locks[h]);
        if (hr != h) flow_lock_acquire(&bucket_locks[hr]);
    } else {
        flow_lock_acquire(&bucket_locks[hr]);
        flow_lock_acquire(&bucket_locks[h]);
    }

    tcp_flow_t *f = flow_lookup_bidir_nolock(src_ip, dst_ip, src_port, dst_port);
    int created = 0;
    if (!f) {
        f = flow_create(src_ip, dst_ip, src_port, dst_port, ts);
        created = 1;
        DEBUG_PRINT("Flow created for %s:%u ↔ %s:%u", src_ip, src_port, dst_ip, dst_port);
    } else {
        /* get a usage reference while we will use it outside bucket lock */
        flow_get_ref(f);
    }
    /* release the bucket locks now that flow is inserted/looked-up */
    if (h <= hr) {
        if (hr != h) flow_lock_release(&bucket_locks[hr]);
        flow_lock_release(&bucket_locks[h]);
    } else {
        flow_lock_release(&bucket_locks[h]);
        flow_lock_release(&bucket_locks[hr]);
    }
    if (!f) return;
    /* we maintain a reference (created -> ref initialized to 1 inside flow_create,
     * lookup -> we incremented ref above). We'll drop the ref at function exit.
     */
    f->last_seen = ts;

    // Direction: dir=0 means src→dst matches flow's tuple, otherwise 1
    int dir = (strcmp(f->src_ip, src_ip) == 0 && strcmp(f->dst_ip, dst_ip) == 0 &&
               f->src_port == src_port && f->dst_port == dst_port) ? 0 : 1;
    DEBUG_PRINT("Flow %p dir=%d", (void*)f, dir);

    /* 
     * ====== FLOW-LEVEL CRITICAL SECTION START ======
     * Serialize TCP reassembly and L7 delivery per flow.
     */
    flow_lock_acquire(&f->lock);

    // Handle new flow initialization
    // --- handle new flow initialization ---
    if (created && (flags & 0x02)) {             // SYN
        if (dir == 0) f->next_s2d = seq + 1;     // ISN consumes 1
        else          f->next_d2s = seq + 1;
        DEBUG_PRINT("New flow with SYN: dir=%d ISN=%u", dir, seq);
    } else if (created && payload_len > 0) {
        // Flow created mid-stream (no SYN). To avoid losing the first payload,
        // initialize expected to this segment's SEQ (not seq+len).
        if (dir == 0) f->next_s2d = seq;
        else          f->next_d2s = seq;
        DEBUG_PRINT("New flow mid-stream: dir=%d start_seq=%u", dir, seq);
    }

    // update syn/fin markers
    if (flags & 0x02) 
        f->seen_syn = 1;

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
        goto out_unlock;
    }

/*
    // Initialize expected seq if first payload in this direction
    if (dir == 0 && f->next_s2d == 0) {
        f->next_s2d = seq + payload_len;
        DEBUG_PRINT("Init next_s2d=%u from first payload", f->next_s2d);
    }
    if (dir == 1 && f->next_d2s == 0) {
        f->next_d2s = seq + payload_len;
        DEBUG_PRINT("Init next_d2s=%u from first payload", f->next_d2s);
    }
*/
    tcp_seg_t *seg = seg_new(payload, payload_len, seq, ts);
    if (!seg) {
        goto out_unlock;
    }

    if (dir == 0) {
        if (f->next_s2d == 0) {
            f->next_s2d = seq;
            DEBUG_PRINT("Init next_s2d=%u from first payload (dir=0)", f->next_s2d);
        }
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
            goto out_unlock;
        }
        try_deliver(f, &f->s2d_head, &f->next_s2d, 0, deliver_cb, user_ctx);
        // after try_deliver, some segs delivered — recompute buffer counter by scanning list or subtract delivered bytes inside try_deliver
        // (we'll subtract delivered bytes in try_deliver later)
    } else {
        if (f->next_d2s == 0) {
            f->next_d2s = seq;
            DEBUG_PRINT("Init next_d2s=%u from first payload (dir=1)", f->next_d2s);
        }
        DEBUG_PRINT("SEG dir=%d seq=%u len=%u expected=%u",
            dir, seq, payload_len,
            (dir==0 ? f->next_s2d : f->next_d2s));

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
            goto out_unlock;
        }
        try_deliver(f, &f->d2s_head, &f->next_d2s, 1, deliver_cb, user_ctx);
    }

out_unlock:
    /* ====== FLOW-LEVEL CRITICAL SECTION END ====== */
    flow_lock_release(&f->lock);
    /* release our usage reference */
    flow_put_ref(f);
    return;
}

/* Periodic maintenance: expire idle or closed flows */
void tcp_reass_periodic_maintenance(time_t now_sec) {
    for (size_t i = 0; i < TCP_REASS_HASH_BUCKETS; ++i) {
        /* lock this bucket for maintenance */
        flow_lock_acquire(&bucket_locks[i]);
        tcp_flow_t **pf = &flow_table[i];
        while (*pf) {
            tcp_flow_t *f = *pf;
            int removed = 0;

            if (f->close_mark_ts != 0 && (now_sec - f->close_mark_ts) > TCP_FIN_LINGER_SEC) {
                DEBUG_PRINT("Expiring closed flow %s:%u <-> %s:%u", f->src_ip, f->src_port, f->dst_ip, f->dst_port);
                *pf = f->next;
                /* mark for free; free only if no active refs */
                f->marked_free = 1;
                if (atomic_load(&f->refcnt) == 0) {
                    flow_free(f);
                }
                removed = 1;
            } else if ((now_sec - f->last_seen) > TCP_REASS_FLOW_TIMEOUT_SEC) {
                DEBUG_PRINT("Expiring idle flow %s:%u <-> %s:%u (last_seen=%ld now=%ld)",
                            f->src_ip, f->src_port, f->dst_ip, f->dst_port,
                            (long)f->last_seen, (long)now_sec);
                *pf = f->next;
                f->marked_free = 1;
                if (atomic_load(&f->refcnt) == 0) {
                    flow_free(f);
                }
                removed = 1;
            }

            if (!removed) pf = &(*pf)->next;
        }
        flow_lock_release(&bucket_locks[i]);
    }
}

