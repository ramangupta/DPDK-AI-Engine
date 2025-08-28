// frag_ipv4.c (RFC-791-ish compliant reassembly with interval merging)

#include "frag_ipv4.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ---------------- Debug -----------------
static int DEBUG_FRAG = 1; // set to 1 for verbose logging, 0 to disable

#define DLOG(fmt, ...) \
    do { if (DEBUG_FRAG) fprintf(stderr, "[frag] " fmt "\n", ##__VA_ARGS__); } while (0)

// ---------------- Config ----------------
#define MAX_FRAG_CTX   64
#define MAX_INTERVALS  64
#define FRAG_TIMEOUT   5000000000ULL // ~5s in TSC

// -------------- Interval set -----------
typedef struct {
    uint32_t start; // inclusive
    uint32_t end;   // exclusive
} interval_t;

// -------------- Reassembly ctx ---------
typedef struct {
    int       in_use;
    uint32_t  src, dst;
    uint16_t  id;
    uint8_t   proto;
    uint64_t  ts_last;

    uint8_t   hdr_buf[60];   // IPv4 header max 60 bytes
    uint8_t   hdr_len;
    int       have_first_hdr;

    uint8_t  *payload;
    uint32_t  payload_cap;

    interval_t iv[MAX_INTERVALS];
    int        iv_count;

    int       saw_last;
    uint32_t  total_len;
} frag_ctx_t;

static frag_ctx_t table[MAX_FRAG_CTX];

// ----------------- helpers --------------
static void report_ipv4_drop(uint16_t id, const char *reason) {
    // stdout so the harness always sees it (stderr still has DLOGs)
    fprintf(stdout, "IPv4 drop (id=%u reason=%s)\n", id, reason);
}


static inline frag_ctx_t* find_ctx(uint32_t src, uint32_t dst,
                                   uint16_t id, uint8_t proto)
{
    for (int i=0;i<MAX_FRAG_CTX;i++) {
        frag_ctx_t *c = &table[i];
        if (c->in_use &&
            c->src==src && c->dst==dst &&
            c->id==id   && c->proto==proto) {
            return c;
        }
    }
    return NULL;
}

static inline frag_ctx_t* alloc_ctx(uint32_t src, uint32_t dst,
                                    uint16_t id, uint8_t proto,
                                    uint64_t now)
{
    // Reclaim stale and log drop
    for (int i=0;i<MAX_FRAG_CTX;i++) {
        frag_ctx_t *c = &table[i];
        if (c->in_use) {
            if ((now - c->ts_last) > FRAG_TIMEOUT) {
                report_ipv4_drop(c->id, "timeout");
                DLOG("id=%u timed out -> drop", c->id);
                free(c->payload);
                memset(c,0,sizeof(*c));
            }
        }
    }

    for (int i=0;i<MAX_FRAG_CTX;i++) {
        if (!table[i].in_use) {
            frag_ctx_t *c = &table[i];
            memset(c,0,sizeof(*c));
            c->in_use = 1;
            c->src = src; c->dst = dst; c->id = id; c->proto = proto;
            c->ts_last = now;                    // keep ts for GC
            return c;
        }
    }
    return NULL;
}


static uint16_t ip_checksum(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t*)data;
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (uint16_t)((p[i] << 8) | p[i+1]);
        if (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (len & 1) {
        sum += (uint16_t)(p[len-1] << 8);
        if (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

// merge [s,e) into c->iv
static void intervals_add_merge(frag_ctx_t *c, uint32_t s, uint32_t e)
{
    if (s >= e) return;
    uint32_t ns = s, ne = e;
    for (int i=0; i<c->iv_count; i++) {
        interval_t *iv = &c->iv[i];
        if (ne < iv->start || ns > iv->end) continue;
        if (iv->start < ns) ns = iv->start;
        if (iv->end   > ne) ne = iv->end;
        iv->start = 1; iv->end = 0;
    }
    if (c->iv_count < MAX_INTERVALS) {
        c->iv[c->iv_count++] = (interval_t){ns, ne};
    } else {
        int idx = c->iv_count - 1;
        if (c->iv[idx].end >= ns && ne >= c->iv[idx].start) {
            if (c->iv[idx].start > ns) c->iv[idx].start = ns;
            if (c->iv[idx].end   < ne) c->iv[idx].end   = ne;
        } else {
            c->iv[idx] = (interval_t){ns, ne};
        }
    }
    int w=0;
    for (int r=0; r<c->iv_count; r++) {
        if (c->iv[r].start < c->iv[r].end) c->iv[w++] = c->iv[r];
    }
    c->iv_count = w;
    for (int i=1; i<c->iv_count; i++) {
        interval_t key = c->iv[i];
        int j = i-1;
        while (j>=0 && c->iv[j].start > key.start) {
            c->iv[j+1] = c->iv[j];
            j--;
        }
        c->iv[j+1] = key;
    }
    int n=0;
    for (int i=0; i<c->iv_count; i++) {
        if (n==0) { c->iv[n++] = c->iv[i]; continue; }
        if (c->iv[i].start <= c->iv[n-1].end) {
            if (c->iv[i].end > c->iv[n-1].end) c->iv[n-1].end = c->iv[i].end;
        } else {
            c->iv[n++] = c->iv[i];
        }
    }
    c->iv_count = n;
}

static int intervals_cover_full(const frag_ctx_t *c, uint32_t need)
{
    if (!need) return 1;
    if (c->iv_count != 1) return 0;
    return c->iv[0].start == 0 && c->iv[0].end >= need;
}


static int ensure_payload_cap(frag_ctx_t *c, uint32_t cap)
{
    if (c->payload_cap >= cap) return 1;
    uint32_t newcap = c->payload_cap ? c->payload_cap : 2048;
    while (newcap < cap) newcap *= 2;
    uint8_t *np = realloc(c->payload, newcap);
    if (!np) return 0;
    if (newcap > c->payload_cap)
        memset(np + c->payload_cap, 0, newcap - c->payload_cap);
    c->payload = np;
    c->payload_cap = newcap;
    return 1;
}

// ----------------- API -------------------
pkt_view *frag_reass_ipv4(const struct rte_ipv4_hdr *ip4,
                          const pkt_view *frag,
                          uint64_t now)
{
    uint16_t frag_off = rte_be_to_cpu_16(ip4->fragment_offset);
    int mf           = (frag_off & RTE_IPV4_HDR_MF_FLAG) != 0;
    uint32_t off     = (uint32_t)((frag_off & RTE_IPV4_HDR_OFFSET_MASK) << 3);

    uint8_t ihl = (ip4->version_ihl & 0x0F) * 4;
    if (frag->len < ihl) return NULL;

    uint32_t frag_payload_len = (frag->len >= ihl) ? (frag->len - ihl) : 0;
    uint32_t copy_len = frag_payload_len;
    uint32_t end = off + copy_len;

    uint32_t src = ip4->src_addr;
    uint32_t dst = ip4->dst_addr;
    uint16_t id  = rte_be_to_cpu_16(ip4->packet_id);
    uint8_t  pr  = ip4->next_proto_id;

    frag_ctx_t *c = find_ctx(src, dst, id, pr);
    if (!c) c = alloc_ctx(src, dst, id, pr, now);
    if (!c) return NULL;
    c->ts_last = now;

    if (off == 0 && !c->have_first_hdr) {
        if (ihl > sizeof(c->hdr_buf)) ihl = sizeof(c->hdr_buf);
        memcpy(c->hdr_buf, ip4, ihl);
        c->hdr_len = ihl;
        c->have_first_hdr = 1;
        DLOG("id=%u captured first header (ihl=%u)", id, ihl);
    }

    if (end && !ensure_payload_cap(c, end)) {
        free(c->payload);
        memset(c,0,sizeof(*c));
        return NULL;
    }

    if (copy_len > 0) {
        memcpy(c->payload + off, frag->data + ihl, copy_len);
        intervals_add_merge(c, off, off + copy_len);
    }

    if (!mf) {
        c->saw_last = 1;
        if ((off + copy_len) > c->total_len)
            c->total_len = off + copy_len;
    }

    // FIX: allow emit when header arrives late or last frag unaligned
    if (c->saw_last && c->have_first_hdr &&
        intervals_cover_full(c, c->total_len)) {

        // FIX in frag_ipv4.c (inside the 'emit' block)
        DLOG("id=%u complete! emitting %u bytes", id, c->total_len);

        uint8_t  hdr_len  = c->hdr_len;                 // <-- stash before memset
        uint32_t total    = hdr_len + c->total_len;

        pkt_view *full = capture_alloc(total);
        if (!full) {
            free(c->payload);
            memset(c, 0, sizeof(*c));
            return NULL;
        }

        memcpy((uint8_t*)full->data,              c->hdr_buf,   hdr_len);
        memcpy((uint8_t*)full->data + hdr_len,    c->payload,   c->total_len);

        struct rte_ipv4_hdr *out = (struct rte_ipv4_hdr *)full->data;
        out->total_length    = rte_cpu_to_be_16((uint16_t)total);
        out->fragment_offset = rte_cpu_to_be_16(0);     // clear MF+offset
        out->hdr_checksum    = 0;

        // clean up ctx before computing checksum, but AFTER stashing hdr_len
        free(c->payload);
        memset(c, 0, sizeof(*c));

        // compute checksum over header length we captured
        out->hdr_checksum    = ip_checksum(out, hdr_len);

        full->len = (uint16_t)total;
        return full;

    }

    return NULL;
}

// ---------------- GC/Flush helpers ----------------

/* Expire contexts that timed out; log a drop for incomplete assemblies. */
void frag_ipv4_gc(uint64_t now)
{
    for (int i = 0; i < MAX_FRAG_CTX; i++) {
        frag_ctx_t *c = &table[i];
        if (!c->in_use) continue;

        if ((now - c->ts_last) > FRAG_TIMEOUT) {
            // Incomplete assembly timed out
            fprintf(stdout, "IPv4 drop (id=%u reason=timeout)\n", c->id);
            DLOG("id=%u timed out -> drop", c->id);
            free(c->payload);
            memset(c, 0, sizeof(*c));
        }
    }
}

/* Flush all still-incomplete contexts. Call this at program shutdown. */
void frag_ipv4_flush_all(void)
{
    for (int i=0; i<MAX_FRAG_CTX; i++) {
        frag_ctx_t *c = &table[i];
        if (c->in_use) {
            if (!(c->saw_last && c->have_first_hdr &&
                  intervals_cover_full(c, c->total_len))) {
                // Incomplete → drop
                DLOG("id=%u flushed incomplete -> drop", c->id);
                report_ipv4_drop(c->id, "incomplete");
            }
            free(c->payload);
            memset(c, 0, sizeof(*c));
        }
    }
}


