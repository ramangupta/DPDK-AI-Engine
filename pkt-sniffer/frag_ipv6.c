// frag_ipv6.c
#include "frag_ipv4.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <rte_ip.h>
#include "capture.h"

#define MAX_FRAG_CTX   64
#define MAX_INTERVALS  64
#define FRAG_TIMEOUT   5000000000ULL // ~5s

// Toggle debug output
#ifndef IPV6_FRAG_DEBUG
#define IPV6_FRAG_DEBUG 1
#endif

typedef struct {
    uint32_t in_use;

    struct in6_addr src;
    struct in6_addr dst;
    uint32_t id;        // 32-bit for IPv6
    uint8_t  proto;
    uint64_t ts_last;

    uint8_t  *payload;
    uint32_t  payload_cap;

    struct {
        uint32_t start;
        uint32_t end;
    } iv[MAX_INTERVALS];
    int iv_count;

    int saw_last;
    uint32_t  total_len;
} frag_ctx6_t;

static frag_ctx6_t table[MAX_FRAG_CTX];

// ---------------- Helpers ----------------
static frag_ctx6_t* find_ctx6(const struct in6_addr *src, const struct in6_addr *dst,
                             uint32_t id, uint8_t proto)
{
    for (int i=0;i<MAX_FRAG_CTX;i++) {
        frag_ctx6_t *c = &table[i];
        if (c->in_use &&
            !memcmp(&c->src, src, sizeof(*src)) &&
            !memcmp(&c->dst, dst, sizeof(*dst)) &&
            c->id==id && c->proto==proto)
        {
            return c;
        }
    }
    return NULL;
}

static frag_ctx6_t* alloc_ctx6(const struct in6_addr *src, const struct in6_addr *dst,
                              uint32_t id, uint8_t proto, uint64_t now)
{
    // GC stale contexts
    for (int i=0;i<MAX_FRAG_CTX;i++) {
        frag_ctx6_t *c = &table[i];
        if (c->in_use && (now - c->ts_last) > FRAG_TIMEOUT) {
            free(c->payload);
            memset(c, 0, sizeof(*c));
        }
    }

    for (int i=0;i<MAX_FRAG_CTX;i++) {
        if (!table[i].in_use) {
            frag_ctx6_t *c = &table[i];
            memset(c,0,sizeof(*c));
            c->in_use = 1;
            memcpy(&c->src, src, sizeof(*src));
            memcpy(&c->dst, dst, sizeof(*dst));
            c->id = id;
            c->proto = proto;
            c->ts_last = now;
            return c;
        }
    }
    return NULL;
}

static int ensure_payload_cap(frag_ctx6_t *c, uint32_t cap)
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

static void intervals_add_merge(frag_ctx6_t *c, uint32_t s, uint32_t e)
{
    // Insert new interval in sorted order and merge
    int i = 0;
    while (i < c->iv_count && c->iv[i].start < s) i++;

    if (s >= e) return;

    // insert new interval at end
    if (c->iv_count < MAX_INTERVALS)
        c->iv[c->iv_count++] = (typeof(c->iv[0])){s, e};

    // bubble-sort by start
    for (int i = 0; i < c->iv_count - 1; i++) {
        for (int j = i + 1; j < c->iv_count; j++) {
            if (c->iv[i].start > c->iv[j].start) {
                typeof(c->iv[0]) tmp = c->iv[i];
                c->iv[i] = c->iv[j];
                c->iv[j] = tmp;
            }
        }
    }

    // merge left-to-right
    int write = 0;
    for (int read = 1; read < c->iv_count; read++) {
        if (c->iv[write].end >= c->iv[read].start) {
            // overlap or contiguous: merge
            if (c->iv[read].end > c->iv[write].end)
                c->iv[write].end = c->iv[read].end;
        } else {
            // no overlap: advance write
            write++;
            c->iv[write] = c->iv[read];
        }
    }
    c->iv_count = write + 1;
}



static int intervals_cover_full(frag_ctx6_t *c, uint32_t total)
{
    if (c->iv_count == 0) return 0;

    uint32_t covered = 0;
    for (int i = 0; i < c->iv_count; i++) {
        if (c->iv[i].start > covered) {
            // gap detected
            return 0;
        }
        if (c->iv[i].end > covered)
            covered = c->iv[i].end;
    }
    return (covered >= total);
}   

// ---------------- API ----------------
pkt_view *frag_reass_ipv6(const uint8_t *frag_hdr, 
                          const pkt_view *pv,
                          uint32_t frag_offset,
                          int mf,
                          uint64_t now)
{
    if (!pv || !frag_hdr) return NULL;

    const struct rte_ipv6_hdr *ip6 = (const struct rte_ipv6_hdr *)pv->data;
    const struct rte_ipv6_frag_hdr *fh = (const struct rte_ipv6_frag_hdr *)frag_hdr;

    uint32_t frag_id = rte_be_to_cpu_32(fh->identification);
    uint16_t raw_off = rte_be_to_cpu_16(fh->fragment_offset); // fragment_offset field in header
    uint32_t off = (raw_off & 0xFFF8);           // offset in bytes
    off *= 8;
    int more_frags = (raw_off & 0x1) != 0;

    uint32_t copy_len = pv->len - sizeof(*ip6) - sizeof(*fh);
    uint32_t end = off + copy_len;

#if IPV6_FRAG_DEBUG
    printf("[DEBUG] IPv6 frag: id=%u, offset=%u, len=%u, mf=%d\n",
           frag_id, off, copy_len, more_frags);
#endif

    frag_ctx6_t *c = find_ctx6((struct in6_addr *)&ip6->src_addr, (struct in6_addr *)&ip6->dst_addr, frag_id, ip6->proto);
    if (!c) {
        c = alloc_ctx6((struct in6_addr *)&ip6->src_addr, (struct in6_addr *)&ip6->dst_addr, frag_id, ip6->proto, now);
        if (!c) {
#if IPV6_FRAG_DEBUG
            printf("[DEBUG] Failed to allocate frag_ctx6 for id=%u\n", frag_id);
#endif
            return NULL;
        }
    }

    c->ts_last = now;

    if (!ensure_payload_cap(c, end)) {
#if IPV6_FRAG_DEBUG
        printf("[DEBUG] Failed to ensure payload capacity for id=%u\n", frag_id);
#endif
        free(c->payload);
        memset(c, 0, sizeof(*c));
        return NULL;
    }

    if (copy_len > 0)
        memcpy(c->payload + off, (uint8_t*)frag_hdr + sizeof(*fh), copy_len);

    intervals_add_merge(c, off, end);

    if (!more_frags) {
        c->saw_last = 1;
        if (c->total_len < end) c->total_len = end;  // track largest end
#if IPV6_FRAG_DEBUG
        printf("[DEBUG] Saw last fragment for id=%u, total_len=%u\n", frag_id, c->total_len);
#endif
    }

    // Check full reassembly using tracked total_len
    if (c->saw_last && intervals_cover_full(c, c->total_len)) {
        pkt_view *full = capture_alloc(sizeof(*ip6) + c->total_len);
        if (!full) return NULL;

        memcpy((uint8_t*)full->data, ip6, sizeof(*ip6));
        memcpy((uint8_t*)full->data + sizeof(*ip6), c->payload, c->total_len);
        full->len = sizeof(*ip6) + c->total_len;

#if IPV6_FRAG_DEBUG
        printf("[DEBUG] IPv6 reassembled (id=%u) total_len=%u\n", frag_id, full->len);
#endif

        free(c->payload);
        memset(c, 0, sizeof(*c));
        return full;
    }

#if IPV6_FRAG_DEBUG
    printf("[DEBUG] IPv6 fragment buffered (id=%u) offset=%u len=%u\n",
           frag_id, off, copy_len);
#endif

    return NULL;
}

/* Flush all still-incomplete IPv6 fragment contexts. Call at program shutdown. */
void frag_ipv6_flush_all(void)
{
    for (int i = 0; i < MAX_FRAG_CTX; i++) {
        frag_ctx6_t *c = &table[i];
        if (c->payload) {
#if IPV6_FRAG_DEBUG
            char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &c->src, src, sizeof(src));
            inet_ntop(AF_INET6, &c->dst, dst, sizeof(dst));
            printf("[DEBUG] Flushing incomplete IPv6 frag id=%u %s → %s\n",
                   c->id, src, dst);
#endif
            free(c->payload);
            memset(c, 0, sizeof(*c));
        }
    }
}
