// frag_ipv6.c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <rte_ip.h>
#include "engine/capture.h"   // for pkt_view
#include "parsers/frag_ipv4.h"

#define MAX_FRAG_CTX        32768
#define HASH_SIZE           16384   // power-of-2, adjust if needed
#define MAX_INTERVALS       32
#define INITIAL_PAYLOAD_CAP 8192    // 8 KB start
#define FRAG_V6_TIMEOUT_NS (60ULL * 1000000000ULL)
#define STALE_BATCH  128    // process 128 contexts per stale flush

atomic_ulong ipv6_frag_timeouts;

// ------------------ Context Struct ------------------
typedef struct frag_ctx6 {
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
    uint32_t total_len;

    struct frag_ctx6 *next;        // hash bucket chain
    struct frag_ctx6 *next_active; // active list
} frag_ctx6_t;

// ------------------ Globals ------------------
static frag_ctx6_t table[MAX_FRAG_CTX];          // pre-allocated pool
static frag_ctx6_t* hash_table[HASH_SIZE];       // hash buckets
static frag_ctx6_t *free_list = NULL;           // free pool
static frag_ctx6_t *active_list = NULL;         // active contexts for GC

// ------------------ Helpers ------------------
static inline uint64_t tsc_to_ns(uint64_t tsc)
{
#ifdef USE_DPDK
    uint64_t hz = rte_get_tsc_hz();
    return (tsc * 1000000000ULL) / hz;
#else
    return tsc;
#endif
}

static inline uint32_t hash_frag_ctx6(const struct in6_addr *src,
                                      const struct in6_addr *dst,
                                      uint32_t id, uint8_t proto)
{
    uint32_t h = 0;
    for(int i=0;i<16;i++) h ^= ((uint8_t*)src->s6_addr)[i];
    for(int i=0;i<16;i++) h ^= ((uint8_t*)dst->s6_addr)[i];
    h ^= id;
    h ^= proto;
    return h & (HASH_SIZE-1);
}

// ------------------ Init ------------------
void frag_reass_ipv6_init(void) 
{
    free_list = &table[0];
    for(int i=0;i<MAX_FRAG_CTX-1;i++)
        table[i].next = &table[i+1];
    table[MAX_FRAG_CTX-1].next = NULL;

    memset(hash_table, 0, sizeof(hash_table));
    active_list = NULL;
}

// ------------------ Allocation / Free ------------------
frag_ctx6_t* alloc_ctx6(const struct in6_addr *src, const struct in6_addr *dst,
                        uint32_t id, uint8_t proto, uint64_t now_ns)
{
    if (!free_list) return NULL;
    frag_ctx6_t *c = free_list;
    free_list = c->next;

    memset(c, 0, sizeof(*c));
    c->in_use = 1;
    memcpy(&c->src, src, sizeof(*src));
    memcpy(&c->dst, dst, sizeof(*dst));
    c->id = id;
    c->proto = proto;
    c->ts_last = now_ns;

    // hash bucket insert
    uint32_t h = hash_frag_ctx6(src, dst, id, proto);
    c->next = hash_table[h];
    hash_table[h] = c;

    // active list insert
    c->next_active = active_list;
    active_list = c;

    global_stats.ipv6_frag_allocs++;
    return c;
}

static void free_ctx6(frag_ctx6_t *c)
{
    if (!c || !c->in_use) return;

    // remove from hash table
    uint32_t h = hash_frag_ctx6(&c->src, &c->dst, c->id, c->proto);
    frag_ctx6_t **pp = &hash_table[h];
    while(*pp) {
        if(*pp == c) { *pp = c->next; break; }
        pp = &(*pp)->next;
    }

    // remove from active list
    frag_ctx6_t **pa = &active_list;
    while(*pa) {
        if(*pa == c) { *pa = c->next_active; break; }
        pa = &(*pa)->next_active;
    }

    if(c->payload) free(c->payload);
    memset(c, 0, sizeof(*c));

    // push back to free list
    c->next = free_list;
    free_list = c;
}

// ------------------ Lookup ------------------
frag_ctx6_t* find_ctx6(const struct in6_addr *src, const struct in6_addr *dst,
                       uint32_t id, uint8_t proto)
{
    uint32_t h = hash_frag_ctx6(src,dst,id,proto);
    frag_ctx6_t *c = hash_table[h];
    while(c) {
        if(c->in_use &&
           !memcmp(&c->src, src, sizeof(*src)) &&
           !memcmp(&c->dst, dst, sizeof(*dst)) &&
           c->id==id && c->proto==proto)
            return c;
        c = c->next;
    }
    return NULL;
}

// ------------------ Stale GC ------------------
void frag_ipv6_flush_stale(uint64_t now_ns)
{
    frag_ctx6_t **pp = &active_list;
    int processed = 0;

    while(*pp && processed < STALE_BATCH) {
        frag_ctx6_t *c = *pp;

        if (c->in_use && (now_ns - c->ts_last > FRAG_V6_TIMEOUT_NS)) {
            // Remove from active list
            *pp = c->next;

            // Flush payload
            if(c->payload) free(c->payload);
            memset(c, 0, sizeof(*c));

            // Add back to free list
            c->next = free_list;
            free_list = c;

            global_stats.ipv6_frag_timeouts++;
            global_stats.dropped++;

            processed++;
        } else {
            pp = &(*pp)->next;  // move to next node
            processed++;
        }
    }
}

// ------------------ Flush All ------------------
void frag_ipv6_flush_all(void)
{
    frag_ctx6_t *c = active_list;
    while(c) {
        frag_ctx6_t *next = c->next_active;
        free_ctx6(c);
        c = next;
    }
}

// ------------------ Payload Helpers ------------------
static int ensure_payload_cap(frag_ctx6_t *c, uint32_t cap)
{
    if (c->payload_cap >= cap) return 1;
    uint32_t newcap = c->payload_cap ? c->payload_cap : INITIAL_PAYLOAD_CAP;
    while(newcap < cap) newcap *= 2;

    uint8_t *np = realloc(c->payload, newcap);
    if(!np) { global_stats.ipv6_frag_drops++; return 0; }

    if(newcap > c->payload_cap) {
        global_stats.ipv6_frag_expands++;
        memset(np + c->payload_cap, 0, newcap - c->payload_cap);
    }

    c->payload = np;
    c->payload_cap = newcap;
    return 1;
}

// ------------------ Interval Helpers ------------------
static void intervals_add_merge(frag_ctx6_t *c, uint32_t s, uint32_t e)
{
    if(s >= e) return;

    if(c->iv_count < MAX_INTERVALS)
        c->iv[c->iv_count++] = (typeof(c->iv[0])){s,e};

    // sort and merge
    int write = 0;
    for(int i=1;i<c->iv_count;i++) {
        if(c->iv[write].end >= c->iv[i].start) {
            if(c->iv[i].end > c->iv[write].end) c->iv[write].end = c->iv[i].end;
        } else {
            write++;
            c->iv[write] = c->iv[i];
        }
    }
    c->iv_count = write+1;
}

static int intervals_cover_full(frag_ctx6_t *c, uint32_t total)
{
    if(c->iv_count == 0) return 0;
    uint32_t covered = 0;
    for(int i=0;i<c->iv_count;i++) {
        if(c->iv[i].start > covered) return 0;
        if(c->iv[i].end > covered) covered = c->iv[i].end;
    }
    return (covered >= total);
}

// ------------------ Reassembly ------------------
pkt_view *frag_reass_ipv6(const uint8_t *frag_hdr, const pkt_view *pv, uint64_t now)
{
    if(!pv || !frag_hdr) return NULL;

    const struct rte_ipv6_hdr *ip6 = (const struct rte_ipv6_hdr *)pv->data;
    const struct rte_ipv6_frag_hdr *fh = (const struct rte_ipv6_frag_hdr *)frag_hdr;

    uint32_t frag_id = rte_be_to_cpu_32(fh->identification);
    uint16_t raw_off = rte_be_to_cpu_16(fh->fragment_offset);
    uint32_t off = raw_off & 0xFFF8;
    int more_frags = raw_off & 0x1;

    uint32_t copy_len = pv->len - sizeof(*ip6) - sizeof(*fh);
    uint32_t end = off + copy_len;

    global_stats.ipv6_frag_received++;
    uint64_t now_ns = tsc_to_ns(now);

    frag_ctx6_t *c = find_ctx6((struct in6_addr *)&ip6->src_addr, (struct in6_addr *)&ip6->dst_addr,
                               frag_id, ip6->proto);
    if(!c) {
        c = alloc_ctx6((struct in6_addr *)&ip6->src_addr, (struct in6_addr *)&ip6->dst_addr,
                       frag_id, ip6->proto, now_ns);
        if(!c) { global_stats.ipv6_frag_drops++; return NULL; }
    }

    c->ts_last = now_ns;
    if(!ensure_payload_cap(c, end)) return NULL;

    if(copy_len > 0)
        memcpy(c->payload + off, (uint8_t*)frag_hdr + sizeof(*fh), copy_len);

    intervals_add_merge(c, off, end);

    if(!more_frags) {
        c->saw_last = 1;
        if(c->total_len < end) c->total_len = end;
    }

    if(c->saw_last && intervals_cover_full(c, c->total_len)) {
        pkt_view *full = capture_alloc(sizeof(*ip6) + c->total_len);
        if(!full) return NULL;

        memcpy((uint8_t*)full->data, ip6, sizeof(*ip6));
        memcpy((uint8_t*)full->data + sizeof(*ip6), c->payload, c->total_len);
        full->len = sizeof(*ip6) + c->total_len;

        global_stats.ipv6_frag_reassembled++;
        free_ctx6(c);
        return full;
    }

    return NULL;
}
