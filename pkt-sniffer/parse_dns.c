#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "parse_dns.h"

// DNS header (12 bytes)
struct dns_hdr {
    uint16_t id, flags, qdcount, ancount, nscount, arcount;
} __attribute__((__packed__));

static int read_qname(const uint8_t *p, uint16_t len, uint16_t *off, char *out, size_t outsz) {
    size_t o = 0; uint16_t i = *off; int jumped = 0; uint16_t jump_to = 0;
    int loops = 0;

    while (i < len && loops++ < 255) {
        uint8_t lab = p[i++];
        if (lab == 0) break;
        if ((lab & 0xC0) == 0xC0) {           // pointer
            if (i >= len) return -1;
            uint8_t b2 = p[i++];
            uint16_t ptr = ((lab & 0x3F) << 8) | b2;
            if (!jumped) jump_to = i, jumped = 1;
            if (ptr >= len) return -1;
            i = ptr;
            continue;
        }
        if (i + lab > len) return -1;
        if (o && o < outsz) out[o++] = '.';
        size_t copy = (o + lab < outsz-1) ? lab : (outsz-1 - o);
        memcpy(out + o, p + i, copy);
        o += copy;
        i += lab;
    }
    if (o < outsz) out[o] = 0; else out[outsz-1] = 0;
    *off = jumped ? jump_to : i;
    return 0;
}

static uint16_t be16(const void *v){ const uint8_t *p=v; return (p[0]<<8)|p[1]; }

void parse_dns_udp(const uint8_t *payload, uint16_t len, int is_response)
{
    if (len < sizeof(struct dns_hdr)) { printf("        DNS <truncated>\n"); return; }
    const struct dns_hdr *h = (const struct dns_hdr*)payload;
    uint16_t flags   = be16(&h->flags);
    uint16_t qdcount = be16(&h->qdcount);
    uint16_t ancount = be16(&h->ancount);

    printf("        DNS %s id=0x%04x qd=%u an=%u flags=0x%04x\n",
           is_response ? "RESP" : "QUERY", be16(&h->id), qdcount, ancount, flags);

    uint16_t off = sizeof(*h);

    // Questions
    for (uint16_t q = 0; q < qdcount; q++) {
        char name[256];
        if (read_qname(payload, len, &off, name, sizeof(name)) < 0) { printf("          QNAME <bad>\n"); return; }
        if (off + 4 > len) { printf("          Q <truncated>\n"); return; }
        uint16_t qtype = be16(payload + off); off += 2;
        uint16_t qclass = be16(payload + off); off += 2;
        printf("          Q: %s  type=%u class=%u\n", name, qtype, qclass);
    }

    // Answers (print a couple for brevity)
    for (uint16_t a = 0; a < ancount && a < 3; a++) {
        char name[256];
        if (read_qname(payload, len, &off, name, sizeof(name)) < 0) { printf("          ANAME <bad>\n"); return; }
        if (off + 10 > len) { printf("          A <truncated>\n"); return; }
        uint16_t type = be16(payload + off); off += 2;
        uint16_t klass = be16(payload + off); off += 2;
        uint32_t ttl = (payload[off]<<24)|(payload[off+1]<<16)|(payload[off+2]<<8)|payload[off+3]; off += 4;
        uint16_t rdlen = be16(payload + off); off += 2;
        if (off + rdlen > len) { printf("          RDATA <truncated>\n"); return; }

        printf("          A: %s  type=%u class=%u ttl=%u ", name, type, klass, ttl);
        if (type == 1 && rdlen == 4) { // A
            printf("A=%u.%u.%u.%u\n", payload[off], payload[off+1], payload[off+2], payload[off+3]);
        } else if (type == 28 && rdlen == 16) { // AAAA
            printf("AAAA=");
            // simple IPv6 print
            for (int i=0;i<16;i++){ printf("%02x", payload[off+i]); if (i%2 && i!=15) printf(":"); }
            printf("\n");
        } else if (type == 5) { // CNAME
            uint16_t tmp = off;
            char cname[256];
            if (read_qname(payload, len, &tmp, cname, sizeof(cname))==0) printf("CNAME=%s\n", cname);
            else printf("CNAME=<bad>\n");
        } else {
            printf("RDATA len=%u (type=%u)\n", rdlen, type);
        }
        off += rdlen;
    }
}
