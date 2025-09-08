#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "parse_dns.h"
#include "stats.h"

const char* rcode_str(int rcode) {
    switch (rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMP";
        case 5: return "REFUSED";
        default: return "UNKNOWN";
    }
}

static int read_qname(const uint8_t *p, uint16_t len, uint16_t *off, char *out, size_t outsz) 
{
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

void parse_dns_udp(const uint8_t *payload, uint16_t len, int is_response, uint64_t now)
{
    if (len < sizeof(struct dns_hdr)) { 
        PARSER_LOG_LAYER("DNS", COLOR_DNS, "        DNS <truncated>\n"); 
        global_stats.drop_invalid_dns++;
        global_stats.dropped++;
        return; 
    }

    const struct dns_hdr *h = (const struct dns_hdr*)payload;
    uint16_t id      = be16(&h->id);
    uint16_t flags   = be16(&h->flags);
    uint16_t qdcount = be16(&h->qdcount);
    uint16_t ancount = be16(&h->ancount);  

    int qr     = (flags >> 15) & 1;
    int opcode = (flags >> 11) & 0xF;
    int aa     = (flags >> 10) & 1;
    int tc     = (flags >> 9)  & 1;
    int rd     = (flags >> 8)  & 1;
    int ra     = (flags >> 7)  & 1;
    int rcode  = (flags & 0xF);     // response code (0=NOERROR, 3=NXDOMAIN, etc.)

    PARSER_LOG_LAYER("DNS", COLOR_DNS, "        DNS %s id=0x%04x qd=%u an=%u ",
           qr ? "RESP" : "QUERY", id, qdcount, ancount);
    if (qr)
        PARSER_LOG_LAYER("DNS", COLOR_DNS, "rcode=%s ", rcode_str(rcode));
    PARSER_LOG_LAYER("DNS", COLOR_DNS, "[AA=%d TC=%d RD=%d RA=%d OPCODE=%d]\n",
           aa, tc, rd, ra, opcode);

    uint16_t off = sizeof(*h);

    // Questions
    for (uint16_t q = 0; q < qdcount; q++) {
        char name[256];
        if (read_qname(payload, len, &off, name, sizeof(name)) < 0) { 
            PARSER_LOG_LAYER("DNS", COLOR_DNS, "          QNAME <bad>\n"); 
            global_stats.drop_invalid_dns++;
            global_stats.dropped++;
            return; 
        }
        if (off + 4 > len) { 
            PARSER_LOG_LAYER("DNS", COLOR_DNS, "          Q <truncated>\n"); 
            global_stats.drop_invalid_dns++;
            global_stats.dropped++;
            return; 
        }
        uint16_t qtype  = be16(payload + off); off += 2;
        uint16_t qclass = be16(payload + off); off += 2;

        PARSER_LOG_LAYER("DNS", COLOR_DNS, "          Q: %s  type=%u class=%u\n", name, qtype, qclass);

        if (!qr) {
            // record query in stats
            stats_record_dns_query(id, name, now, len);
        }
    }

    // Answers (print a couple for brevity)
    for (uint16_t a = 0; a < ancount && a < 3; a++) {
        char name[256];
        if (read_qname(payload, len, &off, name, sizeof(name)) < 0) { 
            DEBUG_LOG(DBG_DNS, "          ANAME <bad>\n"); 
            global_stats.drop_invalid_dns++;
            global_stats.dropped++;
            return; 
        }
        if (off + 10 > len) { 
            DEBUG_LOG(DBG_DNS, "          A <truncated>\n"); 
            global_stats.drop_invalid_dns++;
            global_stats.dropped++;
            return; 
        }
        uint16_t type   = be16(payload + off); off += 2;
        uint16_t klass  = be16(payload + off); off += 2;
        uint32_t ttl    = (payload[off]<<24)|(payload[off+1]<<16)|
                          (payload[off+2]<<8)|payload[off+3]; 
        off += 4;
        uint16_t rdlen  = be16(payload + off); off += 2;
        if (off + rdlen > len) { 
            DEBUG_LOG(DBG_DNS, "          RDATA <truncated>\n"); 
            global_stats.drop_invalid_dns++;
            global_stats.dropped++;
            return; 
        }

        char ans[512] = {0};
        PARSER_LOG_LAYER("DNS", COLOR_DNS, "          A: %s  type=%u class=%u ttl=%u ", name, type, klass, ttl);

        if (type == 1 && rdlen == 4) { // A
            snprintf(ans, sizeof(ans), "%u.%u.%u.%u",
                     payload[off], payload[off+1], payload[off+2], payload[off+3]);
            PARSER_LOG_LAYER("DNS", COLOR_DNS, "A=%s\n", ans);

        } else if (type == 28 && rdlen == 16) { // AAAA
            char *p = ans;
            for (int i=0; i<16; i++) {
                p += sprintf(p, "%02x", payload[off+i]);
                if (i%2 && i!=15) p += sprintf(p, ":");
            }
            PARSER_LOG_LAYER("DNS", COLOR_DNS, "AAAA=%s\n", ans);

        } else if (type == 5) { // CNAME
            uint16_t tmp = off;
            char cname[256];
            if (read_qname(payload, len, &tmp, cname, sizeof(cname)) == 0) {
                snprintf(ans, sizeof(ans), "%s", cname);
                PARSER_LOG_LAYER("DNS", COLOR_DNS, "CNAME=%s\n", cname);
            } else {
                PARSER_LOG_LAYER("DNS", COLOR_DNS, "CNAME=<bad>\n");
            }

        } else if (type == 15) { // MX
            if (rdlen >= 2) {
                uint16_t pref = be16(payload + off);
                uint16_t tmp = off + 2;
                char exch[256];
                if (read_qname(payload, len, &tmp, exch, sizeof(exch)) == 0) {
                    snprintf(ans, sizeof(ans), "MX %u %s", pref, exch);
                    PARSER_LOG_LAYER("DNS", COLOR_DNS, "MX=%u %s\n", pref, exch);
                }
            }
        }
        else if (type == 16) { // TXT
            if (rdlen > 0) {
                int txtlen = payload[off];
                if (txtlen < rdlen) {
                    snprintf(ans, sizeof(ans), "TXT \"%.*s\"", txtlen, payload+off+1);
                    PARSER_LOG_LAYER("DNS", COLOR_DNS, "%s\n", ans);
                }
            }
        }
        else if (type == 33) { // SRV
            if (rdlen >= 6) {
                uint16_t prio = be16(payload + off);
                uint16_t weight = be16(payload + off + 2);
                uint16_t port = be16(payload + off + 4);
                uint16_t tmp = off + 6;
                char target[256];
                if (read_qname(payload, len, &tmp, target, sizeof(target)) == 0) {
                    snprintf(ans, sizeof(ans), "SRV %u %u %u %s", prio, weight, port, target);
                    PARSER_LOG_LAYER("DNS", COLOR_DNS, "SRV %u %u %u %s\n", prio, weight, port, target);
                }
            }
        } else {
            PARSER_LOG_LAYER("DNS", COLOR_DNS, "RDATA len=%u (type=%u)\n", rdlen, type);
        }

        // record answer in stats
        if (qr && ans[0]) {
            stats_record_dns_answer(id, name, ans, rcode, now, len);
        }

        off += rdlen;
    }
}