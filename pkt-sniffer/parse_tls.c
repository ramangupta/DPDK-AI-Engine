/* Full-featured TLS metadata decoder Lightweight (no decryption) */
// parse_tls.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "capture.h"
#include "utils.h"
#include "stats.h"

// Toggle to 1 for detailed hex dumps when bounds fail
#ifndef TLS_DEBUG
#define TLS_DEBUG 0
#endif

struct tls_meta {
    char sni[256];
    char alpn[64];
    char version[16];
    char cipher[64];
};

// TLS Version mapping
static const char *tls_version_str(uint16_t v) {
    switch (v) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default: return "Unknown";
    }
}

// A few common cipher suites (add more as needed)
static const char *tls_cipher_str(uint16_t id) {
    switch (id) {
        case 0x1301: return "TLS_AES_128_GCM_SHA256";
        case 0x1302: return "TLS_AES_256_GCM_SHA384";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
        case 0x009c: return "TLS_RSA_WITH_AES_128_GCM_SHA256";
        case 0x009d: return "TLS_RSA_WITH_AES_256_GCM_SHA384";
        case 0x002f: return "TLS_RSA_WITH_AES_128_CBC_SHA";
        case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
        default: return "Unknown";
    }
}

#if TLS_DEBUG
static void hex_dump(const uint8_t *p, size_t len, size_t max)
{
    size_t n = (len < max) ? len : max;
    for (size_t i = 0; i < n; i++) {
        if ((i % 16) == 0) printf("        ");
        printf("%02x ", p[i]);
        if ((i % 16) == 15) printf("\n");
    }
    if (n % 16) printf("\n");
}
#endif

static inline int be16(const uint8_t *p) { return (p[0] << 8) | p[1]; }
static inline int be24(const uint8_t *p) { return (p[0] << 16) | (p[1] << 8) | p[2]; }

static const char* tls_ct_name(uint8_t ct) {
    switch (ct) {
        case 20: return "ChangeCipherSpec";
        case 21: return "Alert";
        case 22: return "Handshake";
        case 23: return "ApplicationData";
        default: return "Unknown";
    }
}

static void parse_extensions(const uint8_t *exts, size_t exts_len, struct tls_meta *meta)
{
    size_t pos = 0;
    while (pos + 4 <= exts_len) {
        uint16_t type = be16(exts + pos);
        uint16_t elen = be16(exts + pos + 2);
        pos += 4;
        if (pos + elen > exts_len) return;

        // SNI (type 0)
        if (type == 0x0000 && elen >= 5) {
            const uint8_t *p = exts + pos;
            int list_len = be16(p); p += 2;
            if (list_len >= 3) {
                uint8_t name_type = p[0];
                int name_len = be16(p + 1);
                p += 3;
                if (name_type == 0 && name_len > 0 && name_len < (int)sizeof(meta->sni)) {
                    memcpy(meta->sni, p, name_len);
                    meta->sni[name_len] = '\0';
                    printf("      TLS SNI: %s\n", meta->sni);
                }
            }
        }
        // ALPN (type 16)
        else if (type == 0x0010 && elen >= 2) {
            const uint8_t *p = exts + pos;
            int list_len = be16(p); p += 2;
            const uint8_t *end = p + list_len;
            if (list_len > 0 && end <= exts + pos + elen) {
                uint8_t l = *p++;
                if (l > 0 && (p + l) <= end && l < sizeof(meta->alpn)) {
                    memcpy(meta->alpn, p, l);
                    meta->alpn[l] = '\0';
                    printf("      TLS ALPN: %s\n", meta->alpn);
                }
            }
        }
        pos += elen;
    }
}

static void parse_client_hello(const uint8_t *hs, size_t hs_len, struct tls_meta *meta)
{
    if (hs_len < 2 + 32 + 1) return;

    const uint8_t *p = hs;
    uint16_t legacy_version = be16(p); p += 2;
    (void)legacy_version;
    p += 32; // random

    uint8_t sid_len = *p++;
    p += sid_len;

    uint16_t cs_len = be16(p); p += 2;
    p += cs_len;

    uint8_t comp_len = *p++;
    p += comp_len;

    uint16_t ext_len = be16(p); p += 2;
    if ((size_t)(p - hs) + ext_len > hs_len) return;
    if (ext_len) parse_extensions(p, ext_len, meta);
}

static void parse_server_hello(const uint8_t *hs, size_t hs_len, struct tls_meta *meta)
{
    if (hs_len < 2 + 32 + 1 + 2 + 1) return;

    const uint8_t *p = hs;

    uint16_t legacy_version = be16(p); p += 2;
    snprintf(meta->version, sizeof(meta->version), "%s", tls_version_str(legacy_version));

    p += 32; // Random

    uint8_t sid_len = *p++;
    if (p + sid_len > hs + hs_len) return;
    p += sid_len;

    uint16_t chosen = be16(p); p += 2;
    snprintf(meta->cipher, sizeof(meta->cipher), "%s", tls_cipher_str(chosen));

    uint8_t comp = *p++; (void)comp;

    if (p + 2 > hs + hs_len) return;
    uint16_t ext_len = be16(p); p += 2;
    if (p + ext_len > hs + hs_len) return;

    size_t pos = 0;
    while (pos + 4 <= ext_len) {
        uint16_t type = be16(p + pos);
        uint16_t elen = be16(p + pos + 2);
        pos += 4;
        if (pos + elen > ext_len) break;

        if (type == 0x002b && elen >= 2) {
            // supported_versions extension
            uint16_t selver = be16(p + pos);
            snprintf(meta->version, sizeof(meta->version), "%s", tls_version_str(selver));
        }

        pos += elen;
    }
}


void parse_tls(const pkt_view *pv)
{
    struct tls_meta meta = {0};  
    const uint8_t *p = pv->data;
    size_t remain = pv->len;

    while (remain >= 5) {
        uint8_t ct = p[0];
        uint16_t rlen = be16(p + 3);

        if (ct < 20 || ct > 23) return;

        printf("      TLS: content_type=%u (%s) record_len=%u\n", ct, tls_ct_name(ct), rlen);

        if (remain < 5u + rlen) return;

        const uint8_t *rec = p + 5;
        size_t rpay = rlen;

        if (ct == 23) {
            stats_update(PROTO_TLS_APPDATA, rpay);
            printf("      TLS Application Data (%zu bytes)\n", rpay);
        } else if (ct == 22) {
            stats_update(PROTO_TLS_HANDSHAKE, rpay);
            size_t hp = 0;
            while (hp + 4 <= rpay) {
                const uint8_t *hs = rec + hp;
                uint8_t hs_type = hs[0];
                uint32_t hs_len  = be24(hs + 1);
                if (hp + 4u + hs_len > rpay) break;

                if (hs_type == 1) { // ClientHello
                    printf("      TLS Handshake: ClientHello (len=%u)\n", hs_len);
                    parse_client_hello(hs + 4, hs_len, &meta);
                    char srcbuf[80], dstbuf[80];
                    snprintf(srcbuf, sizeof(srcbuf), "%s:%u", pv->src_ip, pv->src_port);
                    snprintf(dstbuf, sizeof(dstbuf), "%s:%u", pv->dst_ip, pv->dst_port);
                    stats_record_tls(srcbuf, dstbuf,
                        meta.sni[0] ? meta.sni : "-",
                        meta.alpn[0] ? meta.alpn : "-",
                        meta.version[0] ? meta.version : "-",
                        "-");
                } else if (hs_type == 2) { // ServerHello
                    printf("      TLS Handshake: ServerHello (len=%u)\n", hs_len);
                    parse_server_hello(hs + 4, hs_len, &meta);
                    char srcbuf[80], dstbuf[80];
                    snprintf(srcbuf, sizeof(srcbuf), "%s:%u", pv->src_ip, pv->src_port);
                    snprintf(dstbuf, sizeof(dstbuf), "%s:%u", pv->dst_ip, pv->dst_port);
                    stats_record_tls(srcbuf, dstbuf,
                        "-",
                        meta.alpn[0] ? meta.alpn : "-",
                        meta.version[0] ? meta.version : "-",
                        meta.cipher[0] ? meta.cipher : "-");
                }
                hp += 4u + hs_len;
            }
        }
        p += 5u + rlen;
        remain -= 5u + rlen;
    }
}
