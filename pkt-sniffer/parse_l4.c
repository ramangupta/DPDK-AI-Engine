#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "parse_l4.h"
#include "utils.h"
#include "parse_dns.h"
#include "stats.h"
#include "parse_dhcp.h"
#include "parse_http.h"
#include "parse_tls.h"
#include "tcp_reass.h"
#include "flows.h"

#ifndef L4_DEBUG
#define L4_DEBUG    0
#endif

#if L4_DEBUG
#define DEBUG_PRINT(fmt, ...) \
    fprintf(stderr, "[L4_PARSE][%s:%d] " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) do {} while (0)
#endif

static const char* icmpv4_type_name(uint8_t t) {
    switch (t) {
        case 0:  return "EchoReply";
        case 3:  return "DestUnreach";
        case 4:  return "SourceQuench";
        case 5:  return "Redirect";
        case 8:  return "EchoRequest";
        case 11: return "TimeExceeded";
        case 12: return "ParamProblem";
        default: return "ICMPv4";
    }
}

static void print_tcp_flags(uint8_t f) {
    // Order: C E U A P R S F
    if (f & RTE_TCP_CWR_FLAG) printf("C");
    if (f & RTE_TCP_ECE_FLAG) printf("E");
    if (f & RTE_TCP_URG_FLAG) printf("U");
    if (f & RTE_TCP_ACK_FLAG) printf("A");
    if (f & RTE_TCP_PSH_FLAG) printf("P");
    if (f & RTE_TCP_RST_FLAG) printf("R");
    if (f & RTE_TCP_SYN_FLAG) printf("S");
    if (f & RTE_TCP_FIN_FLAG) printf("F");
}

// ---- ICMPv4 minimal wire structs (avoid optional headers) ----
struct icmpv4_hdr_min {
    uint8_t  type;
    uint8_t  code;
    uint16_t cksum;
    // then type-specific body...
} __attribute__((__packed__));

struct icmp_echo {
    uint16_t id;
    uint16_t seq;
} __attribute__((__packed__));

// ---- ICMPv6 minimal wire structs ----
struct icmpv6_hdr_min {
    uint8_t  type;
    uint8_t  code;
    uint16_t cksum;
    // body follows
} __attribute__((__packed__));

struct icmpv6_echo {
    uint16_t id;
    uint16_t seq;
} __attribute__((__packed__));

struct icmpv6_nd_target {
    uint8_t target[16];
} __attribute__((__packed__));

static void parse_icmpv4(const uint8_t *p, uint16_t len) {
    if (len < sizeof(struct icmpv4_hdr_min)) { printf("      ICMPv4 <truncated>\n"); return; }
    const struct icmpv4_hdr_min *h = (const struct icmpv4_hdr_min*)p;
    printf("      ICMPv4 type=%u(%s) code=%u\n", h->type, icmpv4_type_name(h->type), h->code);

    const uint8_t *body = p + sizeof(*h);
    uint16_t bodylen = len - sizeof(*h);

    if ((h->type == 8 || h->type == 0) && bodylen >= sizeof(struct icmp_echo)) {
        const struct icmp_echo *e = (const struct icmp_echo*)body;
        printf("        Echo id=%u seq=%u\n", rte_be_to_cpu_16(e->id), rte_be_to_cpu_16(e->seq));
    } else if (h->type == 3 && bodylen >= 1) {
        // Destination Unreachable code meanings (brief)
        static const char* codes[] = {
            "Net Unreach","Host Unreach","Proto Unreach","Port Unreach",
            "Fragment Needed","Source Route Failed"
        };
        uint8_t c = h->code;
        const char* n = (c < 6) ? codes[c] : "Other";
        printf("        DestUnreach: %s\n", n);
    }
}

static void parse_icmpv6(const uint8_t *p, uint16_t len) {
    if (len < sizeof(struct icmpv6_hdr_min)) { printf("      ICMPv6 <truncated>\n"); return; }
    const struct icmpv6_hdr_min *h = (const struct icmpv6_hdr_min*)p;
    printf("      ICMPv6 type=%u code=%u\n", h->type, h->code);

    const uint8_t *body = p + sizeof(*h);
    uint16_t bodylen = len - sizeof(*h);

    switch (h->type) {
        case 128: // Echo Request
        case 129: // Echo Reply
            if (bodylen >= sizeof(struct icmpv6_echo)) {
                const struct icmpv6_echo *e = (const struct icmpv6_echo*)body;
                printf("        Echo id=%u seq=%u\n", rte_be_to_cpu_16(e->id), rte_be_to_cpu_16(e->seq));
            } else {
                printf("        Echo <truncated>\n");
            }
            break;

        case 135: // Neighbor Solicitation
            if (bodylen >= sizeof(struct icmpv6_nd_target)) {
                const struct icmpv6_nd_target *t = (const struct icmpv6_nd_target*)body;
                printf("        Neighbor Solicitation for ");
                print_ipv6_addr(t->target);
                printf("\n");
            } else {
                printf("        Neighbor Solicitation <truncated>\n");
            }
            break;

        case 136: // Neighbor Advertisement
            if (bodylen >= sizeof(struct icmpv6_nd_target)) {
                const struct icmpv6_nd_target *t = (const struct icmpv6_nd_target*)body;
                printf("        Neighbor Advertisement for ");
                print_ipv6_addr(t->target);
                printf("\n");
            } else {
                printf("        Neighbor Advertisement <truncated>\n");
            }
            break;

        case 133: // Router Solicitation
            printf("        Router Solicitation\n");
            break;
        case 134: // Router Advertisement
            printf("        Router Advertisement\n");
            break;
        default:
            // leave as generic
            break;
    }
}

static void parse_tcp_deliver_cb(tcp_flow_t *flow, int dir,
                                 const uint8_t *data, uint32_t len,
                                 time_t ts, void *user_ctx)
{
#if L4_DEBUG
    DEBUG_PRINT("TCP flow %s:%u -> %s:%u | dir=%d | ts=%ld | len=%u\n",
            tcp_flow_src_ip(flow), tcp_flow_src_port(flow),
            tcp_flow_dst_ip(flow), tcp_flow_dst_port(flow),
            dir, ts, len);

    if (len > 0) {
        DEBUG_PRINT("  First bytes: ");
        for (uint32_t i = 0; i < (len < 16 ? len : 16); i++) {
            DEBUG_PRINT("%02x ", data[i]);
        }
        DEBUG_PRINT("\n");
    }
#endif

    if (len == 0) return;

    // Wrap in pkt_view so application parsers can use it
    pkt_view app_pv = {0};
    app_pv.data = (uint8_t*)data;
    app_pv.len  = len;

    /// Fill src/dst IPs and ports based on direction
    if (dir == 0) {
        snprintf(app_pv.src_ip, sizeof(app_pv.src_ip), "%s", tcp_flow_src_ip(flow));
        snprintf(app_pv.dst_ip, sizeof(app_pv.dst_ip), "%s", tcp_flow_dst_ip(flow));
        app_pv.src_port = tcp_flow_src_port(flow);
        app_pv.dst_port = tcp_flow_dst_port(flow);
    } else {
        snprintf(app_pv.src_ip, sizeof(app_pv.src_ip), "%s", tcp_flow_dst_ip(flow));
        snprintf(app_pv.dst_ip, sizeof(app_pv.dst_ip), "%s", tcp_flow_src_ip(flow));
        app_pv.src_port = tcp_flow_dst_port(flow);
        app_pv.dst_port = tcp_flow_src_port(flow);
    }


    // Future: set src/dst ports + IP strings for richer logging
    // e.g., snprintf(app_pv.src_ip, sizeof(app_pv.src_ip), "%s", flow->src_ip);

    // Heuristic: TLS vs HTTP
#if L4_DEBUG
    DEBUG_PRINT("[TCP CB RAW] %.*s\n----\n", (int)app_pv.len, (const char*)app_pv.data);
#endif 

    int l7_proto = tcp_flow_l7_proto(flow);

    if (l7_proto == 0) {
        if (data[0] == 0x16 && len >= 5) {
            tcp_flow_set_l7_proto(flow, 2); // TLS
            DEBUG_PRINT("  → Delivering to TLS parser\n");
            parse_tls(&app_pv);
        } else if ((data[0] >= 'A' && data[0] <= 'Z') || (len >= 5 && memcmp(data, "HTTP/", 5) == 0)) {
            tcp_flow_set_l7_proto(flow, 1); // HTTP
            DEBUG_PRINT("  → Delivering to HTTP parser\n");
            parse_http(&app_pv);
        } else {
            DEBUG_PRINT("  → Unrecognized L7 payload (not HTTP/TLS)\n");
        }
    } else if (l7_proto == 1) {
        DEBUG_PRINT("  → Same flow cont ... Delivering to HTTP parser\n");
        // HTTP already identified
        parse_http(&app_pv);
    } else if (l7_proto == 2) {
        DEBUG_PRINT("  → Same flow cont ... Delivering to TLS parser\n");
        // TLS already identified
        parse_tls(&app_pv);
    }

#if 0
    if (len > 0) {
        // Heuristic: TLS starts with 0x16 handshake
        if (data[0] == 0x16 && len >= 5) {

            DEBUG_PRINT("  → Delivering to TLS parser\n");
            parse_tls(&app_pv);

        } else {
            // Crude HTTP detection: starts with alpha or "HTTP/"
            if ((data[0] >= 'A' && data[0] <= 'Z') ||
                (len >= 5 && memcmp(data, "HTTP/", 5) == 0))
            {

                DEBUG_PRINT("  → Delivering to HTTP parser\n");

                parse_http(&app_pv);
            } else {

                DEBUG_PRINT("  → Unrecognized L7 payload (not HTTP/TLS)\n");
                // future app parsers go here
            }
        }
    }
#endif 
}

void parse_l4(pkt_view *pv_full, pkt_view *pv_slice, uint64_t now)
{
    flow_key_t fkey;

    if (pv_slice->l4_proto == IPPROTO_UDP) {
        stats_update(PROTO_UDP, pv_slice->len);
        if (pv_slice->len < sizeof(struct rte_udp_hdr)) 
        { 
            printf("      UDP <truncated>\n"); 
            return; 
        }
        const struct rte_udp_hdr *uh = (const struct rte_udp_hdr*)pv_slice->data;
        uint16_t udplen = rte_be_to_cpu_16(uh->dgram_len);
        uint16_t paylen = (udplen >= sizeof(*uh) && udplen <= pv_slice->len) ? (udplen - sizeof(*uh)) : 0;
        uint16_t sport = rte_be_to_cpu_16(uh->src_port);
        uint16_t dport = rte_be_to_cpu_16(uh->dst_port);
        const uint8_t *udp_payload = pv_slice->data + sizeof(*uh);

        pv_full->src_port = sport;
        pv_full->dst_port = dport;

        flow_key_build(&fkey, (pv_full->l3_proto == AF_INET6) ? 6 : 4, 
                       pv_full->src_ip, pv_full->dst_ip,
                       IPPROTO_UDP, sport, dport);

        flow_update(&fkey, pv_slice->len);

        if (paylen > 0 && (sport == 53 || dport == 53)) {
            stats_update(PROTO_DNS, pv_slice->len);
            parse_dns_udp(udp_payload, paylen, /*is_response=*/(sport == 53), now);
        }
        
        printf("      UDP %u → %u len=%u payload=%u\n",
            rte_be_to_cpu_16(uh->src_port),
            rte_be_to_cpu_16(uh->dst_port),
            udplen, paylen);

        if ((sport == 67 && dport == 68) || (sport == 68 && dport == 67)) {
            pkt_view dhcpview = {
                .data = (uint8_t *)uh + sizeof(*uh),
                .len  = paylen,
                .src_port = sport,
                .dst_port = dport,
            };
            handle_dhcp(&dhcpview);
        }
    } else if (pv_slice->l4_proto == IPPROTO_TCP) {
        stats_update(PROTO_TCP, pv_slice->len);
        if (pv_slice->len < sizeof(struct rte_tcp_hdr)) { printf("      TCP <truncated>\n"); return; }
        const struct rte_tcp_hdr *th = (const struct rte_tcp_hdr*)pv_slice->data;
        uint8_t hlen = (th->data_off >> 4) * 4;
        if (hlen < sizeof(struct rte_tcp_hdr) || hlen > pv_slice->len) {
            printf("      TCP <bad header len>\n");
            return;
        }
        printf("      TCP %u → %u seq=%u ack=%u win=%u hlen=%u flags=",
               rte_be_to_cpu_16(th->src_port),
               rte_be_to_cpu_16(th->dst_port),
               rte_be_to_cpu_32(th->sent_seq),
               rte_be_to_cpu_32(th->recv_ack),
               rte_be_to_cpu_16(th->rx_win),
               hlen);
        print_tcp_flags(th->tcp_flags);
        printf("\n");
        // If you ever want to peek payload: const uint8_t* payload = data + hlen; uint16_t paylen = len - hlen;
        uint16_t payload_len = (pv_slice->len > hlen) ? (pv_slice->len - hlen) : 0;
        const uint8_t *payload = (const uint8_t *)pv_slice->data + hlen;

        pkt_view app_pv = {
            .data = (uint8_t *)payload,
            .len  = payload_len,
            .src_port = rte_be_to_cpu_16(th->src_port),
            .dst_port = rte_be_to_cpu_16(th->dst_port),
        };
        // copy over IPs from parent pv
        snprintf(app_pv.src_ip, sizeof(app_pv.src_ip), "%s", pv_slice->src_ip);
        snprintf(app_pv.dst_ip, sizeof(app_pv.dst_ip), "%s", pv_slice->dst_ip);

        pv_full->src_port = app_pv.src_port;
        pv_full->dst_port = app_pv.dst_port;

        flow_key_build(&fkey, (pv_full->l3_proto == AF_INET6) ? 6 : 4, 
                       pv_full->src_ip, pv_full->dst_ip,
                       IPPROTO_TCP, pv_full->src_port, pv_full->dst_port);

        flow_update(&fkey, pv_slice->len);

        // call reassembler
        tcp_reass_process_segment(pv_full->src_ip, pv_full->dst_ip,
                          pv_full->src_port, pv_full->dst_port,
                          payload, payload_len,
                          rte_be_to_cpu_32(th->sent_seq),
                          th->tcp_flags, time(NULL),
                          parse_tcp_deliver_cb, NULL);

    } else if (pv_slice->l4_proto == IPPROTO_ICMP) {
        stats_update(PROTO_ICMP, pv_slice->len);
        parse_icmpv4(pv_slice->data, pv_slice->len);

    } else if (pv_slice->l4_proto == IPPROTO_ICMPV6) {
        stats_update(PROTO_ICMP, pv_slice->len);
        parse_icmpv6(pv_slice->data, pv_slice->len);

    } else {
        printf("      L4 proto=%u (not decoded)\n", pv_slice->l4_proto);
    }
}
