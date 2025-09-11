#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "utils/utils.h"
#include "stats/stats.h"
#include "utils/flows.h"
#include "parsers/parse_l4.h"
#include "parsers/parse_dns.h"
#include "parsers/parse_dhcp.h"
#include "parsers/parse_http.h"
#include "parsers/parse_tls.h"
#include "parsers/tcp_reass.h"

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

static const char *tcp_flags_str(uint8_t f) {
    static char buf[16]; // thread-unsafe but fine for single-threaded logs
    int pos = 0;

    if (f & RTE_TCP_CWR_FLAG) buf[pos++] = 'C';
    if (f & RTE_TCP_ECE_FLAG) buf[pos++] = 'E';
    if (f & RTE_TCP_URG_FLAG) buf[pos++] = 'U';
    if (f & RTE_TCP_ACK_FLAG) buf[pos++] = 'A';
    if (f & RTE_TCP_PSH_FLAG) buf[pos++] = 'P';
    if (f & RTE_TCP_RST_FLAG) buf[pos++] = 'R';
    if (f & RTE_TCP_SYN_FLAG) buf[pos++] = 'S';
    if (f & RTE_TCP_FIN_FLAG) buf[pos++] = 'F';

    if (pos == 0) buf[pos++] = '-';  // no flags set
    buf[pos] = '\0';
    return buf;
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
    if (len < sizeof(struct icmpv4_hdr_min)) { 
        printf("      ICMPv4 <truncated>\n");
        global_stats.drop_invalid_l4++;
        global_stats.dropped++;
        return; 
    }
    const struct icmpv4_hdr_min *h = (const struct icmpv4_hdr_min*)p;
    PARSER_LOG_LAYER("ICMP", COLOR_ICMP, "      ICMPv4 type=%u(%s) code=%u", 
                     h->type, icmpv4_type_name(h->type), h->code);
    
    const uint8_t *body = p + sizeof(*h);
    uint16_t bodylen = len - sizeof(*h);

    if ((h->type == 8 || h->type == 0) && bodylen >= sizeof(struct icmp_echo)) {
        const struct icmp_echo *e = (const struct icmp_echo*)body;
        PARSER_LOG_LAYER("ICMP", COLOR_ICMP, "        Echo id=%u seq=%u", 
                         rte_be_to_cpu_16(e->id), rte_be_to_cpu_16(e->seq));
    } else if (h->type == 3 && bodylen >= 1) {
        // Destination Unreachable code meanings (brief)
        static const char* codes[] = {
            "Net Unreach","Host Unreach","Proto Unreach","Port Unreach",
            "Fragment Needed","Source Route Failed"
        };
        uint8_t c = h->code;
        const char* n = (c < 6) ? codes[c] : "Other";
        PARSER_LOG_LAYER("ICMP", COLOR_ICMP, "        DestUnreach: %s", n);
    }
}

static void parse_icmpv6(const uint8_t *p, uint16_t len) {
    if (len < sizeof(struct icmpv6_hdr_min)) { 
        printf("      ICMPv6 <truncated>"); 
        global_stats.drop_invalid_l4++;
        global_stats.dropped++;
        return; 
    }
    const struct icmpv6_hdr_min *h = (const struct icmpv6_hdr_min*)p;
    PARSER_LOG_LAYER("ICMPv6", COLOR_ICMP, "      ICMPv6 type=%u code=%u", h->type, h->code);

    const uint8_t *body = p + sizeof(*h);
    uint16_t bodylen = len - sizeof(*h);

    switch (h->type) {
        case 128: // Echo Request
        case 129: // Echo Reply
            if (bodylen >= sizeof(struct icmpv6_echo)) {
                const struct icmpv6_echo *e = (const struct icmpv6_echo*)body;
                PARSER_LOG_LAYER("ICMPv6", COLOR_ICMP, "        Echo id=%u seq=%u", 
                                rte_be_to_cpu_16(e->id), rte_be_to_cpu_16(e->seq));
            } else {
                PARSER_LOG_LAYER("ICMPv6", COLOR_ICMP, "        Echo <truncated>");
            }
            break;

        case 135: // Neighbor Solicitation
            if (bodylen >= sizeof(struct icmpv6_nd_target)) {
                const struct icmpv6_nd_target *t = (const struct icmpv6_nd_target*)body;
                PARSER_LOG_LAYER("ICMPv6", COLOR_ICMP, "        Neighbor Solicitation for ");
                print_icmpv6_addr(t->target);
            } else {
                PARSER_LOG_LAYER("ICMPv6", COLOR_ICMP, "        Neighbor Solicitation <truncated>");
            }
            break;

        case 136: // Neighbor Advertisement
            if (bodylen >= sizeof(struct icmpv6_nd_target)) {
                const struct icmpv6_nd_target *t = (const struct icmpv6_nd_target*)body;
                PARSER_LOG_LAYER("ICMPv6", COLOR_ICMP, "        Neighbor Advertisement for ");
                print_icmpv6_addr(t->target);
            } else {
                PARSER_LOG_LAYER("ICMPv6", COLOR_ICMP, "        Neighbor Advertisement <truncated>");
            }
            break;

        case 133: // Router Solicitation
            PARSER_LOG_LAYER("ICMPv6", COLOR_ICMP, "        Router Solicitation\n");
            break;
        case 134: // Router Advertisement
            PARSER_LOG_LAYER("ICMPv6", COLOR_ICMP, "        Router Advertisement\n");
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

    PARSER_LOG_LAYER("TCP", COLOR_TCP, "TCP flow %s:%u -> %s:%u | dir=%d | ts=%ld | len=%u\n",
            tcp_flow_src_ip(flow), tcp_flow_src_port(flow),
            tcp_flow_dst_ip(flow), tcp_flow_dst_port(flow),
            dir, ts, len);

    if (len > 0) {
        DEBUG_LOG(DBG_TCP,"  First bytes: ");
        for (uint32_t i = 0; i < (len < 16 ? len : 16); i++) {
            DEBUG_LOG(DBG_TCP,"%02x ", data[i]);
        }
    }


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

    DEBUG_LOG(DBG_TCP,"%.*s\n----\n", (int)app_pv.len, (const char*)app_pv.data);

    int l7_proto = tcp_flow_l7_proto(flow);

    if (l7_proto == 0) {
        if (data[0] == 0x16 && len >= 5) {
            tcp_flow_set_l7_proto(flow, 2); // TLS
            PARSER_LOG_LAYER("TCP", COLOR_TCP, "  → Delivering to TLS parser\n");
            parse_tls(&app_pv);
        } else if ((data[0] >= 'A' && data[0] <= 'Z') || (len >= 5 && memcmp(data, "HTTP/", 5) == 0)) {
            tcp_flow_set_l7_proto(flow, 1); // HTTP
            PARSER_LOG_LAYER("TCP", COLOR_TCP, "  → Delivering to HTTP parser\n");
            parse_http(&app_pv);
        } else {
            PARSER_LOG_LAYER("TCP", COLOR_TCP, "  → Unrecognized L7 payload (not HTTP/TLS)\n");
            global_stats.drop_unknown_l7++;
            global_stats.dropped++;
        }
    } else if (l7_proto == 1) {
        DEBUG_LOG(DBG_TCP, "  → Same flow cont ... Delivering to HTTP parser\n");
        // HTTP already identified
        parse_http(&app_pv);
    } else if (l7_proto == 2) {
        DEBUG_LOG(DBG_TCP, "  → Same flow cont ... Delivering to TLS parser\n");
        // TLS already identified
        parse_tls(&app_pv);
    }
}

void parse_l4(pkt_view *pv_full, pkt_view *pv_slice, uint64_t now)
{
    flow_key_t fkey;

    if (pv_slice->l4_proto == IPPROTO_UDP) {
        stats_update(PROTO_UDP, pv_slice->len);
        if (pv_slice->len < sizeof(struct rte_udp_hdr)) 
        { 
            DEBUG_LOG(DBG_UDP,"      UDP <truncated>\n");
            global_stats.drop_truncated_udp++;
            global_stats.dropped++; 
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
        
        PARSER_LOG_LAYER("UDP", COLOR_UDP, "      UDP %u → %u len=%u payload=%u\n",
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
        if (pv_slice->len < sizeof(struct rte_tcp_hdr)) { 
            DEBUG_LOG(DBG_TCP,"      TCP <truncated>\n"); 
            global_stats.drop_truncated_tcp++;
            global_stats.dropped++;
            return; 
        }
        const struct rte_tcp_hdr *th = (const struct rte_tcp_hdr*)pv_slice->data;
        uint8_t hlen = (th->data_off >> 4) * 4;
        if (hlen < sizeof(struct rte_tcp_hdr) || hlen > pv_slice->len) {
            DEBUG_LOG(DBG_TCP,"      TCP <bad header len>\n");
            global_stats.drop_bad_header_tcp++;
            global_stats.dropped++;
            return;
        }
        PARSER_LOG_LAYER("TCP", COLOR_TCP,
                        "TCP %u → %u seq=%u ack=%u win=%u hlen=%u flags=%s",
                        rte_be_to_cpu_16(th->src_port),
                        rte_be_to_cpu_16(th->dst_port),
                        rte_be_to_cpu_32(th->sent_seq),
                        rte_be_to_cpu_32(th->recv_ack),
                        rte_be_to_cpu_16(th->rx_win),
                        hlen,
                        tcp_flags_str(th->tcp_flags));

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
        DEBUG_LOG(DBG_L4, "      L4 proto=%u (not decoded)\n", pv_slice->l4_proto);
        if (pv_slice->l4_proto != IPPROTO_FRAGMENT) { 
        global_stats.drop_non_udp_tcp++;
        global_stats.dropped++;
        }
    }
}
