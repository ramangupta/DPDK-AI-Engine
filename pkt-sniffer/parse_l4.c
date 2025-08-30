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

void parse_l4(pkt_view *pv, uint8_t proto)
{
    if (proto == IPPROTO_UDP) {
        stats_update(PROTO_UDP, pv->len);
        if (pv->len < sizeof(struct rte_udp_hdr)) 
        { 
            printf("      UDP <truncated>\n"); 
            return; 
        }
        const struct rte_udp_hdr *uh = (const struct rte_udp_hdr*)pv->data;
        uint16_t udplen = rte_be_to_cpu_16(uh->dgram_len);
        uint16_t paylen = (udplen >= sizeof(*uh) && udplen <= pv->len) ? (udplen - sizeof(*uh)) : 0;
        uint16_t sport = rte_be_to_cpu_16(uh->src_port);
        uint16_t dport = rte_be_to_cpu_16(uh->dst_port);
        const uint8_t *udp_payload = pv->data + sizeof(*uh);

        if (paylen > 0 && (sport == 53 || dport == 53)) {
            stats_update(PROTO_DNS, pv->len);
            parse_dns_udp(udp_payload, paylen, /*is_response=*/(sport == 53));
        }
        
        if ((sport == 67 && dport == 68) || (sport == 68 && dport == 67)) {
            pkt_view dhcpview = {
                .data = (uint8_t *)uh + sizeof(*uh),
                .len  = udplen,
                .src_port = sport,
                .dst_port = dport,
            };
            handle_dhcp(&dhcpview);
        }

        printf("      UDP %u → %u len=%u payload=%u\n",
            rte_be_to_cpu_16(uh->src_port),
            rte_be_to_cpu_16(uh->dst_port),
            udplen, paylen);

    } else if (proto == IPPROTO_TCP) {
        stats_update(PROTO_TCP, pv->len);
        if (pv->len < sizeof(struct rte_tcp_hdr)) { printf("      TCP <truncated>\n"); return; }
        const struct rte_tcp_hdr *th = (const struct rte_tcp_hdr*)pv->data;
        uint8_t hlen = (th->data_off >> 4) * 4;
        if (hlen < sizeof(struct rte_tcp_hdr) || hlen > pv->len) {
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
        uint16_t payload_len = (pv->len > hlen) ? (pv->len - hlen) : 0;
        const uint8_t *payload = (const uint8_t *)pv->data + hlen;

        pkt_view app_pv = {
            .data = (uint8_t *)payload,
            .len  = payload_len,
            .src_port = rte_be_to_cpu_16(th->src_port),
            .dst_port = rte_be_to_cpu_16(th->dst_port),
        };
        // copy over IPs from parent pv
        snprintf(app_pv.src_ip, sizeof(app_pv.src_ip), "%s", pv->src_ip);
        snprintf(app_pv.dst_ip, sizeof(app_pv.dst_ip), "%s", pv->dst_ip);

        if (rte_be_to_cpu_16(th->src_port) == 80 || 
            rte_be_to_cpu_16(th->dst_port) == 80) {
            printf(" HTTP packet \n");
            parse_http(&app_pv);
        } else if (payload_len >= 5 && (rte_be_to_cpu_16(th->src_port) == 443 || 
                   rte_be_to_cpu_16(th->dst_port) == 443)) {
            printf(" TLS packet \n");
            parse_tls(&app_pv);
        }

    } else if (proto == IPPROTO_ICMP) {
        stats_update(PROTO_ICMP, pv->len);
        parse_icmpv4(pv->data, pv->len);

    } else if (proto == IPPROTO_ICMPV6) {
        stats_update(PROTO_ICMP, pv->len);
        parse_icmpv6(pv->data, pv->len);

    } else {
        printf("      L4 proto=%u (not decoded)\n", proto);
    }
}
