#include "parse_data.h"
#include "engine/capture.h"
#include "utils/debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "gen_main.h"

// Fragment IPv4 packet carrying TCP + FIX payload
static void send_ipv4_fragments(flow_ctx_t *flow,
                                uint8_t *payload, size_t payload_len)
{
    uint8_t frame[ETH_MTU];
    size_t offset_payload = 0;
    static uint16_t ip_id = 0;

    // Prepare Ethernet header
    struct eth_hdr *eth = (struct eth_hdr*)frame;
    memset(eth->dst, 0x38, 6);
    memset(eth->src, 0x34, 6);
    eth->ethertype = htons(0x0800);

    ip_id++; // unique per batch

    while (offset_payload < payload_len) {
        size_t frag_size = payload_len - offset_payload;
        size_t max_frag = ETH_MTU - ETH_HDR_LEN - IP_HDR_LEN - TCP_HDR_LEN;
        if (frag_size > max_frag) frag_size = max_frag;

        // IPv4 header
        struct ipv4_hdr *ip = (struct ipv4_hdr*)(frame + ETH_HDR_LEN);
        ip->ver_ihl = 0x45;
        ip->ttl = 64;
        ip->proto = 6;
        ip->saddr = flow->src_ip;
        ip->daddr = flow->dst_ip;
        ip->tot_len = htons(IP_HDR_LEN + TCP_HDR_LEN + frag_size);
        ip->id = htons(ip_id);
        uint16_t frag_off = (offset_payload >> 3) & 0x1FFF;
        if (offset_payload + frag_size < payload_len) frag_off |= 0x2000; // MF
        ip->frag_off = htons(frag_off);

        // TCP header
        struct tcp_hdr *tcp = (struct tcp_hdr*)(frame + ETH_HDR_LEN + IP_HDR_LEN);
        tcp->src_port = htons(flow->src_port);
        tcp->dst_port = htons(flow->dst_port);
        tcp->seq = htonl(flow->tcp_seq + offset_payload);   // cumulative + offset
        tcp->ack_seq = 0;
        tcp->data_off = (TCP_HDR_LEN / 4) << 4;
        tcp->flags = 0x18; // PSH+ACK

        // Copy payload fragment
        memcpy(frame + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN,
               payload + offset_payload, frag_size);

        // pkt_view for parser
        pkt_view pv = {0};
        pv.data = frame;
        pv.len = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + frag_size;

        char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &flow->src_ip, src_ip_str, sizeof(src_ip_str));
        inet_ntop(AF_INET, &flow->dst_ip, dst_ip_str, sizeof(dst_ip_str));
        strncpy(pv.src_ip, src_ip_str, sizeof(pv.src_ip));
        strncpy(pv.dst_ip, dst_ip_str, sizeof(pv.dst_ip));
        pv.src_port = flow->src_port;
        pv.dst_port = flow->dst_port;
        pv.ts_ns = now_tsc();  

        parse_packet(&pv);

        uint64_t latency_ns = now_tsc() - pv.ts_ns;
        perf_update(pv.len, latency_ns);

        offset_payload += frag_size;
    }
}

int main(int argc, char **argv) 
{
    srand((unsigned)time(NULL));
    DEBUG_MASK = DBG_PARSER | DBG_APP | DBG_TCP | DBG_TCP_REASS;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [fix|itch|sbe|all]\n", argv[0]);
        return 1;
    }

    flow_ctx_t flow = {
        .src_ip   = inet_addr("10.0.0.1"),
        .dst_ip   = inet_addr("10.0.0.2"),
        .tcp_seq  = 1,
    };

    if (!strcmp(argv[1], "fix")) {
        flow.src_port = 5001;
        flow.dst_port = 5001;
    } else if (!strcmp(argv[1], "itch")) {
        flow.src_port = 5002;
        flow.dst_port = 5002;
    } else if (!strcmp(argv[1], "sbe")) {
        flow.src_port = 5003;
        flow.dst_port = 5003;
    } else if (!strcmp(argv[1], "all")) {
        // maybe rotate among 5001/5002/5003
        // or generate 3 separate flows
    }

    /* Initializations */
    perf_init();
    perf_start();
    tcp_reass_init();
    setup_signal_handlers();
    frag_reass_ipv6_init();
    market_view_init();

    uint8_t payload[MAX_PAYLOAD];

    while (1) {
        size_t payload_len = 0;

        if (!strcmp(argv[1], "fix")) {
            payload_len = generate_FIX(payload, sizeof(payload));
        } else if (!strcmp(argv[1], "itch")) {
            payload_len = generate_ITCH(payload, sizeof(payload));
        } else if (!strcmp(argv[1], "sbe")) {
            payload_len = generate_SBE(payload, sizeof(payload));
        } else if (!strcmp(argv[1], "all")) {
            // FIX flow
            flow_ctx_t fix_flow = flow;
            fix_flow.src_port = 5001;
            fix_flow.dst_port = 5001;
            size_t len_fix = generate_FIX(payload, sizeof(payload));
            if (len_fix) {
                send_ipv4_fragments(&fix_flow, payload, len_fix);
                fix_flow.tcp_seq += len_fix;
            }

            // ITCH flow
            flow_ctx_t itch_flow = flow;
            itch_flow.src_port = 5002;
            itch_flow.dst_port = 5002;
            size_t len_itch = generate_ITCH(payload, sizeof(payload));
            if (len_itch) {
                send_ipv4_fragments(&itch_flow, payload, len_itch);
                itch_flow.tcp_seq += len_itch;
            }

            // SBE flow
            flow_ctx_t sbe_flow = flow;
            sbe_flow.src_port = 5003;
            sbe_flow.dst_port = 5003;
            size_t len_sbe = generate_SBE(payload, sizeof(payload));
            if (len_sbe) {
                send_ipv4_fragments(&sbe_flow, payload, len_sbe);
                sbe_flow.tcp_seq += len_sbe;
            }

            // skip the bottom send, just poll stats
            stats_poll();
            continue;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[1]);
            return 1;
        }

        if (payload_len == 0)
            continue;

        // Send & update TCP sequence (single protocol case)
        send_ipv4_fragments(&flow, payload, payload_len);
        flow.tcp_seq += payload_len;

        stats_poll();
    }

    /* De-initialize routines */
    perf_stop();
    stats_report_final();
    frag_ipv4_flush_all();
    frag_ipv6_flush_all();
    tcp_reass_fini();

    fflush(stdout);
    fflush(stderr);

    printf("Synthetic %s stream completed\n", argv[1]);
    return 0;
}
