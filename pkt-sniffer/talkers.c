#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "talkers.h"
#include <linux/if_ether.h>   // ETH_P_ARP
#include <netinet/in.h>
#include "sniffer_proto.h"

struct talker table[MAX_TALKERS];
int used = 0;

enum sort_mode talkers_sort_mode = SORT_BY_PKTS; // default

int cmp_pkts(const void *a, const void *b) {
    const struct talker *ta = a, *tb = b;
    return (tb->pkts > ta->pkts) - (tb->pkts < ta->pkts);
}

int cmp_bytes(const void *a, const void *b) {
    const struct talker *ta = a, *tb = b;
    return (tb->bytes > ta->bytes) - (tb->bytes < ta->bytes);
}

void talkers_update(const pkt_view *pv) {
    char flowbuf[256];
    const char *proto_str;
    const char *src_ip = strlen(pv->src_ip) ? pv->src_ip : "?";
    const char *dst_ip = strlen(pv->dst_ip) ? pv->dst_ip : "?";

    if (pv->l3_proto == AF_INET || pv->l3_proto == AF_INET6) {
        // Use IANA protocol name for L4
        proto_str = proto_name(pv->l4_proto);

        snprintf(flowbuf, sizeof(flowbuf), "%s:%u -> %s:%u",
                 src_ip, pv->src_port,
                 dst_ip, pv->dst_port);

    } else if (pv->l3_proto == ETH_P_ARP) {
        proto_str = "ARP";
        snprintf(flowbuf, sizeof(flowbuf),
                 "%s (%s) -> %s (%s)",
                 src_ip, pv->src_mac,
                 dst_ip, pv->dst_mac);
    } else {
        proto_str = proto_name(pv->l3_proto);  // fallback: name L3 proto if possible
        snprintf(flowbuf, sizeof(flowbuf), "len=%u", pv->len);
    }

    // Update existing entry if match
    for (int i = 0; i < used; i++) {
        if (strcmp(table[i].flow, flowbuf) == 0 &&
            strcmp(table[i].proto, proto_str) == 0) {
            table[i].pkts++;
            table[i].bytes += pv->len;
            return;
        }
    }

    // Add new entry
    if (used < MAX_TALKERS) {
        strncpy(table[used].flow, flowbuf, sizeof(table[used].flow));
        table[used].flow[sizeof(table[used].flow) - 1] = '\0';

        strncpy(table[used].proto, proto_str, sizeof(table[used].proto));
        table[used].proto[sizeof(table[used].proto) - 1] = '\0';

        table[used].pkts = 1;
        table[used].bytes = pv->len;
        used++;
    }
}

static void human_bytes(uint64_t bytes, char *out, size_t outlen) {
    if (bytes < 1024)
        snprintf(out, outlen, "%-6lu B ", bytes);   // pad
    else if (bytes < 1024 * 1024)
        snprintf(out, outlen, "%-6.1f KB", bytes / 1024.0);
    else if (bytes < 1024ULL * 1024ULL * 1024ULL)
        snprintf(out, outlen, "%-6.1f MB", bytes / (1024.0 * 1024.0));
    else
        snprintf(out, outlen, "%-6.1f GB", bytes / (1024.0 * 1024.0 * 1024.0));
}


void talkers_report(void) {
    if (used == 0) {
        printf("\n=== Top Talkers (last 5s) ===\nNo talkers yet.\n");
        return;
    }

    if (talkers_sort_mode == SORT_BY_BYTES)
        qsort(table, used, sizeof(table[0]), cmp_bytes);
    else
        qsort(table, used, sizeof(table[0]), cmp_pkts);

    // Find max widths for Flow and Proto
    size_t max_flow = strlen("Flow");
    size_t max_proto = strlen("Proto");

    for (int i = 0; i < used; i++) {
        size_t flow_len = strlen(table[i].flow);
        if (flow_len > max_flow) max_flow = flow_len;

        size_t proto_len = strlen(table[i].proto);
        if (proto_len > max_proto) max_proto = proto_len;
    }

    printf("\n=== Top Talkers (last 5s, Sort Mode: %s) ===\n",
           talkers_sort_mode == SORT_BY_BYTES ? "Bytes" : "Packets");
    printf("%-*s %-*s %-10s %-10s\n",
           (int)max_flow, "Flow",
           (int)max_proto, "Proto",
           "Pkts", "Bytes");

    int limit = (used < TOP_N) ? used : TOP_N;
    for (int i = 0; i < limit; i++) {
        char bytestr[32];
        human_bytes(table[i].bytes, bytestr, sizeof(bytestr));

        printf("%-*s %-*s %-10lu %-10s\n",
                (int)max_flow, table[i].flow,
                (int)max_proto, table[i].proto,
                table[i].pkts,
                bytestr);
    }
}



void talkers_reset(void) {
    used = 0;
}
