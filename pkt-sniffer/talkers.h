// talkers.h
#ifndef TALKERS_H
#define TALKERS_H

#include "capture.h"

#define MAX_TALKERS 1024
#define TOP_N 5

enum sort_mode {
    SORT_BY_PKTS,
    SORT_BY_BYTES
};

struct talker {
    char flow[128];     // "src_ip:src_port -> dst_ip:dst_port proto"
    char proto[8];    // "TCP", "UDP", "ICMP", etc.
    uint64_t pkts;
    uint64_t bytes;
};

extern struct talker table[MAX_TALKERS];
extern int used;

int cmp_bytes(const void *a, const void *b);
int cmp_pkts(const void *a, const void *b);

void talkers_update(const pkt_view *pv);
void talkers_report(void);
void talkers_reset(void);

// Expose sort mode (default = pkts)
extern enum sort_mode talkers_sort_mode;

#endif
