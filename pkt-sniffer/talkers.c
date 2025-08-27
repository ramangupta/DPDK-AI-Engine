#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "talkers.h"

struct talker {
    char ip[64];
    uint64_t pkts;
    uint64_t bytes;
};

static struct talker table[MAX_TALKERS];
static int used = 0;

enum sort_mode talkers_sort_mode = SORT_BY_PKTS; // default

static int cmp_pkts(const void *a, const void *b) {
    const struct talker *ta = a, *tb = b;
    return (tb->pkts > ta->pkts) - (tb->pkts < ta->pkts);
}

static int cmp_bytes(const void *a, const void *b) {
    const struct talker *ta = a, *tb = b;
    return (tb->bytes > ta->bytes) - (tb->bytes < ta->bytes);
}

void talkers_update(const char *ip, uint16_t len) {
    for (int i = 0; i < used; i++) {
        if (strcmp(table[i].ip, ip) == 0) {
            table[i].pkts++;
            table[i].bytes += len;
            return;
        }
    }
    if (used < MAX_TALKERS) {
        strncpy(table[used].ip, ip, sizeof(table[used].ip));
        table[used].ip[sizeof(table[used].ip)-1] = '\0';
        table[used].pkts = 1;
        table[used].bytes = len;
        used++;
    }
}

void talkers_report(void) {
    if (used == 0) {
        printf("\n=== Top Talkers (last 5 s) ===\nNo talkers yet.\n");
        return;
    }

    if (talkers_sort_mode == SORT_BY_BYTES)
        qsort(table, used, sizeof(table[0]), cmp_bytes);
    else
        qsort(table, used, sizeof(table[0]), cmp_pkts);

    printf("\n=== Top Talkers (last 5s Sort Mode %s) ===\n", 
            talkers_sort_mode == SORT_BY_BYTES ? "Bytes" : "Packets");
    int limit = (used < TOP_N) ? used : TOP_N;
    for (int i = 0; i < limit; i++) {
        printf("%-40s pkts=%lu bytes=%.1f KB\n",
               table[i].ip, table[i].pkts,
               table[i].bytes / 1024.0);
    }
}

void talkers_reset(void) {
    used = 0;
}
