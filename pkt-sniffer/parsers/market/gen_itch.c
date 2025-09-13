// gen_itch.c
#include "parse_data.h"
#include "engine/capture.h"
#include "parsers/parse_eth.h"  // parse_packet()
#include "utils/debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "gen_main.h"

#define ETH_MTU_FORCE 100   // small to force fragmentation (tweakable)

// ITCH-like simple textual synthetic message:
// (this is NOT real binary ITCH — it's a readable placeholder)
static size_t generate_itch_message(char *buf, size_t buf_size, const char *symbol, size_t msg_index) {
    double price = 100.0 + (rand() % 10000) / 100.0;
    int qty = 1 + (rand() % 1000);
    char side = (rand() % 2) ? '1' : '2';  // FIX-style: '1'=Buy, '2'=Sell
    const char *msg_type = (rand() % 2) ? "QUOTE" : "TRADE";

    // timestamp (ms)
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long ms = ts.tv_nsec / 1000000;

    char order_id[32], exec_id[32];
    snprintf(order_id, sizeof(order_id), "ITCHORD%zu", msg_index + 1);
    snprintf(exec_id, sizeof(exec_id), "ITCHEXEC%zu", msg_index + 1);

    int n = snprintf(buf, buf_size,
        "ITCH|%s|%s|%.2f|%d|%c|SEQ=%zu|%s|%s|40=%c|207=%s|TS=%ld.%03ld\n",
        symbol,
        msg_type,
        price,
        qty,
        side,
        msg_index + 1,
        order_id,
        exec_id,
        '2',                // order_type = Limit
        "XNAS",             // exchange
        ts.tv_sec, ms
    );

    return n;
}

static size_t generate_itch_stream(uint8_t *buf, size_t buf_size, size_t num_msgs, const char *symbol) {
    size_t off = 0;
    for (size_t i = 0; i < num_msgs; ++i) {
        size_t n = generate_itch_message((char*)buf + off, buf_size - off, symbol, i);
        if (n == 0 || off + n >= buf_size) break;
        off += n;
    }
    return off;
}

// --- Public wrapper (called from gen_main.c) ---
size_t generate_ITCH(uint8_t *buf, size_t buf_size) {
    const char *symbol = "NSE_EQ";
    size_t num_msgs = 12;

    return generate_itch_stream(buf, buf_size, num_msgs, symbol);
}

