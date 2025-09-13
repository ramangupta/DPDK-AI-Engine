// parse_data.h
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>   // for usleep()

typedef struct {
    char type[8];           // FIX / ITCH / SBE type
    char protocol[8];       // FIX, ITCH, SBE
    char symbol[32];        // instrument
    double price;           // last/trade price
    double bid_price;       // optional, best bid
    double ask_price;       // optional, best ask
    uint32_t quantity;      // trade quantity
    uint32_t bid_qty;       // optional
    uint32_t ask_qty;       // optional
    char side;              // '1' = buy, '2' = sell, etc.
    uint64_t timestamp;     // msg timestamp in ms
    uint32_t seq_num;       // feed sequence number

    // optional / extended fields
    char exchange[16];      // multi-exchange support
    char order_id[32];      // order reference
    char exec_id[32];       // execution id
    char order_type;        // '1' = Market, '2' = Limit
    char misc_flags[16];    // quick flags
    double p95_price;       // analytics
    double p99_price;       // analytics
    double avg_price;       // analytics
} market_msg_t;

typedef struct {
    market_msg_t *msgs;
    size_t count;
    size_t capacity;
} market_data_view;

typedef struct {
    uint8_t *buf;
    size_t len;
    size_t capacity;
} fix_stream_t;

// Global or per-engine flow table (simplified)
typedef struct {
    char key[64];       // e.g., src:port-dst:port
    fix_stream_t stream;
} fix_flow_entry;

// Forward declare pkt_view from capture engine
typedef struct pkt_view pkt_view;

// --- FIX ---
void parse_fix(pkt_view *pv);

// --- ITCH ---
void parse_itch(pkt_view *pv);
void parse_itch_message(const uint8_t *buf, size_t len, market_data_view *mdv);

// --- SBE ---
void parse_sbe(pkt_view *pv);
void parse_sbe_message(const uint8_t *buf, size_t len, market_data_view *mdv);

void market_view_add(market_data_view *view, market_msg_t *msg);
market_data_view *market_view_get(void);
void market_view_init(void);
