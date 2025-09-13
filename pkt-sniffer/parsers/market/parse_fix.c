#include "parse_data.h"
#include "engine/capture.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#define FIX_SOH 0x01

fix_flow_entry fix_flow_table[256]; // Example

static const char* fix_side_desc(char side) {
    switch (side) {
        case '1': return "Buy";
        case '2': return "Sell";
        case '3': return "BuyMinus";
        case '4': return "SellPlus";
        default:  return "-";
    }
}

const char* fix_ordtype_desc(char t) {
    switch (t) {
        case '1': return "Market";
        case '2': return "Limit";
        case '3': return "Stop";
        case '4': return "Stop Limit";
        default:  return "?";
    }
}

// Initialize stream buffer
void fix_stream_init(fix_stream_t *stream, size_t initial_size) {
    stream->buf = calloc(1, initial_size);
    stream->len = 0;
    stream->capacity = initial_size;
}

// Free stream buffer
void fix_stream_free(fix_stream_t *stream) {
    free(stream->buf);
    stream->buf = NULL;
    stream->len = 0;
    stream->capacity = 0;
}

// Append new data to stream
void fix_stream_append(fix_stream_t *stream, const uint8_t *data, size_t data_len) {
    if (stream->len + data_len > stream->capacity) {
        size_t new_capacity = (stream->len + data_len) * 2;
        uint8_t *tmp = realloc(stream->buf, new_capacity);
        if (!tmp) return;
        stream->buf = tmp;
        stream->capacity = new_capacity;
    }
    memcpy(stream->buf + stream->len, data, data_len);
    stream->len += data_len;
}

// Find or create stream buffer for pkt_view
fix_stream_t* get_stream_for_pkt(pkt_view *pv) {
    char key[256];
    snprintf(key, sizeof(key), "%s:%u-%s:%u", pv->src_ip, pv->src_port, pv->dst_ip, pv->dst_port);

    for (int i = 0; i < 256; i++) {
        if (strcmp(fix_flow_table[i].key, key) == 0) 
            return &fix_flow_table[i].stream;

        if (fix_flow_table[i].key[0] == '\0') {
            strcpy(fix_flow_table[i].key, key);
            fix_stream_init(&fix_flow_table[i].stream, 1024);
            return &fix_flow_table[i].stream;
        }
    }
    return NULL; // table full
}

// Parse timestamp helper
static uint64_t parse_fix_timestamp(const char *ts_str) {
    if (!ts_str || strlen(ts_str) < 19) return 0;

    struct tm t = {0};
    int msec = 0;
    sscanf(ts_str, "%4d%2d%2d-%2d:%2d:%2d.%3d",
           &t.tm_year, &t.tm_mon, &t.tm_mday,
           &t.tm_hour, &t.tm_min, &t.tm_sec, &msec);

    t.tm_year -= 1900;
    t.tm_mon -= 1;

    time_t s = mktime(&t);
    if (s == -1) return 0;
    return ((uint64_t)s * 1000) + msec;
}

// Parse one complete FIX message from buffer
// Returns number of bytes consumed
size_t parse_one_fix_message(uint8_t *buf, size_t len, market_msg_t *msg_out) {
    size_t i = 0;
    int saw_checksum = 0;

    market_msg_t msg = {0};

    while (i < len) {
        size_t start = i;

        // Find next SOH
        while (i < len && buf[i] != FIX_SOH) i++;
        if (i >= len) break; // incomplete field

        size_t pair_len = i - start;
        if (pair_len == 0) { i++; continue; }

        char pair[128] = {0};
        if (pair_len >= sizeof(pair)) pair_len = sizeof(pair) - 1;
        memcpy(pair, buf + start, pair_len);

        char *eq = strchr(pair, '=');
        if (!eq) { i++; continue; }
        *eq = '\0';
        const char *tag = pair;
        const char *value = eq + 1;

        strncpy(msg.protocol, "FIX", sizeof(msg.protocol)-1);
        
        // Map FIX tags to enriched fields
        if (strcmp(tag, "35") == 0) strncpy(msg.type, value, sizeof(msg.type)-1);
        else if (strcmp(tag, "55") == 0) strncpy(msg.symbol, value, sizeof(msg.symbol)-1);
        else if (strcmp(tag, "44") == 0) msg.price = strtod(value, NULL);
        else if (strcmp(tag, "38") == 0) msg.quantity = (uint32_t)strtoul(value, NULL, 10);
        else if (strcmp(tag, "54") == 0) msg.side = value[0];
        else if (strcmp(tag, "34") == 0) msg.seq_num = (uint32_t)atoi(value);
        else if (strcmp(tag, "52") == 0) msg.timestamp = parse_fix_timestamp(value);

        // Additional enriched fields
        else if (strcmp(tag, "37") == 0) strncpy(msg.order_id, value, sizeof(msg.order_id)-1);
        else if (strcmp(tag, "17") == 0) strncpy(msg.exec_id, value, sizeof(msg.exec_id)-1);
        else if (strcmp(tag, "40") == 0) msg.order_type = value[0];
        else if (strcmp(tag, "207") == 0) strncpy(msg.exchange, value, sizeof(msg.exchange)-1);

        else if (strcmp(tag, "10") == 0) { // checksum → end of message
            saw_checksum = 1;
            i++; // include SOH
            break;
        }

        i++; // skip SOH
    }

    if (!saw_checksum) return 0; // incomplete message

    if (msg_out) *msg_out = msg;
    return i;
}



// Parse stream-safe FIX messages
void parse_fix_stream(fix_stream_t *stream, market_data_view *mdv) {
    size_t offset = 0;
    while (offset < stream->len) {
        market_msg_t msg;
        size_t consumed = parse_one_fix_message(stream->buf + offset, stream->len - offset, &msg);
        if (consumed == 0) 
            break; // incomplete message

        if (mdv->count < mdv->capacity) mdv->msgs[mdv->count++] = msg;

        offset += consumed;
    }

    // Shift remaining incomplete bytes to beginning
    if (offset > 0 && offset < stream->len) {
        memmove(stream->buf, stream->buf + offset, stream->len - offset);
        stream->len -= offset;
    } else {
        stream->len = 0;
    }
}

// Exposed function
void parse_fix(pkt_view *pv) 
{
    fix_stream_t *stream = get_stream_for_pkt(pv);
    if (!stream) return;

    market_data_view *global_view = market_view_get();

    // Append new payload
    fix_stream_append(stream, pv->data, pv->len);

    // Parse messages from stream
    market_data_view mdv = {0};
    mdv.capacity = 128;
    mdv.msgs = calloc(mdv.capacity, sizeof(market_msg_t));
    if (!mdv.msgs) return;

    parse_fix_stream(stream, &mdv); // same internal parsing logic

    DEBUG_LOG(DBG_APP, "FIX parsed %zu msgs\n", mdv.count);
    for (size_t j = 0; j < mdv.count; j++) {
        market_msg_t *m = &mdv.msgs[j];
        DEBUG_LOG(DBG_APP,
            "  [%zu] type=%s | sym=%s | px=%.2f | qty=%u | side=%s | seq=%u | ts=%" PRIu64
            " | order_id=%s | exec_id=%s | ord_type=%s | exch=%s\n",
            j,
            m->type,
            m->symbol,
            m->price,
            m->quantity,
            fix_side_desc(m->side),
            m->seq_num,
            m->timestamp,
            m->order_id[0] ? m->order_id : "-",   // safe: print "-" if empty
            m->exec_id[0] ? m->exec_id : "-",
            m->order_type ? fix_ordtype_desc(m->order_type) : "-", // optional helper
            m->exchange[0] ? m->exchange : "-"
        );
        market_view_add(global_view, m);
    }

    free(mdv.msgs);

    // Free stream if all data was consumed
    if (stream->len == 0) {
        fix_stream_free(stream);
        // Remove from table
        for (int i = 0; i < 256; i++) {
            if (&fix_flow_table[i].stream == stream) {
                fix_flow_table[i].key[0] = '\0';
                break;
            }
        }
    }
}