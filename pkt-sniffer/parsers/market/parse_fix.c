#define _GNU_SOURCE
#include "parse_data.h"
#include "engine/capture.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include "anomaly/anomaly.h"  // common header for inter_arrival, burst, protocol coverage
#include "anomaly/futures_options.h"

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
    if (!ts_str) return 0;

    char buf[32] = {0};
    strncpy(buf, ts_str, sizeof(buf)-1);  // truncate if necessary

    // Ensure we have enough characters
    if (strlen(buf) < 19) return 0;

    struct tm t = {0};
    int msec = 0;

    if (sscanf(buf, "%4d%2d%2d-%2d:%2d:%2d.%3d",
               &t.tm_year, &t.tm_mon, &t.tm_mday,
               &t.tm_hour, &t.tm_min, &t.tm_sec, &msec) != 7) {
        return 0;
    }

    t.tm_year -= 1900;
    t.tm_mon  -= 1;

    time_t s = timegm(&t);
    if (s == -1) return 0;

    return ((uint64_t)s * 1000) + msec;
}



void log_fix_message(const market_msg_t *m, uint8_t *start, uint8_t *end) {
    printf("[DEBUG] Parsed FIX msg: ");
    for (uint8_t *p = start; p < end; p++) {
        if (*p == FIX_SOH) fputc('|', stdout);
        else fputc(*p, stdout);
    }
    fputc('\n', stdout);
}

static void copy_fix_field(char *dst, size_t dst_size,
                           const char *start, const char *end) {
    if (!start || !end || end < start) {
        if (dst_size > 0) dst[0] = '\0';
        return;
    }
    size_t len = (size_t)(end - start);
    if (len >= dst_size) len = dst_size - 1;
    memcpy(dst, start, len);
    dst[len] = '\0';
}

// Parse one complete FIX message from buffer
// Returns number of bytes consumed
// Parse one full FIX message from buffer
// Returns number of bytes consumed, 0 if incomplete
// Parse one full FIX message safely
// Returns number of bytes consumed, 0 if incomplete
size_t parse_one_fix_message(uint8_t *buf, size_t len, market_msg_t *msg_out) {
    if (len < 10) return 0; // too small for a FIX message

    // 1. Find start of FIX message
    uint8_t *start = (uint8_t *)memmem(buf, len, "8=FIX", 5);
    if (!start) return 0;

    size_t remaining = len - (start - buf);

    // 2. Find checksum field "10="
    uint8_t *checksum_tag = (uint8_t *)memmem(start, remaining, "10=", 3);
    if (!checksum_tag) return 0;

    // Find end of checksum (SOH)
    uint8_t *end = memchr(checksum_tag, FIX_SOH, remaining - (checksum_tag - start));
    if (!end) return 0;
    end++; // include SOH

    market_msg_t msg = {0};
    strncpy(msg.protocol, "FIX", sizeof(msg.protocol) - 1);

    // 3. Parse fields between start and end
    uint8_t *ptr = start;
    while (ptr < end) {
        uint8_t *soh = memchr(ptr, FIX_SOH, end - ptr);
        if (!soh) break;

        uint8_t *eq = memchr(ptr, '=', soh - ptr);
        if (!eq) {
            ptr = soh + 1;
            continue;
        }

        size_t tag_len = (size_t)(eq - ptr);
        if (tag_len >= 16) tag_len = 15;

        char tag[16] = {0};
        memcpy(tag, ptr, tag_len);

        const char *value   = (const char *)(eq + 1);
        const char *val_end = (const char *)soh;

        // sanity check
        if (!value || val_end < value || (size_t)(val_end - value) >= 256) {
            fprintf(stderr, "[WARN] Invalid field length, skipping: tag=%s\n", tag);
            ptr = soh + 1;
            continue;
        }

        char tmpbuf[64]; // temp buffer for numbers/strings

        if (strcmp(tag, "35") == 0)
            copy_fix_field(msg.type, sizeof(msg.type), value, val_end);
        else if (strcmp(tag, "55") == 0) {
            int accept = 0;

            // Accept if it starts with a letter
            if (isalpha((unsigned char)value[0])) {
                accept = 1;
            }
            // Special exception for 360ONE
            else if ((val_end - value) == 6 && strncmp(value, "360ONE", 6) == 0) {
                accept = 1;
            }

            if (accept) {
                copy_fix_field(msg.symbol, sizeof(msg.symbol), value, val_end);
            } else {
                fprintf(stderr, "[WARN] Ignoring malformed 55 field: '%.*s'\n",
                        (int)(val_end - value), value);
            }
        }
        else if (strcmp(tag, "44") == 0) {
            copy_fix_field(tmpbuf, sizeof(tmpbuf), value, val_end);
            msg.price = strtod(tmpbuf, NULL);
        }
        else if (strcmp(tag, "38") == 0) {
            copy_fix_field(tmpbuf, sizeof(tmpbuf), value, val_end);
            msg.quantity = (uint32_t)strtoul(tmpbuf, NULL, 10);
        } else if (strcmp(tag, "54") == 0)
            msg.side = value[0];
        else if (strcmp(tag, "34") == 0) {
            copy_fix_field(tmpbuf, sizeof(tmpbuf), value, val_end);
            msg.seq_num = (uint32_t)atoi(tmpbuf);
        }
        else if (strcmp(tag, "52") == 0) {
            copy_fix_field(tmpbuf, sizeof(tmpbuf), value, val_end);
            msg.timestamp = parse_fix_timestamp(tmpbuf);
        }
        else if (strcmp(tag, "37") == 0)
            copy_fix_field(msg.order_id, sizeof(msg.order_id), value, val_end);
        else if (strcmp(tag, "17") == 0)
            copy_fix_field(msg.exec_id, sizeof(msg.exec_id), value, val_end);
        else if (strcmp(tag, "40") == 0)
            msg.order_type = value[0];
        else if (strcmp(tag, "207") == 0)
            copy_fix_field(msg.exchange, sizeof(msg.exchange), value, val_end);
        else if (strcmp(tag, "1000") == 0) {
            copy_fix_field(tmpbuf, sizeof(tmpbuf), value, val_end);
            msg.open_interest = strtoull(tmpbuf, NULL, 10);   // use uint64_t
        }
        else if (strcmp(tag, "1001") == 0) {
            copy_fix_field(tmpbuf, sizeof(tmpbuf), value, val_end);
            msg.cci = atoi(tmpbuf);   // Commodity Channel Index
        } else if (strcmp(tag, "1002") == 0) {
            copy_fix_field(tmpbuf, sizeof(tmpbuf), value, val_end);
            msg.atr = atof(tmpbuf);
        } else if (strcmp(tag, "5001") == 0) {
            copy_fix_field(tmpbuf, sizeof(tmpbuf), value, val_end);
            msg.day_open = strtod(tmpbuf, NULL);
        }
        else if (strcmp(tag, "5002") == 0) {
            copy_fix_field(tmpbuf, sizeof(tmpbuf), value, val_end);
            msg.day_high = strtod(tmpbuf, NULL);
        }
        else if (strcmp(tag, "5003") == 0) {
            copy_fix_field(tmpbuf, sizeof(tmpbuf), value, val_end);
            msg.day_low = strtod(tmpbuf, NULL);
        }
        else if (strcmp(tag, "5004") == 0) {
            copy_fix_field(tmpbuf, sizeof(tmpbuf), value, val_end);
            msg.prev_close = strtod(tmpbuf, NULL);
        }
        else if (strcmp(tag, "5005") == 0) {
            copy_fix_field(tmpbuf, sizeof(tmpbuf), value, val_end);
            msg.high_52wk = strtod(tmpbuf, NULL);
        }
        else if (strcmp(tag, "5006") == 0) {
            copy_fix_field(tmpbuf, sizeof(tmpbuf), value, val_end);
            msg.low_52wk = strtod(tmpbuf, NULL);
        }
        else if (strcmp(tag, "5007") == 0) {
            copy_fix_field(tmpbuf, sizeof(tmpbuf), value, val_end);
            msg.avg_volume_10d = strtod(tmpbuf, NULL);
        }
        else if (strcmp(tag, "5008") == 0) {
            copy_fix_field(tmpbuf, sizeof(tmpbuf), value, val_end);
            msg.avg_volume_3m = strtod(tmpbuf, NULL);
        } else if (strcmp(tag, "5012") == 0) {
            copy_fix_field(tmpbuf, sizeof(tmpbuf), value, val_end);
            msg.day_volume = strtoull(tmpbuf, NULL, 10);
        }

        ptr = soh + 1; // move past SOH
    }

    if (msg_out) *msg_out = msg;

    return (size_t)(end - start);
}


// Stream-safe parser
void parse_fix_stream(fix_stream_t *stream, market_data_view *mdv) {
    size_t offset = 0;

    while (offset < stream->len) {
        market_msg_t msg;
        size_t consumed = parse_one_fix_message(stream->buf + offset, stream->len - offset, &msg);
        if (consumed == 0) break; // incomplete message

        // Skip invalid or empty symbols
        if (!msg.symbol[0] || !is_valid_symbol(msg.symbol)) {
            fprintf(stderr, "[WARN] Dropping invalid symbol: '%s'\n", msg.symbol);
            offset += consumed;
            continue;
        }

        // Add to market view if space available
        if (mdv->count < mdv->capacity) mdv->msgs[mdv->count++] = msg;

        offset += consumed;
    }

    // Shift remaining bytes
    if (offset > 0 && offset < stream->len) {
        memmove(stream->buf, stream->buf + offset, stream->len - offset);
        stream->len -= offset;
    } else stream->len = 0;
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
                " | order_id=%s | exec_id=%s | ord_type=%s | exch=%s | OI=%" PRIu64 " | CCI=%d\n"
                "  | ATR=%.2f | day_open=%.2f | day_high=%.2f | day_low=%.2f | prev_close=%.2f\n"
                "      high_52wk=%.2f | low_52wk=%.2f | avg_vol_10d=%.2f | avg_vol_3m=%.2f\n"
                "      market_cap=%.2f | pe_ratio=%.2f | eps=%.2f\n",
                j,
                m->type,
                m->symbol,
                m->price,
                m->quantity,
                fix_side_desc(m->side),
                m->seq_num,
                m->timestamp,
                m->order_id[0] ? m->order_id : "-",
                m->exec_id[0] ? m->exec_id : "-",
                m->order_type ? fix_ordtype_desc(m->order_type) : "-",
                m->exchange[0] ? m->exchange : "-",
                m->open_interest,
                m->cci,
                m->atr,
                m->day_open,
                m->day_high,
                m->day_low,
                m->prev_close,
                m->high_52wk,
                m->low_52wk,
                m->avg_volume_10d,
                m->avg_volume_3m,
                m->market_cap,
                m->pe_ratio,
                m->eps
            );



        // -----------------------------
        // Phase 1 anomaly detection
        // -----------------------------
        int idx = hash_symbol(m->symbol);

        // Quick check: does symbol contain digits?


        if (!(is_valid_symbol(m->symbol))) {
            printf("\n\n\n[WARN !!!! OUCH ] Suspicious symbol='%s'\n\n\n", m->symbol);
        }
            
        //printf("\n[DEBUG] Raw FIX payload (full, len=%zu): %.*s\n", 
        //                pv->len, (int)pv->len, pv->data);   

        interval_counts[idx]++;

        // If first time seeing this symbol at idx, copy it
        if (symbol_table[idx][0] == '\0') {
            strncpy(symbol_table[idx], m->symbol, sizeof(symbol_table[idx]) - 1);
            symbol_table[idx][sizeof(symbol_table[idx]) - 1] = '\0';
        }
        

        if (!m->symbol[0]) continue;

        // Inter-arrival time
        prev_ts[idx] = m->timestamp;

        // Count protocol activity (but don’t check yet)
        fix_count[idx]++;

        // -----------------------------
        // Add to global view as usual
        // -----------------------------
        market_view_add(global_view, m);
    }

    analyze_futures_options(); // new function to update fno_symbol_t entries
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