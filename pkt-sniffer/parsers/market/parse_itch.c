// parse_itch.c
#include "parse_data.h"
#include "sniffer_proto.h"
#include "engine/capture.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


void parse_itch_message(const uint8_t *buf, size_t len, market_data_view *mdv) {
    if (len == 0) return;

    char tmp[1024];
    if (len >= sizeof(tmp)) len = sizeof(tmp) - 1;
    memcpy(tmp, buf, len);
    tmp[len] = '\0';

    char *saveptr;
    char *line = strtok_r(tmp, "\n", &saveptr);
    while (line) {
        market_msg_t msg = {0};
        strncpy(msg.protocol, "ITCH", sizeof(msg.protocol)-1);

        char *tok;
        char *inner_save;

        // "ITCH"
        tok = strtok_r(line, "|", &inner_save);
        if (!tok) { line = strtok_r(NULL, "\n", &saveptr); continue; }

        // symbol
        tok = strtok_r(NULL, "|", &inner_save);
        if (tok) strncpy(msg.symbol, tok, sizeof(msg.symbol)-1);

        // msg_type (QUOTE / TRADE)
        tok = strtok_r(NULL, "|", &inner_save);
        if (tok) strncpy(msg.type, tok, sizeof(msg.type)-1);

        // price
        tok = strtok_r(NULL, "|", &inner_save);
        if (tok) msg.price = strtod(tok, NULL);

        // qty
        tok = strtok_r(NULL, "|", &inner_save);
        if (tok) msg.quantity = (uint32_t)atoi(tok);

        // side (1=Buy,2=Sell)
        tok = strtok_r(NULL, "|", &inner_save);
        if (tok) msg.side = tok[0];

        // seq_num: "SEQ=123"
        tok = strtok_r(NULL, "|", &inner_save);
        if (tok && strncmp(tok, "SEQ=", 4) == 0)
            msg.seq_num = (uint32_t)atoi(tok+4);

        // order_id
        tok = strtok_r(NULL, "|", &inner_save);
        if (tok) strncpy(msg.order_id, tok, sizeof(msg.order_id)-1);

        // exec_id
        tok = strtok_r(NULL, "|", &inner_save);
        if (tok) strncpy(msg.exec_id, tok, sizeof(msg.exec_id)-1);

        // order_type: "40=X"
        tok = strtok_r(NULL, "|", &inner_save);
        if (tok && strncmp(tok, "40=", 3) == 0)
            msg.order_type = tok[3];

        // exchange: "207=XXX"
        tok = strtok_r(NULL, "|", &inner_save);
        if (tok && strncmp(tok, "207=", 4) == 0)
            strncpy(msg.exchange, tok+4, sizeof(msg.exchange)-1);

        // timestamp: "TS=sec.ms"
        tok = strtok_r(NULL, "|", &inner_save);
        if (tok && strncmp(tok, "TS=", 3) == 0) {
            long sec=0, ms=0;
            sscanf(tok+3, "%ld.%ld", &sec, &ms);
            msg.timestamp = (uint64_t)sec * 1000 + (uint64_t)ms;
        } else {
            msg.timestamp = (uint64_t)time(NULL) * 1000; // fallback
        }

        // Add to mdv
        if (mdv->count < mdv->capacity) {
            mdv->msgs[mdv->count++] = msg;
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }
}

void parse_itch(pkt_view *pv) {
    PARSER_LOG_LAYER("ITCH", COLOR_APP,
        "ITCH payload: len=%u | src=%s:%u -> dst=%s:%u\n",
        pv->len, pv->src_ip, pv->src_port, pv->dst_ip, pv->dst_port);

    if (pv->len == 0) return;

    market_data_view mdv = {0};
    mdv.capacity = 128;
    mdv.msgs = calloc(mdv.capacity, sizeof(market_msg_t));
    if (!mdv.msgs) return;

    parse_itch_message(pv->data, pv->len, &mdv);

    DEBUG_LOG(DBG_APP, "ITCH parsed %zu msgs\n", mdv.count);

    // add to global view
    market_data_view *global_view = market_view_get();
    for (size_t i = 0; i < mdv.count; i++) {
        market_view_add(global_view, &mdv.msgs[i]);
    }

    free(mdv.msgs);
}
