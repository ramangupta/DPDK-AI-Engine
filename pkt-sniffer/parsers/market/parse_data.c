#include "parse_data.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>

#define MARKET_VIEW_MAX 1024

static market_data_view g_market_view = {0};

#if 0
bool is_valid_symbol(const char *s) {
    if (!s || !*s) return false;
    for (const char *p = s; *p; p++) {
        if (isdigit(*p) || (*p == '.') || (*p == '-')) 
            return false;
    }
    return true;
}
#endif

void market_view_init(void)
{
    g_market_view.capacity = MARKET_VIEW_MAX;
    g_market_view.count = 0;
    g_market_view.msgs = calloc(g_market_view.capacity, sizeof(market_msg_t));
    if (!g_market_view.msgs) {
        fprintf(stderr, "[ERROR] Failed to allocate market view\n");
        g_market_view.capacity = 0;
    }
}

void market_view_add(market_data_view *view, market_msg_t *msg)
{
    if (!view || !msg || !view->msgs) return;

    if (msg->symbol[0] == '\0' || strlen(msg->symbol) >= sizeof(msg->symbol))
        return;

    if (!(msg->price)) {
        fprintf(stderr, "WARN: Skipping suspicious symbol='%s'\n", msg->symbol);
        fprintf(stderr, "[DEBUG] Raw FIX when symbol invalid: %s\n", msg);
        return;
    }

    // Update existing symbol if exists
    for (size_t i = 0; i < view->count; i++) {

        if (strcmp(view->msgs[i].symbol, msg->symbol) == 0) {
            memcpy(&view->msgs[i], msg, sizeof(market_msg_t));
            // force symbol null-termination (safety)
            view->msgs[i].symbol[sizeof(view->msgs[i].symbol) - 1] = '\0';
            return;
        }
    }

    // Append / overwrite
    size_t idx = (view->count >= view->capacity)
                 ? (view->count % view->capacity)
                 : view->count++;

    memcpy(&view->msgs[idx], msg, sizeof(market_msg_t));
    view->msgs[idx].symbol[sizeof(view->msgs[idx].symbol) - 1] = '\0';
}

market_data_view *market_view_get(void)
{
    return &g_market_view;
}
