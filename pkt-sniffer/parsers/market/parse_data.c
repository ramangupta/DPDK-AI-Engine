#include "parse_data.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MARKET_VIEW_MAX 1024

static market_data_view g_market_view = {0};

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

    if (view->count >= view->capacity) {
        // Optional: circular buffer
        size_t idx = view->count % view->capacity;
        memcpy(&view->msgs[idx], msg, sizeof(market_msg_t));
        view->count = view->capacity; // cap it
    } else {
        memcpy(&view->msgs[view->count], msg, sizeof(market_msg_t));
        view->count++;
    }
}

market_data_view *market_view_get(void)
{
    return &g_market_view;
}
