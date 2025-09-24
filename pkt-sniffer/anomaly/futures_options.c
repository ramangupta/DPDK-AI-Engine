// futures_options.c
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "uthash.h"
#include <inttypes.h>
#include "debug.h"
#include "parsers/market/parse_data.h"
#include "anomaly/futures_options.h"


// ------------------------------------------------------------------
// Symbol structure
// ------------------------------------------------------------------
typedef struct {
    const char *symbol;
    // add other fields as needed
    fno_symbol_t *fno; // pointer to original struct if needed
    UT_hash_handle hh;  // makes this struct hashable
} symbol_hash_t;

// ------------------------------------------------------------------
// Global hash table
// ------------------------------------------------------------------
static symbol_hash_t *symbol_table = NULL;

// ------------------------------------------------------------------
// Initialize hash table from FNO_SYMBOLS array
// ------------------------------------------------------------------
void init_symbol_table(void) {
    static bool initialized = false;
    if (initialized) return;

    for (size_t i = 0; i < FNO_SYMBOL_COUNT; i++) {
        symbol_hash_t *entry = malloc(sizeof(symbol_hash_t));
        entry->symbol = FNO_SYMBOLS[i].symbol;
        entry->fno = &FNO_SYMBOLS[i];
        HASH_ADD_KEYPTR(hh, symbol_table, entry->symbol, strlen(entry->symbol), entry);
    }

    initialized = true;
}

// ------------------------------------------------------------------
// Lookup by symbol
// ------------------------------------------------------------------
fno_symbol_t *fno_get_symbol(const char *symbol) {
    init_symbol_table();

    symbol_hash_t *entry = NULL;
    HASH_FIND_STR(symbol_table, symbol, entry);
    return entry ? entry->fno : NULL;
}

// Function to set remark
void fno_set_remark(const char *symbol, const char *remark_text) {
    if (!symbol || !remark_text) return;

    for (size_t i = 0; i < FNO_SYMBOL_COUNT; i++) {
        fno_symbol_t *fno = fno_get_symbol(symbol);
        if (strcmp(fno->symbol, symbol) == 0) {
            pthread_mutex_lock(&fno->lock);
            strncpy(fno->remark, remark_text, MAX_REMARK_LEN - 1);
            fno->remark[MAX_REMARK_LEN - 1] = '\0'; // ensure null-termination
            pthread_mutex_unlock(&fno->lock);
            break;
        }
    }
}

// ------------------------------------------------------------------
// Validate symbol
// ------------------------------------------------------------------
bool is_valid_symbol(const char *symbol) {
    return fno_get_symbol(symbol) != NULL;
}

void analyze_futures_options(void) {
    market_data_view *view = market_view_get();
    if (!view || !view->msgs) {
        fprintf(stderr, "[FnO] Market view not initialized\n");
        return;
    }

    printf("[FnO] Running analytics on %zu instruments\n", view->count);

    fno_set_remark("ABCAPITAL", "My lovely BHEL stock");
    for (size_t i = 0; i < view->count; i++) {
        market_msg_t *m = &view->msgs[i];

        if (!m->symbol[0]) continue;

        // Lookup corresponding fno_symbol
        fno_symbol_t *fno = fno_get_symbol(m->symbol);
        if (!fno) continue; // ignore unknown symbols

        pthread_mutex_lock(&fno->lock);

        // Populate fno_symbol fields from market_msg
        fno->current_price    = m->price;
        fno->day_open         = m->day_open;        // add these in market_msg_t if missing
        fno->day_high         = m->day_high;
        fno->day_low          = m->day_low;
        fno->prev_close       = m->prev_close;
        fno->high_52wk        = m->high_52wk;
        fno->low_52wk         = m->low_52wk;
        fno->avg_volume_10d   = m->avg_volume_10d;
        fno->avg_volume_3m    = m->avg_volume_3m;
        fno->market_cap       = m->market_cap;
        fno->pe_ratio         = m->pe_ratio;
        fno->eps              = m->eps;
        fno->cci              = m->cci;             // Commodity Channel Index
        fno->atr              = m->atr;             // Average True Range
        fno->vol[0]           = (double)m->day_volume; // today’s volume

        // Update derived values
        if (fno->support > 0.0) {
            fno->rs_diff_pct = (fno->current_price - fno->support) / fno->support * 100.0;
        } else {
            fno->rs_diff_pct = 0.0;
        }

        // Recompute state
        // Recompute state
        fno->state = FNO_STATE_UNDETERMINED;

        if (fno->resistance > 0) {
            if (fno->current_price >= fno->resistance * 0.98 &&
                fno->current_price <= fno->resistance * 1.02) {
                fno->state = FNO_STATE_AT_RESISTANCE;
            } else if (fno->current_price > fno->resistance * 1.02) {
                fno->state = FNO_STATE_BREAKOUT;
            }
        }

        if (fno->support > 0) {
            if (fno->current_price >= fno->support * 0.98 &&
                fno->current_price <= fno->support * 1.02) {
                fno->state = FNO_STATE_AT_SUPPORT;
            } else if (fno->current_price < fno->support * 0.98) {
                fno->state = FNO_STATE_BROKEN_SUPPORT;
            }
        }

        // If nothing matched, fallback
        if (fno->state == FNO_STATE_UNDETERMINED) {
            fno->state = FNO_STATE_RANGE_BOUND;
        }

        pthread_mutex_unlock(&fno->lock);

        // Example analytics / logging
        DEBUG_LOG(DBG_APP,
            "[FnO] %s | price=%.2f | day_open=%.2f | day_high=%.2f | day_low=%.2f | prev_close=%.2f\n"
            "      52wk_high=%.2f | 52wk_low=%.2f | OI=%" PRIu64 " | CCI=%d | ATR=%.2f | state=%d | RS%%=%.2f\n"
            "      vol_cur=%.0f | vol_1d=%.0f | vol_2d=%.0f | vol_3d=%.0f\n"
            "      avg_vol_10d=%.0f | avg_vol_3m=%.0f | market_cap=%.2f | PE=%.2f | EPS=%.2f\n",
            fno->symbol,
            fno->current_price,
            fno->day_open,
            fno->day_high,
            fno->day_low,
            fno->prev_close,
            fno->high_52wk,
            fno->low_52wk,
            m->open_interest,   // Assuming you still have `market_msg_t *m` in context
            fno->cci,
            fno->atr,
            fno->state,
            fno->rs_diff_pct,
            fno->vol[0], fno->vol[1], fno->vol[2], fno->vol[3],
            fno->avg_volume_10d,
            fno->avg_volume_3m,
            fno->market_cap,
            fno->pe_ratio,
            fno->eps
        );

    }
}


// ------------------------------------------------------------------
// Update volumes (shift last 3, add new current)
// ------------------------------------------------------------------


// Called once at end of trading day
// Internal: perform rollover
static void fno_rollover_day(void) {
    market_data_view *view = market_view_get();
    if (!view || !view->msgs) return;

    for (size_t i = 0; i < view->count; i++) {
        market_msg_t *m = &view->msgs[i];
        if (!m->symbol[0]) continue;

        fno_symbol_t *s = fno_get_symbol(m->symbol);
        if (!s) continue;

        pthread_mutex_lock(&s->lock);

        // shift past vols
        s->vol[3] = s->vol[2];
        s->vol[2] = s->vol[1];
        s->vol[1] = s->vol[0];

        // reset current day volume
        s->vol[0] = 0.0;

        printf("RAMAN : Volume rollover for %s: vol[1]=%.0f vol[2]=%.0f vol[3]=%.0f\n",
               s->symbol, s->vol[1], s->vol[2], s->vol[3]);
        pthread_mutex_unlock(&s->lock);
    }
}

// Track which day we last rolled
static int last_rollover_date = -1;

// Public hook called by stat_poll
void fno_check_rollover(void) {
    time_t now = time(NULL);
    struct tm *tm_now = localtime(&now);

    // Trigger only after market close: >= 15:30
    if (tm_now->tm_hour > 15 || (tm_now->tm_hour == 15 && tm_now->tm_min >= 30)) {
        // Run rollover only once per calendar day
        if (last_rollover_date != tm_now->tm_mday) {

            printf("[DEBUG] %02d:%02d: Rollover triggered for %04d-%02d-%02d\n",
                   tm_now->tm_hour, tm_now->tm_min,
                   tm_now->tm_year + 1900, tm_now->tm_mon + 1, tm_now->tm_mday);
            fno_rollover_day();
            last_rollover_date = tm_now->tm_mday;
        }
    }
}



