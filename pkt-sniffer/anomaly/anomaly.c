// anomaly.c

#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include "anomaly.h"

#define MAX_SYMBOLS 1024

uint64_t prev_ts[MAX_SYMBOLS] = {0};
uint32_t fix_count[MAX_SYMBOLS] = {0};
uint32_t itch_count[MAX_SYMBOLS] = {0};
uint32_t sbe_count[MAX_SYMBOLS] = {0};
sliding_window_t burst_window[MAX_SYMBOLS] = {0};

uint32_t interval_counts[MAX_SYMBOLS] = {0};
anomaly_state_t anomaly_states[MAX_SYMBOLS] = {0};

char symbol_table[MAX_SYMBOLS][32] = {{0}};

int hash_symbol(const char *sym) {
    unsigned int h = 0;
    while (*sym) h = (h * 31 + *sym++) % MAX_SYMBOLS;
    return h;
}

void anomaly_detection(void) {

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t now_ms = ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;

    for (int i = 0; i < MAX_SYMBOLS; i++) {
        if (!symbol_table[i][0]) continue;  // skip unused slots

        anomaly_state_t *state = &anomaly_states[i];
        const char *sym = symbol_table[i];

        // -------- Protocol coverage --------
        if (fix_count[i] || itch_count[i] || sbe_count[i]) {
            check_protocol_coverage(fix_count[i], itch_count[i], sbe_count[i], 
                                    sym, i, state, now_ms);
        }

        // -------- Burst detection --------
        if (interval_counts[i] > 0) {
            record_burst(i, interval_counts[i]);     
            check_burst(&burst_window[i], sym, state, now_ms);
            interval_counts[i] = 0;  // reset for next interval
        }

        // -------- Delay detection --------
        check_inter_arrival(prev_ts[i], sym, i, now_ms, state);
    }

    // -------- Reset per-interval counters --------
    reset_counts_interval();
}
