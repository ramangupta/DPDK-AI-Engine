#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "anomaly/anomaly.h"

void record_burst(int idx, uint32_t count) {
    sliding_window_t *w = &burst_window[idx];
    w->counts[w->idx] = count;              
    w->idx = (w->idx + 1) % BURST_WINDOW;  
}

void check_burst(sliding_window_t *w, const char *symbol, 
                 anomaly_state_t *state, uint64_t now_ms) 
{
    // Compute average over the sliding window
    double sum = 0;
    int valid = 0;
    for (int i = 0; i < BURST_WINDOW; i++) {
        if (w->counts[i] > 0) {
            sum += w->counts[i];
            valid++;
        }
    }
    double avg = (valid > 0) ? (sum / valid) : 0;

    // Get latest count
    uint32_t latest = w->counts[(w->idx + BURST_WINDOW - 1) % BURST_WINDOW];

    // Determine if this is a burst
    int is_burst = (latest > avg * BURST_FACTOR);

    // Consecutive intervals logic
    if (is_burst) {
        state->burst_consec++;
    } else {
        state->burst_consec = 0; // reset if not a burst
    }

    // Fire alert only if consecutive requirement met and cooldown passed
    if (state->burst_consec >= BURST_CONSEC_REQUIRED) {
        uint64_t cooldown_ms = BURST_COOLDOWN * 1000ULL;
        if (now_ms - state->last_burst_ms >= cooldown_ms) {
            snprintf(state->burst_alert_msg, sizeof(state->burst_alert_msg),
                     "[ALERT] Burst detected for %s: %u msgs/sec (avg %.2f)\n",
                    symbol, latest, avg);
            printf("[ALERT] Burst detected for %s: %u msgs/sec (avg %.2f)\n",
                   symbol, latest, avg);
            strncpy(state->symbol, symbol, sizeof(state->symbol) - 1);
            state->symbol[sizeof(state->symbol) - 1] = '\0';  // ensure null termination

            state->last_burst_ms = now_ms;
            state->burst_consec = 0; // reset after alert
        }
    }

    // Update exponential moving average (optional)
    w->avg = 0.8 * w->avg + 0.2 * latest;
}


