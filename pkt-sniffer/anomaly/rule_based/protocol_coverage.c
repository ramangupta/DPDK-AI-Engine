#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "anomaly/anomaly.h"

typedef struct {
    int fix_active;
    int itch_active;
    int sbe_active;
} proto_state_t;

proto_state_t last_state[1024] = {0};

void reset_counts_interval() {
    for (int i = 0; i < 1024; i++) {
        fix_count[i] = 0;
        itch_count[i] = 0;
        sbe_count[i] = 0;
    }
}

void check_protocol_coverage(uint32_t fix, uint32_t itch, uint32_t sbe,
                             const char *symbol, int idx,
                             anomaly_state_t *state,
                             uint64_t now_ms)
{
    if (!state || !symbol || !symbol[0]) return;

    int fix_active  = fix  > 0;
    int itch_active = itch > 0;
    int sbe_active  = sbe  > 0;

    // Only alert if exactly two feeds are missing (all except active)
    if ((fix_active && !itch_active && !sbe_active) ||
        (itch_active && !fix_active && !sbe_active) ||
        (sbe_active && !fix_active && !itch_active)) {

        // Cooldown check to avoid repeated alerts
        uint64_t cooldown_ms = 5000; // 5 seconds
        if (now_ms - state->protocol_last_alert_ms >= cooldown_ms) {
            if (fix_active) {
                snprintf(state->protocol_alert_msg, sizeof(state->protocol_alert_msg),
                         "[ALERT] ITCH and SBE feeds missing for %s (FIX active)\n", symbol);
                // printf("[ALERT] ITCH and SBE feeds missing for %s (FIX active)\n", symbol);
            }
            else if (itch_active) {
                snprintf(state->protocol_alert_msg, sizeof(state->protocol_alert_msg),
                         "[ALERT] FIX and SBE feeds missing for %s (ITCH active)\n", symbol);
                // printf("[ALERT] FIX and SBE feeds missing for %s (ITCH active)\n", symbol);
            }
            else {
                snprintf(state->protocol_alert_msg, sizeof(state->protocol_alert_msg),
                         "[ALERT] FIX and ITCH feeds missing for %s (SBE active)\n", symbol);
                // printf("[ALERT] FIX and ITCH feeds missing for %s (SBE active)\n", symbol);
            }
            state->protocol_last_alert_ms = now_ms;
            strncpy(state->symbol, symbol, sizeof(state->symbol) - 1);
            state->symbol[sizeof(state->symbol) - 1] = '\0';  // ensure null termination
        }
    }

    // Update current feed states
    state->fix_missing  = fix_active;
    state->itch_missing = itch_active;
    state->sbe_missing  = sbe_active;
}



