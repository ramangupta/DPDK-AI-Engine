#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include "anomaly/anomaly.h"

static const char *delay_sev_str(int s) {
    switch (s) {
    case DELAY_WARN:  return "WARN";
    case DELAY_ALERT: return "ALERT";
    case DELAY_CRIT:  return "CRITICAL";
    default:          return "NONE";
    }
}

// prev_ts_ms: last seen timestamp for symbol, in milliseconds since epoch
// now_ms:     now time in milliseconds (compute in stats_poll and pass here)
// idx:        symbol index into delay_state[] / symbol_table[]
void check_inter_arrival(uint64_t prev_ts_ms,
                         const char *symbol,
                         int idx,
                         uint64_t now_ms,
                         anomaly_state_t *state)
{
    if (prev_ts_ms == 0 || !symbol || !symbol[0] || !state) return;

    uint64_t delta_ms = (now_ms > prev_ts_ms) ? (now_ms - prev_ts_ms) : 0;

    // Determine current observed severity
    int obs_sev = DELAY_NONE;
    if (delta_ms >= DELAY_THRESHOLD_CRIT)  obs_sev = DELAY_CRIT;
    else if (delta_ms >= DELAY_THRESHOLD_ALERT) obs_sev = DELAY_ALERT;
    else if (delta_ms >= DELAY_THRESHOLD_WARN)  obs_sev = DELAY_WARN;

    // -------- Recovery --------
    if (obs_sev == DELAY_NONE) {
        if (state->delay_state != DELAY_NONE) {
            //printf("[RECOVERED] %s delay recovered (was %s)\n",
              //     symbol, delay_sev_str(state->delay_state));
            state->delay_state = DELAY_NONE;
        }
        state->delay_consec = 0;
        return;
    }

    // -------- Escalation --------
    if (obs_sev > state->delay_state) {
        uint64_t cooldown_ms = ((uint64_t)DELAY_COOLDOWN) * 1000ULL;
        if (now_ms - state->delay_last_alert_ms >= cooldown_ms) {
            snprintf(state->delay_alert_msg, sizeof(state->delay_alert_msg),
                     "[%s] Escalation for %s: %" PRIu64 " ms\n",
                     delay_sev_str(obs_sev), symbol, delta_ms);
            //printf("[%s] Escalation for %s: %" PRIu64 " ms\n",
              //     delay_sev_str(obs_sev), symbol, delta_ms);

            strncpy(state->symbol, symbol, sizeof(state->symbol) - 1);
            state->symbol[sizeof(state->symbol) - 1] = '\0';  // ensure null termination

            state->delay_state = obs_sev;
            state->delay_last_alert_ms = now_ms;
        }
        state->delay_consec = 0;  // keep stable until downgrade
        return;
    }

    // -------- Stability streak --------
    if (obs_sev == state->delay_state) {
        state->delay_consec++;
    } else {
        state->delay_consec = 1;
    }

    // -------- Downgrade after consecutive intervals + cooldown --------
    if (obs_sev < state->delay_state && state->delay_consec >= DELAY_CONSEC_REQUIRED) {
        uint64_t cooldown_ms = ((uint64_t)DELAY_COOLDOWN) * 1000ULL;
        if (now_ms - state->delay_last_alert_ms >= cooldown_ms) {
            printf("[%s] Downgrade for %s: %" PRIu64 " ms\n",
                   delay_sev_str(obs_sev), symbol, delta_ms);
            state->delay_state = obs_sev;
            state->delay_last_alert_ms = now_ms;
            state->delay_consec = 0;
        }
    }
}
