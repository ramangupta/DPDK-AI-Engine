#ifndef ANOMALY_H
#define ANOMALY_H

#include <stdint.h>

#define MAX_SYMBOLS 1024
#define INTER_ARRIVAL_THRESHOLD_MS 100  // adjust per symbol
#define BURST_FACTOR     1.5        // how many times above average
#define BURST_WINDOW     10       // seconds in sliding window
#define BURST_DEBOUNCE   2        // must persist for N intervals
#define BURST_MIN_RATE   10       // msgs/sec minimum before alerting
#define BURST_CONSEC_REQUIRED  2    // number of consecutive intervals before triggering burst alert
#define BURST_COOLDOWN         5    // cooldown in seconds between alerts

#define DELAY_THRESHOLD_WARN   500   // ms
#define DELAY_THRESHOLD_ALERT 1000   // ms
#define DELAY_THRESHOLD_CRIT  2000   // ms
#define DELAY_CONSEC_REQUIRED    3   // require this many consecutive intervals
#define DELAY_COOLDOWN          10   // seconds cooldown between alerts for same severity

#define DELAY_NONE  0
#define DELAY_WARN  1
#define DELAY_ALERT 2
#define DELAY_CRIT  3

typedef struct {
    uint32_t counts[BURST_WINDOW];
    int idx;
    double avg;          // exponential moving average
    int consecutive;     // for debounce
} sliding_window_t;

typedef struct {

    char symbol[32];   // <-- add this
    
    // ----- Protocol coverage -----
    int fix_missing;     // consecutive intervals FIX missing
    int itch_missing;    // consecutive intervals ITCH missing
    int sbe_missing;     // consecutive intervals SBE missing
    uint64_t protocol_last_alert_ms;
    char protocol_alert_msg[128];

    // ----- Burst detection -----
    int burst_consec;    // consecutive intervals over threshold
    uint64_t last_burst_ms;  // last alert timestamp (ms) for cooldown
    char burst_alert_msg[128];

    // ----- Delay detection -----
    int delay_consec;        // consecutive intervals of observed delay
    int delay_state;         // last reported severity (DELAY_NONE..DELAY_CRIT)
    uint64_t delay_last_alert_ms; // last alert timestamp for cooldown
    char delay_alert_msg[128];
} anomaly_state_t;

extern anomaly_state_t anomaly_states[MAX_SYMBOLS];

int hash_symbol(const char *sym);

// ---------- Inter-arrival ----------
void check_inter_arrival(uint64_t prev_ts_ms,
                         const char *symbol,
                         int idx,
                         uint64_t now_ms,
                         anomaly_state_t *state);

// ---------- Burst detection ----------

void record_burst(int idx, uint32_t count);

void check_burst(sliding_window_t *w, const char *symbol, 
                 anomaly_state_t *state, uint64_t now_ms);

// ---------- Protocol coverage ----------
void check_protocol_coverage(uint32_t fix, uint32_t itch, uint32_t sbe,
                             const char *symbol, int idx,
                             anomaly_state_t *state,
                             uint64_t now_ms);

void reset_counts_interval(void);

void anomaly_detection(void);

extern uint64_t prev_ts[MAX_SYMBOLS];
extern sliding_window_t burst_window[MAX_SYMBOLS];
extern uint32_t fix_count[MAX_SYMBOLS];
extern uint32_t itch_count[MAX_SYMBOLS];
extern uint32_t sbe_count[MAX_SYMBOLS];
extern char symbol_table[MAX_SYMBOLS][32]; 
extern uint32_t interval_counts[MAX_SYMBOLS];
#endif // ANOMALY_H
