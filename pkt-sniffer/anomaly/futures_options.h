#ifndef FUTURES_OPTIONS_H
#define FUTURES_OPTIONS_H

#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdint.h>

#define MAX_REMARK_LEN 512
// ------------------------------------------------------------------
// Per-symbol F&O structure
// ------------------------------------------------------------------
typedef enum {
    FNO_STATE_AT_RESISTANCE,
    FNO_STATE_AT_SUPPORT,
    FNO_STATE_BREAKOUT,
    FNO_STATE_BROKEN_SUPPORT,
    FNO_STATE_RANGE_BOUND,
    FNO_STATE_UNDETERMINED
} fno_state_t;

typedef enum {
    FNO_CATEGORY_INDEX,
    FNO_CATEGORY_AUTO_SECTOR,
    FNO_CATEGORY_CAPITAL_GOODS,
    FNO_CATEGORY_CHEMICALS,
    FNO_CATEGORY_CONSTRUCTION,
    FNO_CATEGORY_CONSTRUCTION_MATERIALS,
    FNO_CATEGORY_CONSUMER_DURABLES,
    FNO_CATEGORY_CONSUMER_SERVICES,
    FNO_CATEGORY_FMCG, 
    FNO_CATEGORY_PRIVATE_BANKING,
    FNO_CATEGORY_PUBLIC_BANKING,
    FNO_CATEGORY_FINANCIAL_SERVICES,
    FNO_CATEGORY_HEALTHCARE,
    FNO_CATEGORY_IT,
    FNO_CATEGORY_METALS_AND_MINING,
    FNO_CATEGORY_OIL_AND_GAS,
    FNO_CATEGORY_POWER,
    FNO_CATEGORY_REALTY,
    FNO_CATEGORY_SERVICES,
    FNO_CATEGORY_TELECOM,
    FNO_CATEGORY_TEXTILES,
    FNO_CATEGORY_MAX
} fno_category_t;

typedef struct {
    char symbol[32];
    pthread_mutex_t lock;

    // user input
    double support;
    double resistance;

    fno_category_t category;
    // from feed / API
    double current_price;
    double vol[4];       // [0] = current, [1-3] = past 3 days
    double high_52wk;
    double low_52wk;
    int cci;            // Commodity Channel Index
    float atr;       // Average True Range
    // derived
    fno_state_t state;
    double rs_diff_pct;  // (res-support)/support * 100

    double day_open;
    double day_high;
    double day_low;
    double prev_close;
    double avg_volume_10d;
    double avg_volume_3m;
    double market_cap;
    double pe_ratio;
    double eps;

    char remark[MAX_REMARK_LEN]; 
} fno_symbol_t;

// ------------------------------------------------------------------
// Global F&O mapping (implemented in fno_data.c)
// ------------------------------------------------------------------
extern fno_symbol_t FNO_SYMBOLS[];
extern const size_t FNO_SYMBOL_COUNT;

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------
bool is_valid_symbol(const char *symbol);
fno_symbol_t *fno_get_symbol(const char *symbol);
void analyze_futures_options(void);
void fno_update_volume(const char *symbol, double today_vol);
void fno_check_rollover(void);

#endif // FUTURES_OPTIONS_H
