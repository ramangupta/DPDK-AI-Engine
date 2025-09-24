#include "parse_data.h"
#include "engine/capture.h"
#include "parsers/parse_eth.h"
#include "utils/debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "gen_main.h"
#include "stats/stats.h"
#include "tsc.h"

// Static sequence numbers
static uint32_t seq_num = 1;     // FIX application seq num

// --- Helpers ---
static double random_price(double min, double max) {
    return min + ((double)rand() / RAND_MAX) * (max - min);
}

static uint32_t random_qty(uint32_t min, uint32_t max) {
    return min + (rand() % (max - min + 1));
}

// Helper to compute FIX checksum (sum of all bytes modulo 256)
static int fix_compute_checksum(const char *buf, size_t len) {
    int sum = 0;
    for (size_t i = 0; i < len; i++) sum += (unsigned char)buf[i];
    return sum % 256;
}

// Generate a single FIX ExecutionReport message
int generate_fix_message(char *buf, size_t buf_size,
                         const char *symbol,
                         double price, uint32_t qty, char side,
                         const char *order_id,
                         const char *exec_id,
                         char order_type,
                         const char *exchange,
                         uint32_t oi, int cci) // <-- new fields
{
    char body[512];
    char header[64];
    char tmp[1024];

    static uint32_t seq_num = 1;   // internal counter
    // 1. Generate current UTC timestamp with milliseconds
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    char timestamp[32];
    snprintf(timestamp, sizeof(timestamp),
             "%04d%02d%02d-%02d:%02d:%02d.%03ld",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000);

    char safe_symbol[32];
    strncpy(safe_symbol, symbol, sizeof(safe_symbol) - 1);
    safe_symbol[sizeof(safe_symbol) - 1] = '\0';

    // 2. Build body (fields after 9=...)
    // 2. Build body (fields after 9=...)
    int body_len = snprintf(body, sizeof(body),
        "35=8%c"
        "52=%s%c"
        "55=%s%c"
        "44=%.2f%c"
        "38=%u%c"
        "54=%c%c"
        "34=%u%c"
        "37=%s%c"
        "17=%s%c"
        "40=%c%c"
        "207=%s%c"
        "1000=%u%c"   // OI
        "1001=%d%c",  // CCI
        FIX_SOH,
        timestamp, FIX_SOH,
        safe_symbol, FIX_SOH,
        price, FIX_SOH,
        qty, FIX_SOH,
        side, FIX_SOH,
        seq_num, FIX_SOH,
        order_id ? order_id : "ORD0", FIX_SOH,
        exec_id ? exec_id : "EXEC0", FIX_SOH,
        order_type ? order_type : '2', FIX_SOH,
        exchange ? exchange : "XNSE", FIX_SOH,
        oi, FIX_SOH,
        cci, FIX_SOH
    );

    if (body_len < 0 || body_len >= (int)sizeof(body)) return -1;

    for (int i = 0; i < body_len; i++) {
        putchar(body[i] == FIX_SOH ? '|' : body[i]);
    }
    putchar('\n');
    
    // 3. Header with exact BodyLength
    int hdr_len = snprintf(header, sizeof(header),
        "8=FIX.4.4%c9=%d%c",
        FIX_SOH, body_len, FIX_SOH
    );
    if (hdr_len < 0 || hdr_len >= (int)sizeof(header)) return -1;

    // 4. Concatenate header + body
    int msg_len = snprintf(tmp, sizeof(tmp), "%s%s", header, body);
    if (msg_len < 0 || msg_len >= (int)sizeof(tmp)) return -1;

    // 5. Compute checksum
    int checksum = fix_compute_checksum(tmp, msg_len);

    // 6. Final message into buf
    int total = snprintf(buf, buf_size, "%s10=%03d%c", tmp, checksum, FIX_SOH);
    if (total < 0 || total >= (int)buf_size) return -1;

    // 7. Debug
#if 0
    printf("RAW MSG HEX: ");
    for (int i = 0; i < total; i++) {
        printf("%02X ", (unsigned char)buf[i]);
    }
    printf("\n");
#endif
    // 8. Increment seq
    seq_num++;

    return total;
}



// Generate a stream of FIX messages
static size_t generate_fix_stream(uint8_t *buf, size_t buf_size,
                                  size_t num_msgs, const char *symbol) {
    size_t offset = 0;

    for (size_t i = 0; i < num_msgs; i++) {
        double price = random_price(100.0, 200.0);
        uint32_t qty = random_qty(50, 1000);
        char side = (rand() % 2) ? '1' : '2';   // FIX: 1=Buy, 2=Sell
        char order_type = '2';                  // default Limit order
        const char *exchange = "XNSE";          // hardcoded for now

        // Unique order + exec IDs
        char order_id[32], exec_id[32];
        snprintf(order_id, sizeof(order_id), "ORD%zu", i + 1);
        snprintf(exec_id, sizeof(exec_id), "EXEC%zu", i + 1);

        uint64_t oi = (rand() % 100000) + 50000;   // random OI
        int cci = (rand() % 200) - 100;            // random CCI, e.g., -100..+100

        int n = generate_fix_message((char *)(buf + offset),
                                     buf_size - offset,
                                     symbol,
                                     price,
                                     qty,
                                     side,
                                     order_id,
                                     exec_id,
                                     order_type,
                                     exchange, oi,
                                     cci);

        if (n <= 0 || offset + n >= buf_size) {
            break;  // buffer full or error
        }

        offset += n;
    }

    return offset;
}


// --- Public wrapper called from main ---
size_t generate_FIX(uint8_t *buf, size_t buf_size) {
    static FILE *fifo = NULL;
    if (!fifo) fifo = fopen("/tmp/fix_pipe", "rb");
    if (!fifo) return 0;

    size_t n = fread(buf, 1, buf_size, fifo);
    return n;
}
