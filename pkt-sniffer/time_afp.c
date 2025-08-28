// time_afp.c
#include "tsc.h"
#include <time.h>
#include <stdint.h>

uint64_t now_tsc(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    // Convert to nanoseconds (like a high-res tick counter)
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}
