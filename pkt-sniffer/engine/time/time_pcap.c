// time_pcap.c
#include <time.h>
#include "tsc.h"

uint64_t now_tsc(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec; // ns
}
