// time_dpdk.c
#include "tsc.h"
#include <rte_cycles.h>

uint64_t now_tsc(void) {
    return rte_rdtsc();
}
