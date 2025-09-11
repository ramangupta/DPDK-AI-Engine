// time_dpdk.c
#include <rte_cycles.h>
#include "tsc.h"

uint64_t now_tsc(void) {
    return rte_rdtsc();
}
