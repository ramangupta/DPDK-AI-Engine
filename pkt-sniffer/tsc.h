// time.h
#pragma once
#include <stdint.h>

// Always returns "monotonic ticks"
uint64_t now_tsc(void);
