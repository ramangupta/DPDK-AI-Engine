// talkers.h
#ifndef TALKERS_H
#define TALKERS_H

#include "capture.h"

#define MAX_TALKERS 1024
#define TOP_N 5

enum sort_mode {
    SORT_BY_PKTS,
    SORT_BY_BYTES
};

void talkers_update(const pkt_view *pv);
void talkers_report(void);
void talkers_reset(void);

// Expose sort mode (default = pkts)
extern enum sort_mode talkers_sort_mode;

#endif
