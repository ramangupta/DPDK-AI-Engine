#ifndef PARSE_L4_H
#define PARSE_L4_H

#include <stdint.h>
#include "capture.h"

void parse_l4(pkt_view *pv, uint8_t proto);

#endif
