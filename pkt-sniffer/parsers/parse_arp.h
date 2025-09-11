#pragma once
#include "engine/capture.h"   // for pkt_view

void handle_arp(pkt_view *pv_full, const pkt_view *pv_slice);
