#pragma once
#include <stdint.h>
#include "capture.h"

struct bootp_hdr {
    uint8_t  op;       // Message op code / message type: 1 = BOOTREQUEST, 2 = BOOTREPLY
    uint8_t  htype;    // Hardware type
    uint8_t  hlen;     // Hardware address length
    uint8_t  hops;     // Hops
    uint32_t xid;      // Transaction ID
    uint16_t secs;     // Seconds elapsed
    uint16_t flags;    // Flags
    uint32_t ciaddr;   // Client IP address
    uint32_t yiaddr;   // 'Your' (client) IP address
    uint32_t siaddr;   // Server IP address
    uint32_t giaddr;   // Gateway IP address
    uint8_t  chaddr[16]; // Client hardware address
    uint8_t  sname[64];  // Optional server host name
    uint8_t  file[128];  // Boot file name
    uint32_t magic_cookie; // DHCP magic cookie: 0x63825363
    // Followed by DHCP options
} __attribute__((packed));

void handle_dhcp(pkt_view *pv);
