// tunnel_types.h
#pragma once
#include <stdint.h>

// ------------------------------
// Supported Tunnel Types
// ------------------------------
typedef enum {
    TUNNEL_NONE = 0,
    TUNNEL_GRE,
    TUNNEL_VXLAN,
    TUNNEL_GENEVE,
    // Future: IP-in-IP, L2TP, etc.
} tunnel_type_t;

// ------------------------------
// Generic Tunnel Info
// ------------------------------
typedef struct {
    tunnel_type_t type;       // Tunnel type
    uint16_t inner_proto;     // Inner protocol: IPv4=0x0800, IPv6=0x86DD, etc.

    // Optional metadata
    uint32_t vni;             // VXLAN/GENEVE VNI or GRE key
    uint16_t gre_flags;       // GRE flags (if GRE)
} tunnel_info;