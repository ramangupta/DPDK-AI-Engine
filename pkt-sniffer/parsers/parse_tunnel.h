/* GRE (Generic Routing Encapsulation)
 *
 * - RFC 2784.
 * - Encapsulates many Layer 3 protocols inside IP.
 * - Often used to build point-to-point VPNs.
 * - Can carry multicast and non-IP traffic.
 * - Can be combined with IPsec for security.
 */

// parse_tunnel.h
#pragma once

#include <stdint.h>
#include <stddef.h>

#include "tunnel_types.h"
#include "engine/capture.h"

// ------------------------------
// Generic Tunnel Parser API
// ------------------------------
// pkt: pointer to the start of the payload (after IP/UDP header)
// len: length of the payload
// l4_proto_hint: protocol hint from IPv4/IPv6 header (IPPROTO_GRE/IPPROTO_UDP)
// tinfo: output structure, populated if a tunnel is detected
// Returns: 1 if a tunnel was detected, 0 otherwise
int parse_tunnel(pkt_view *outer);

