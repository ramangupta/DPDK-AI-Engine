/*
 * DHCP sits on top of UDP with client port as 68 and server port as 67
 *
 * handle_dhcp() basics
 * DHCP starts with the BOOTP header (fixed 236 bytes) followed by options. 
 * At minimum, you can print:
 *      op (1=request, 2=reply)
 *      xid (transaction id)
 *      yiaddr (your IP address)
 *      siaddr (server IP)
 *      first option(s): Message Type 
 *              (DHCPDISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE, INFORM)
 * Options parsing
 *      Look for magic_cookie == 0x63825363.
 *      Then parse TLV options until 0xff (end).
 *      Option 53 = DHCP Message Type.
 */
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "parse_dhcp.h"
#include <string.h>
#include "stats.h"

static void print_ip(const char *label, const uint8_t *ip) {
    PARSER_LOG_LAYER("DHCP", COLOR_DHCP, "        %s %u.%u.%u.%u\n", label, ip[0], ip[1], ip[2], ip[3]);
}

static void print_ip_list(const char *label, const uint8_t *v, uint8_t len) {
    PARSER_LOG_LAYER("DHCP", COLOR_DHCP, "        %s ", label);
    for (int i=0; i<len; i+=4) {
        PARSER_LOG_LAYER("DHCP", COLOR_DHCP, "%u.%u.%u.%u", v[i], v[i+1], v[i+2], v[i+3]);
        if (i+4 < len) printf(", ");
    }
    printf("\n");
}


static inline void parse_dhcp_options(const uint8_t *opt, size_t len) {
    const uint8_t *end = opt + len;

    while (opt < end) {
        uint8_t code = *opt++;
        if (code == 0xFF) break;   // End
        if (code == 0x00) continue; // Pad

        if (opt >= end) break;
        uint8_t optlen = *opt++;
        if (opt + optlen > end) break;

        switch (code) {
        case 53: { // DHCP Message Type
            const char *mt = "UNKNOWN";
            if (opt[0] == 1) mt = "DISCOVER";
            else if (opt[0] == 2) mt = "OFFER";
            else if (opt[0] == 3) mt = "REQUEST";
            else if (opt[0] == 4) mt = "DECLINE";
            else if (opt[0] == 5) mt = "ACK";
            else if (opt[0] == 6) mt = "NAK";
            else if (opt[0] == 7) mt = "RELEASE";
            else if (opt[0] == 8) mt = "INFORM";
            printf("      type=%s\n", mt);
            break;
        }
        case 1: // Subnet Mask
            print_ip("subnet_mask", opt);
            break;
        case 3: // Router
            print_ip_list("router", opt, optlen);
            break;
        case 6: // DNS servers
            print_ip_list("dns", opt, optlen);
            break;
        case 51: { // Lease time
            uint32_t lease = ntohl(*(uint32_t*)opt);
            PARSER_LOG_LAYER("DHCP", COLOR_DHCP, "        lease_time %u s\n", lease);
            break;
        }
        case 58: { // Renewal time (T1)
            uint32_t t1 = ntohl(*(uint32_t*)opt);
            PARSER_LOG_LAYER("DHCP", COLOR_DHCP, "        renewal_time %u s\n", t1);
            break;
        }
        case 59: { // Rebinding time (T2)
            uint32_t t2 = ntohl(*(uint32_t*)opt);
            PARSER_LOG_LAYER("DHCP", COLOR_DHCP, "        rebinding_time %u s\n", t2);
            break;
        }
        case 54: // Server identifier
            print_ip("server_id", opt);
            break;
        case 12: // Hostname
            PARSER_LOG_LAYER("DHCP", COLOR_DHCP, "        hostname %.*s\n", optlen, (const char*)opt);
            break;
        default:
            // Uncomment if you want to see all options
            // printf("        option %u (len=%u)\n", code, optlen);
            break;
        }
        opt += optlen;
    }
}

void handle_dhcp(pkt_view *pv) {
    if (pv->len < sizeof(struct bootp_hdr)) {
        DEBUG_LOG(DBG_DHCP, "    DHCP <truncated>");
        global_stats.drop_invalid_ipv4++;
        global_stats.dropped++;
        return;
    }

    const struct bootp_hdr *bp = (const struct bootp_hdr *)pv->data;
    uint16_t hdr_len = sizeof(struct bootp_hdr);

    const char *msgtype = "UNKNOWN";   // <-- declare here at top level

    PARSER_LOG_LAYER("DHCP", COLOR_DHCP, "    DHCP xid=0x%x op=%u (%s)",
           ntohl(bp->xid),
           bp->op,
           (bp->op == 1) ? "REQUEST" : (bp->op == 2 ? "REPLY" : "UNKNOWN"));

    if (bp->yiaddr) {
        PARSER_LOG_LAYER("DHCP", COLOR_DHCP, "        yiaddr %s", inet_ntoa(*(struct in_addr*)&bp->yiaddr));
    }

    // DHCP options
    if (pv->len > hdr_len) {
        const uint8_t *opt = (const uint8_t *)bp + hdr_len;
        const uint8_t *end = (const uint8_t *)bp + pv->len;

        if (ntohl(bp->magic_cookie) == 0x63825363) {
            while (opt < end) {
                uint8_t code = *opt++;
                if (code == 0xFF) break;    // END option
                if (code == 0x00) continue; // PAD option
                if (opt >= end) break;

                uint8_t len = *opt++;
                if (opt + len > end) break;

                switch (code) {
                    case 53: // DHCP Message Type
                        if (len == 1) {
                            switch (*opt) {
                                case 1: msgtype = "DISCOVER"; break;
                                case 2: msgtype = "OFFER";    break;
                                case 3: msgtype = "REQUEST";  break;
                                case 4: msgtype = "DECLINE";  break;
                                case 5: msgtype = "ACK";      break;
                                case 6: msgtype = "NAK";      break;
                                case 7: msgtype = "RELEASE";  break;
                                case 8: msgtype = "INFORM";   break;
                            }
                        }
                        PARSER_LOG_LAYER("DHCP", COLOR_DHCP, "      type=%s", msgtype);
                        break;

                    case 50: // Requested IP
                        if (len == 4) {
                            PARSER_LOG_LAYER("DHCP", COLOR_DHCP, "      requested_ip=%s",
                                   inet_ntoa(*(struct in_addr*)opt));
                        }
                        break;
                    case 54: // Server Identifier
                        if (len == 4) {
                            PARSER_LOG_LAYER("DHCP", COLOR_DHCP, "      server_id=%s",
                                   inet_ntoa(*(struct in_addr*)opt));
                        }
                        break;
                    case 51: // Lease Time
                        if (len == 4) {
                            uint32_t t;
                            memcpy(&t, opt, 4);
                            PARSER_LOG_LAYER("DHCP", COLOR_DHCP, "      lease_time=%u sec", ntohl(t));
                        }
                        break;
                    case 1: // Subnet Mask
                        if (len == 4) {
                            PARSER_LOG_LAYER("DHCP", COLOR_DHCP, "      subnet_mask=%s",
                                   inet_ntoa(*(struct in_addr*)opt));
                        }
                        break;
                    case 3: // Router
                        if (len % 4 == 0) {
                            for (int i = 0; i < len; i += 4) {
                                PARSER_LOG_LAYER("DHCP", COLOR_DHCP, "      router=%s",
                                       inet_ntoa(*(struct in_addr*)(opt + i)));
                            }
                        }
                        break;
                    case 6: // DNS servers
                        if (len % 4 == 0) {
                            for (int i = 0; i < len; i += 4) {
                                PARSER_LOG_LAYER("DHCP", COLOR_DHCP, "      dns=%s",
                                       inet_ntoa(*(struct in_addr*)(opt + i)));
                            }
                        }
                        break;
                }
                opt += len;
            }
        }
    }

    // record stats
    stats_record_dhcp(ntohl(bp->xid), msgtype,
                      inet_ntoa(*(struct in_addr*)&bp->yiaddr));
}

