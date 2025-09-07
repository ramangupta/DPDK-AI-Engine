#include <stdio.h>
#include <arpa/inet.h>
#include <rte_arp.h>
#include "parse_arp.h"
#include "stats.h"   // make sure it's included

void handle_arp(pkt_view *pv_full, const pkt_view *pv_slice)
{
    if (pv_slice->len < sizeof(struct rte_arp_hdr)) {
        DEBUG_LOG(DBG_ARP, "      ARP <truncated>\n");
        return;
    }

    const struct rte_arp_hdr *arp = (const struct rte_arp_hdr *)pv_slice->data;

    // Convert addresses safely
    char sip[INET_ADDRSTRLEN] = {0};
    char tip[INET_ADDRSTRLEN] = {0};
    if (!inet_ntop(AF_INET, &arp->arp_data.arp_sip, sip, sizeof(sip)))
        snprintf(sip, sizeof(sip), "?");
    if (!inet_ntop(AF_INET, &arp->arp_data.arp_tip, tip, sizeof(tip)))
        snprintf(tip, sizeof(tip), "?");

    if (!inet_ntop(AF_INET, &arp->arp_data.arp_sip, pv_full->src_ip, sizeof(pv_full->src_ip)))
        snprintf(pv_full->src_ip, sizeof(pv_full->src_ip), "?");
    if (!inet_ntop(AF_INET, &arp->arp_data.arp_tip, pv_full->dst_ip, sizeof(pv_full->dst_ip)))
        snprintf(pv_full->dst_ip, sizeof(pv_full->dst_ip), "?");

    // Convert MAC
    char mac[32];
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp->arp_data.arp_sha.addr_bytes[0],
             arp->arp_data.arp_sha.addr_bytes[1],
             arp->arp_data.arp_sha.addr_bytes[2],
             arp->arp_data.arp_sha.addr_bytes[3],
             arp->arp_data.arp_sha.addr_bytes[4],
             arp->arp_data.arp_sha.addr_bytes[5]);

    snprintf(pv_full->src_mac, sizeof(pv_full->src_mac),
                 "%02x:%02x:%02x:%02x:%02x:%02x",
                 arp->arp_data.arp_sha.addr_bytes[0],
                 arp->arp_data.arp_sha.addr_bytes[1],
                 arp->arp_data.arp_sha.addr_bytes[2],
                 arp->arp_data.arp_sha.addr_bytes[3],
                 arp->arp_data.arp_sha.addr_bytes[4],
                 arp->arp_data.arp_sha.addr_bytes[5]);

    snprintf(pv_full->dst_mac, sizeof(pv_full->dst_mac),
                 "%02x:%02x:%02x:%02x:%02x:%02x",
                 arp->arp_data.arp_tha.addr_bytes[0],
                 arp->arp_data.arp_tha.addr_bytes[1],
                 arp->arp_data.arp_tha.addr_bytes[2],
                 arp->arp_data.arp_tha.addr_bytes[3],
                 arp->arp_data.arp_tha.addr_bytes[4],
                 arp->arp_data.arp_tha.addr_bytes[5]);

    switch (ntohs(arp->arp_opcode)) {
    case RTE_ARP_OP_REQUEST:
        PARSER_LOG_LAYER("ARP", COLOR_ARP, "      ARP request: who has %s? tell %s (%s)\n", tip, sip, mac);
        stats_record_arp(tip, NULL);   // record request
        break;
    case RTE_ARP_OP_REPLY:
        PARSER_LOG_LAYER("ARP", COLOR_ARP, "      ARP reply: %s is at %s\n", sip, mac);
        stats_record_arp(sip, mac);    // record reply
        break;
    default:
        PARSER_LOG_LAYER("ARP", COLOR_ARP, "      ARP opcode=%u (not supported)\n", ntohs(arp->arp_opcode));
        break;
    }
}

