#include <stdio.h>
#include <arpa/inet.h>
#include <rte_arp.h>
#include "parse_arp.h"
#include "stats.h"   // make sure it's included

void handle_arp(const pkt_view *pv)
{
    if (pv->len < sizeof(struct rte_arp_hdr)) {
        printf("      ARP <truncated>\n");
        return;
    }

    const struct rte_arp_hdr *arp = (const struct rte_arp_hdr *)pv->data;

    // Convert addresses safely
    char sip[INET_ADDRSTRLEN] = {0};
    char tip[INET_ADDRSTRLEN] = {0};
    if (!inet_ntop(AF_INET, &arp->arp_data.arp_sip, sip, sizeof(sip)))
        snprintf(sip, sizeof(sip), "?");
    if (!inet_ntop(AF_INET, &arp->arp_data.arp_tip, tip, sizeof(tip)))
        snprintf(tip, sizeof(tip), "?");

    // Convert MAC
    char mac[32];
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp->arp_data.arp_sha.addr_bytes[0],
             arp->arp_data.arp_sha.addr_bytes[1],
             arp->arp_data.arp_sha.addr_bytes[2],
             arp->arp_data.arp_sha.addr_bytes[3],
             arp->arp_data.arp_sha.addr_bytes[4],
             arp->arp_data.arp_sha.addr_bytes[5]);

    switch (ntohs(arp->arp_opcode)) {
    case RTE_ARP_OP_REQUEST:
        printf("      ARP request: who has %s? tell %s (%s)\n", tip, sip, mac);
        stats_record_arp(tip, NULL);   // record request
        break;
    case RTE_ARP_OP_REPLY:
        printf("      ARP reply: %s is at %s\n", sip, mac);
        stats_record_arp(sip, mac);    // record reply
        break;
    default:
        printf("      ARP opcode=%u (not supported)\n", ntohs(arp->arp_opcode));
        break;
    }
}

