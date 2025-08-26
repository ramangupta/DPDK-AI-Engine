#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>

#define RX_RING_SIZE     256
#define NUM_MBUFS        8191
#define MBUF_CACHE_SIZE  250
#define BURST_SIZE       64

static volatile int keep_running = 1;

static void handle_sigint(int sig) { (void)sig; keep_running = 0; }

static inline void print_mac(const uint8_t *m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void hexdump_line(const uint8_t *p, uint16_t len, uint16_t max_bytes) {
    if (len > max_bytes) len = max_bytes;
    for (uint16_t i = 0; i < len; i++) {
        printf("%02x%s", p[i], ((i+1) % 16) ? " " : "\n");
    }
    if (len % 16) puts("");
}

struct eth_hdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ether_type; /* big endian */
} __attribute__((__packed__));

struct ipv4_hdr_s {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t hdr_checksum;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((__packed__));

struct ipv6_hdr_s {
    uint32_t ver_tc_fl;
    uint16_t payload_len;
    uint8_t  next_hdr;
    uint8_t  hop_limit;
    uint8_t  saddr[16];
    uint8_t  daddr[16];
} __attribute__((__packed__));

static void print_ipv4(uint32_t a) {
    const uint8_t *b = (const uint8_t *)&a;
    printf("%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static void print_ipv6(const uint8_t a[16]) {
    // minimal compact print (no full RFC 5952 compression)
    for (int i=0;i<16;i+=2) {
        uint16_t w = ((uint16_t)a[i] << 8) | a[i+1];
        printf("%x", w);
        if (i<14) printf(":");
    }
}

int main(int argc, char **argv) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");

    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) rte_exit(EXIT_FAILURE, "No Ethernet ports\n");
    uint16_t port_id = 0;

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) rte_exit(EXIT_FAILURE, "mempool create failed\n");

    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));

    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret < 0) rte_exit(EXIT_FAILURE, "dev_configure failed: %d\n", ret);

    ret = rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE,
                                 rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
    if (ret < 0) rte_exit(EXIT_FAILURE, "rx_queue_setup failed: %d\n", ret);

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) rte_exit(EXIT_FAILURE, "dev_start failed: %d\n", ret);

    printf("Sniffing on DPDK port %u ... Ctrl+C to stop\n", port_id);
    signal(SIGINT, handle_sigint);

    uint64_t pkts_total = 0, bytes_total = 0;
    uint64_t last_tsc = rte_get_tsc_cycles();
    const uint64_t hz = rte_get_tsc_hz();

    struct rte_mbuf *bufs[BURST_SIZE];

    while (keep_running) {
        const uint16_t n = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);
        if (n == 0) {
            // print simple stats every ~1s
            uint64_t now = rte_get_tsc_cycles();
            if (now - last_tsc > hz) {
                printf("[stats] pkts=%" PRIu64 " bytes=%" PRIu64 "\n", pkts_total, bytes_total);
                last_tsc = now;
            }
            continue;
        }

        for (uint16_t i = 0; i < n; i++) {
            struct rte_mbuf *m = bufs[i];
            uint16_t plen = rte_pktmbuf_pkt_len(m);
            uint8_t *p = rte_pktmbuf_mtod(m, uint8_t *);

            if (plen < sizeof(struct eth_hdr)) {
                rte_pktmbuf_free(m);
                continue;
            }

            struct eth_hdr *eth = (struct eth_hdr *)p;
            uint16_t etype = rte_be_to_cpu_16(eth->ether_type);

            printf("[len=%u] ", plen);
            print_mac(eth->src); printf(" -> "); print_mac(eth->dst);
            printf("  EtherType=0x%04x", etype);

            const uint8_t *l3 = p + sizeof(struct eth_hdr);
            uint16_t l3len = plen - sizeof(struct eth_hdr);

            if (etype == 0x0800 && l3len >= sizeof(struct ipv4_hdr_s)) {
                const struct ipv4_hdr_s *ip4 = (const struct ipv4_hdr_s *)l3;
                printf("  IPv4 ");
                print_ipv4(ip4->saddr); printf(" -> "); print_ipv4(ip4->daddr);
                printf("  proto=%u", ip4->proto);
            } else if (etype == 0x86DD && l3len >= sizeof(struct ipv6_hdr_s)) {
                const struct ipv6_hdr_s *ip6 = (const struct ipv6_hdr_s *)l3;
                printf("  IPv6 ");
                print_ipv6(ip6->saddr); printf(" -> "); print_ipv6(ip6->daddr);
                printf("  nh=%u", ip6->next_hdr);
            } else if (etype == 0x0806) {
                printf("  ARP");
            }

            printf("\n");
            hexdump_line(p, plen, 32); // first 32 bytes
            pkts_total += 1;
            bytes_total += plen;

            rte_pktmbuf_free(m);
        }
    }

    printf("Exiting. Total pkts=%" PRIu64 ", bytes=%" PRIu64 "\n", pkts_total, bytes_total);
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
    return 0;
}
