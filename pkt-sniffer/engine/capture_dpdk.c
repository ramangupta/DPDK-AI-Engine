// capture_dpdk.c — NIC bound to vfio-pci (kernel-bypass) or vdev (e.g., TAP)
// Uses the unified pkt_view API.

/*
 * USAGE
 * sudo ./build/pkt-sniffer --no-pci --vdev=net_pcap0,rx_pcap=$(pwd)/tmp/out4.pcap,tx_pcap=/tmp/out2.pcap   --log-level=pmd.net.pcap,8
*/

// capture_dpdk.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_lcore.h>
#include "engine/capture.h"

/* Tunables */
#define RX_RING_SIZE    1024
#define TX_RING_SIZE    1024
#define NUM_MBUFS       32768
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE      128

/* pkt_view pool parameters */
#define PV_POOL_BASE_NAME "pv_pool"
#define PV_POOL_SIZE NUM_MBUFS
#define PV_POOL_CACHE 256

/* Max sockets supported (safe upper bound) */
#ifndef MAX_SOCKETS
#define MAX_SOCKETS 8
#endif

int capture_port = -1;

static unsigned nb_pv_pools = 0;
static struct rte_mempool *mbuf_pool = NULL;
static struct rte_mempool *pv_pools[MAX_SOCKETS]; /* per-socket pkt_view pools */
static uint16_t active_port = RTE_MAX_ETHPORTS;

/* RX state kept per-lcore via simple static arrays for bursts */
static __thread struct rte_mbuf *mbuf_burst[BURST_SIZE];
static __thread pkt_view *pv_burst[BURST_SIZE];
static __thread int burst_idx = 0;
static __thread int burst_count = 0;

/* number of RX/TX queues we configure */
static unsigned nb_rx_queues = 1;
static unsigned nb_tx_queues = 1;

/* Helper to create per-socket pv pools */
static int create_pv_pools(void) {
    unsigned sockets = rte_socket_count();
    if (sockets == 0) {
        sockets = 1;
    }

    if (sockets > MAX_SOCKETS) 
        sockets = MAX_SOCKETS;

    for (unsigned s = 0; s < sockets; s++) {
        char name[64];
        snprintf(name, sizeof(name), "%s_socket%u", PV_POOL_BASE_NAME, s);
        pv_pools[s] = rte_mempool_create(name, PV_POOL_SIZE,
                                         sizeof(pkt_view), PV_POOL_CACHE,
                                         0, NULL, NULL, NULL, NULL,
                                         s, 0);
        if (!pv_pools[s]) {
            fprintf(stderr, "Failed to create pv_pool for socket %u\n", s);
            /* free any created pools */
            for (unsigned j = 0; j < s; j++) {
                rte_mempool_free(pv_pools[j]);
                pv_pools[j] = NULL;
            }
        nb_pv_pools = 0;
        return -1;

        }
    }
    nb_pv_pools = sockets;
    return 0;
}

/* Allocate pkt_view from socket-local pv pool */
static pkt_view *pv_alloc_from_pool(void) {
    pkt_view *pv = NULL;
    int socket = rte_socket_id();
    if (socket < 0) 
        socket = 0;
    
    if ((unsigned)socket >= nb_pv_pools) 
        socket = 0;
    
    if (rte_mempool_get(pv_pools[socket], (void **)&pv) < 0) 
        return NULL;
    
    memset(pv, 0, sizeof(*pv));
    return pv;
}

/* Return pkt_view to pool */
static void pv_free_to_pool(pkt_view *pv) {
    if (!pv) 
        return;
    
    int socket = rte_socket_id();
    
    if (socket < 0) 
        socket = 0;
    
    if ((unsigned)socket >= nb_pv_pools) 
        socket = 0;
    
    memset(pv, 0, sizeof(*pv));
    rte_mempool_put(pv_pools[socket], pv);
}

int capture_init(int argc, char **argv, const char *file) 
{
    /* Initialize EAL */
    if (rte_eal_init(argc, argv) < 0) {
        fprintf(stderr, "EAL init failed\n");
        return -1;
    }

    unsigned nb_ports = rte_eth_dev_count_avail();
    DEBUG_LOG(DBG_DPDK, "DPDK reports %u available ports\n", nb_ports);
    if (nb_ports == 0) {
        printf("No DPDK ports available (did you pass --vdev?).\n");
        return -1;
    }

    /* Pick first usable port */
    RTE_ETH_FOREACH_DEV(active_port) {
        DEBUG_LOG(DBG_DPDK, "Found DPDK port %u\n", active_port);
        break;
    }
    if (active_port == RTE_MAX_ETHPORTS) {
        printf("No usable ports found\n");
        return -1;
    }
    capture_port = active_port;

    /* Create mbuf pool */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                                        NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        printf("mbuf_pool create failed\n");
        return -1;
    }

    /* Create pkt_view pools */
    if (create_pv_pools() < 0) {
        printf("pv_pool create failed\n");
        rte_mempool_free(mbuf_pool);
        mbuf_pool = NULL;
        return -1;
    }

    /* Queue planning */
    unsigned lcores = rte_lcore_count();
    unsigned desired_rx_queues = (lcores > 0) ? lcores : 1;
    unsigned desired_tx_queues = desired_rx_queues;

    struct rte_eth_dev_info dev_info;
    int ret = rte_eth_dev_info_get(active_port, &dev_info);
    if (ret != 0) {
        fprintf(stderr, "Failed to get dev_info for port %u: %s\n",
                active_port, strerror(-ret));
        return -1;
    }

    unsigned max_rx = dev_info.max_rx_queues ? dev_info.max_rx_queues : 1;
    unsigned max_tx = dev_info.max_tx_queues ? dev_info.max_tx_queues : 1;

    nb_rx_queues = desired_rx_queues <= max_rx ? desired_rx_queues : max_rx;
    nb_tx_queues = desired_tx_queues <= max_tx ? desired_tx_queues : max_tx;

    DEBUG_LOG(DBG_DPDK,
        "Requested RX=%u TX=%u; device supports RX=%u TX=%u; using RX=%u TX=%u\n",
        desired_rx_queues, desired_tx_queues, max_rx, max_tx, nb_rx_queues, nb_tx_queues);

    /* Configure port */
    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;

    /* Desired offloads */
    const uint64_t desired_rx_offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM;
    const uint64_t desired_tx_offloads =
        RTE_ETH_TX_OFFLOAD_TCP_TSO |
        RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
        RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

    /* Only enable supported subset */
    uint64_t allowed_rx = dev_info.rx_offload_capa & desired_rx_offloads;
    uint64_t allowed_tx = dev_info.tx_offload_capa & desired_tx_offloads;

    port_conf.rxmode.offloads = allowed_rx;
    port_conf.txmode.offloads = allowed_tx;

    DEBUG_LOG(DBG_DPDK,
        "dev_info.rx_offload_capa=0x%016" PRIx64 " enabled_rx=0x%016" PRIx64 "\n"
        "dev_info.tx_offload_capa=0x%016" PRIx64 " enabled_tx=0x%016" PRIx64 "\n",
        (uint64_t)dev_info.rx_offload_capa, (uint64_t)allowed_rx,
        (uint64_t)dev_info.tx_offload_capa, (uint64_t)allowed_tx);

    if (rte_eth_dev_configure(active_port, nb_rx_queues, nb_tx_queues, &port_conf) < 0) {
        printf("dev_configure failed\n");

        if (rte_eth_dev_is_valid_port(active_port))
            rte_eth_dev_close(active_port);

        for (unsigned s = 0; s < nb_pv_pools; s++) {
            if (pv_pools[s]) {
                rte_mempool_free(pv_pools[s]);
                pv_pools[s] = NULL;
            }
        }
        nb_pv_pools = 0;

        if (mbuf_pool) {
            rte_mempool_free(mbuf_pool);
            mbuf_pool = NULL;
        }
        return -1;
    }

    /* RX queue setup */
    for (unsigned q = 0; q < nb_rx_queues; q++) {
        if (rte_eth_rx_queue_setup(active_port, q, RX_RING_SIZE,
                                   rte_eth_dev_socket_id(active_port),
                                   NULL, mbuf_pool) < 0) {
            printf("rx_queue_setup failed for q=%u\n", q);
            return -1;
        }
    }

    /* TX queue setup */
    for (unsigned q = 0; q < nb_tx_queues; q++) {
        if (rte_eth_tx_queue_setup(active_port, q, TX_RING_SIZE,
                                   rte_eth_dev_socket_id(active_port),
                                   NULL) < 0) {
            printf("tx_queue_setup failed for q=%u\n", q);
            return -1;
        }
    }

    /* Start device */
    if (rte_eth_dev_start(active_port) < 0) {
        printf("dev_start failed\n");
        return -1;
    }

    DEBUG_LOG(DBG_DPDK, "DPDK init success on port %u with %u RX queues, %u TX queues!\n",
           active_port, nb_rx_queues, nb_tx_queues);
    return 0;
}

#ifdef USE_DPDK
/* Zero-copy wrapper around DPDK mbuf
   Now allocates pkt_view from pv_pool (fast mempool), fills fields, and
   returns a pv owned by caller; caller must call capture_release(pv).
*/
pkt_view *capture_from_mbuf(struct rte_mbuf *mbuf) {
    if (!mbuf) return NULL;

    pkt_view *pv = pv_alloc_from_pool();
    if (!pv) {
        // fallback: drop mbuf when unable to allocate wrapper
        rte_pktmbuf_free(mbuf);
        return NULL;
    }

    pv->data = rte_pktmbuf_mtod(mbuf, uint8_t *);   // point directly into mbuf data
    pv->len  = rte_pktmbuf_pkt_len(mbuf);           // total packet length
    pv->kind = PV_KIND_MBUF;                        // mark as mbuf-backed
    pv->backing = mbuf;                             // remember mbuf for freeing later
    pv->inner_pkt = NULL;

    DEBUG_LOG(DBG_DPDK, "pkt_view=%p from mbuf=%p pkt_len=%u\n",
        (void*)pv, (void*)mbuf, pv->len);

    return pv;
}
#endif

/* capture_next: thread-local. Select queue based on lcore id to spread across queues. */
pkt_view *capture_next(void) 
{

    if (burst_idx >= burst_count) {
        burst_count = rte_eth_rx_burst(active_port, 0, mbuf_burst, BURST_SIZE);
        burst_idx = 0;
        if (burst_count == 0) 
            return NULL;

        for (int i = 0; i < burst_count; i++) {
            /* Prefetch mbuf struct and packet data to reduce cache miss */
            rte_prefetch0(mbuf_burst[i]);
            rte_prefetch0(rte_pktmbuf_mtod(mbuf_burst[i], void *));

            pv_burst[i] = capture_from_mbuf(mbuf_burst[i]);
            if (!pv_burst[i]) {
                /* capture_from_mbuf frees mbuf on failure */
                pv_burst[i] = NULL;
            }
        }
    }


    if (burst_idx + 1 < burst_count && pv_burst[burst_idx + 1]) {
        rte_prefetch0(pv_burst[burst_idx + 1]->data);
        rte_prefetch0(pv_burst[burst_idx + 1]->backing);
    }

    return pv_burst[burst_idx++];
}

void capture_close(void) 
{
    rte_eth_dev_stop(active_port);
    rte_eth_dev_close(active_port);

    for (unsigned s = 0; s < nb_pv_pools; s++) {
        if (pv_pools[s]) {
            rte_mempool_free(pv_pools[s]);
            pv_pools[s] = NULL;
        }
    }
    nb_pv_pools = 0;

    if (mbuf_pool) {
        rte_mempool_free(mbuf_pool);
        mbuf_pool = NULL;
    }
}

/* Release only the backing buffer, return wrapper to pool */
void capture_release(pkt_view *pv) {
    if (!pv) return;


    switch (pv->kind) {
        case PV_KIND_MBUF:
#ifdef USE_DPDK
            if (pv->backing) {
                rte_pktmbuf_free((struct rte_mbuf *)pv->backing);
                pv->backing = NULL;
            }
#endif
            pv_free_to_pool(pv);
            break;

        case PV_KIND_HEAP:
            if (pv->backing) {
                free(pv->backing);
                pv->backing = NULL;
            }
            free(pv);
            break;

        case PV_KIND_STACK:
        case PV_KIND_BORROWED:
        /* Caller owns wrapper/data: do not free */
        break;

        default:
            /* Unknown kind - return wrapper to pool conservatively */
            pv_free_to_pool(pv);
            break;
    }
}


/* capture_free: fully free pkt_view and any inner_pkt recursively */
void capture_free(pkt_view *pv) 
{
    if (!pv) 
        return;

    DEBUG_LOG(DBG_DPDK, "capture_free: pv=%p kind=%d data=%p len=%u inner_pkt=%p\n",
              (void*)pv, pv->kind, (void*)pv->data, (unsigned)pv->len, (void*)pv->inner_pkt);

    if (pv->inner_pkt) {
        capture_free(pv->inner_pkt);
        pv->inner_pkt = NULL;
    }

    switch (pv->kind) {
        case PV_KIND_HEAP:
            if (pv->backing) {
                free(pv->backing);
                pv->backing = NULL;
            }
            free(pv);
        break;

        case PV_KIND_MBUF:
            if (pv->backing) {
                rte_pktmbuf_free((struct rte_mbuf *)pv->backing);
                pv->backing = NULL;
            }
            pv_free_to_pool(pv);
        break;

        case PV_KIND_STACK:
        case PV_KIND_BORROWED:
            /* wrapper/owner-managed: do nothing */
            break;

        default:
            pv_free_to_pool(pv);
        break;
    }
}

// malloc + copy (frag reassembly etc.)
pkt_view *capture_alloc(size_t len) {
    pkt_view *pv = malloc(sizeof(pkt_view));
    if (!pv) return NULL;

    uint8_t *buf = malloc(len);
    if (!buf) {
        free(pv);
        return NULL;
    }

    pv->data    = buf;
    pv->len     = len;
    pv->kind    = PV_KIND_HEAP;
    pv->backing = buf;
    return pv;
}

#if 0
pkt_view *capture_alloc(size_t len) {
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) return NULL;

    if (rte_pktmbuf_tailroom(mbuf) < len) {
        rte_pktmbuf_free(mbuf);
        return NULL;
    }

    pkt_view *pv = pv_alloc_from_pool();
    if (!pv) {
        rte_pktmbuf_free(mbuf);
        return NULL;
    }

    pv->data    = rte_pktmbuf_mtod(mbuf, uint8_t *);
    pv->len     = len;
    pv->kind    = PV_KIND_MBUF;
    pv->backing = mbuf;
    pv->inner_pkt = NULL;

    return pv;
}
    #endif
