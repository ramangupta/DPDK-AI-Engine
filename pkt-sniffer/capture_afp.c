// Works on Wi-Fi, any NIC
// capture_afp.c
#include "capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>

static int sock_fd = -1;

// a reusable receive buffer; parse happens before next recv, so it's safe
static uint8_t rx_buf[2048];

int capture_init(int argc, char **argv, const char *file) {
    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        perror("socket(AF_PACKET)");
        return -1;
    }
    return 0;
}

pkt_view *capture_next(void) {
    ssize_t n = recv(sock_fd, rx_buf, sizeof(rx_buf), 0);
    if (n < 0) {
        perror("recv(AF_PACKET)");
        return NULL;
    }
    if (n == 0) return NULL;

    return capture_wrap(rx_buf, n);
}

void capture_close(void) {
    if (sock_fd >= 0) close(sock_fd);
    sock_fd = -1;
}

void capture_release(pkt_view *pv) {
    if (!pv) return;
    if (pv->kind == PV_KIND_HEAP) {
        free(pv->backing);     // data buffer
        free(pv);              // pkt_view itself
    }
    // PV_KIND_STACK: nothing to do
    // PV_KIND_MBUF: not used in AFP backend
}

