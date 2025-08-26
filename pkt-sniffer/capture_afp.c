// Works on Wi-Fi, any NIC


// capture_afp.c
#include "capture.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

static int sock_fd = -1;

int capture_init(void) {
    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        perror("socket(AF_PACKET)");
        return -1;
    }
    // Optionally bind to a specific interface (like "eth0")
    // For now, we can leave it bound to all
    return 0;
}

int capture_next(uint8_t *buf, uint16_t buflen) {
    ssize_t n = recv(sock_fd, buf, buflen, 0);
    if (n < 0) {
        perror("recv(AF_PACKET)");
        return -1;
    }
    return (int)n;
}

void capture_close(void) {
    if (sock_fd >= 0) close(sock_fd);
    sock_fd = -1;
}
