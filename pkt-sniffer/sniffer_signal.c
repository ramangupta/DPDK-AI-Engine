// signals.c
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include "pcap_writer.h"

static void handle_sigint(int sig) {
    (void)sig;
    fprintf(stderr, "\nCaught SIGINT, closing pcap and exiting...\n");
    pcap_writer_close();
    exit(0);
}

void setup_signal_handlers(void) {
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);   // Ctrl-C
    sigaction(SIGTERM, &sa, NULL);  // kill/stop
}
