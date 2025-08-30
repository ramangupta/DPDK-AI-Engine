#include "cli.h"
#include "filter.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>   // for getaddrinfo()

static struct option long_opts[] = {
    {"proto",      required_argument, 0, 'p'},  // dns | tcp | udp | arp
    {"port",       required_argument, 0, 'P'},  // 1..65535
    {"ip",         required_argument, 0, 'i'},  // IPv4/IPv6 literal
    {"host",       required_argument, 0, 'H'},  // substring match
    {"write-pcap", required_argument, 0, 'w'},  // PCAP support
    {"help",       no_argument,       0, 'h'},
    {0,0,0,0}
};

static int parse_u16(const char *s, unsigned short *out) {
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || !end || *end != '\0' || v < 1 || v > 65535) return -1;
    *out = (unsigned short)v;
    return 0;
}

void cli_usage(const char *prog) {
    printf("Usage: %s [filter options] [DPDK EAL options]\n", prog);
    printf("Filter options:\n");
    printf("  -p, --proto <dns|tcp|udp|arp>\n");
    printf("  -P, --port <1-65535>\n");
    printf("  -i, --ip <IPv4/IPv6>\n");
    printf("  -H, --host <substring>\n");
    printf("  -w, --write-pcap <file>  Save captured packets to PCAP file\n");
    printf("  -h, --help\n");
    printf("\nNotes:\n");
    printf("  * Unknown options (e.g., DPDK EAL flags like --no-pci, -vdev=...) are ignored.\n");
    printf("  * DNS means TCP/53 or UDP/53.\n");
}

void cli_parse(int argc, char **argv) {
    filter_init();

    // getopt will stop at first unknown unless opterr=0
    opterr = 0;
    optind = 1;

    int opt;
    // IMPORTANT: use getopt_long_only to avoid exploding '-vdev=...' into -v -d -e -v ...
    while ((opt = getopt_long_only(argc, argv, "p:P:i:H:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            g_filters.filter_proto = true;
            strncpy(g_filters.proto, optarg, sizeof(g_filters.proto) - 1);
            g_filters.proto[sizeof(g_filters.proto) - 1] = '\0';
            if (strcmp(g_filters.proto, "tcp") &&
                strcmp(g_filters.proto, "udp") &&
                strcmp(g_filters.proto, "arp") &&
                strcmp(g_filters.proto, "dns") &&
                strcmp(g_filters.proto, "icmp") &&
                strcmp(g_filters.proto, "icmp6")) {
                fprintf(stderr, "Unsupported --proto: %s\n", g_filters.proto);
                exit(1);
            }
            break;
        case 'P': {
            unsigned short port = 0;
            if (parse_u16(optarg, &port) != 0) {
                fprintf(stderr, "Invalid --port: %s\n", optarg);
                exit(1);
            }
            g_filters.filter_port = true;
            g_filters.port = port;
            break;
        }
        case 'i':
            if (strchr(optarg, ':')) {
                // IPv6
                if (inet_pton(AF_INET6, optarg, &g_filters.ip6) == 1) {
                    g_filters.has_ip6 = true;
                } else {
                    fprintf(stderr, "Invalid IPv6 address: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
            } else {
                // IPv4
                if (inet_pton(AF_INET, optarg, &g_filters.ip4) == 1) {
                    g_filters.has_ip4 = true;
                } else {
                    fprintf(stderr, "Invalid IPv4 address: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
            }
            break;
        case 'H':
            g_filters.filter_host = true;
            strncpy(g_filters.host_str, optarg, sizeof(g_filters.host_str) - 1);
            g_filters.host_str[sizeof(g_filters.host_str) - 1] = '\0';

            struct addrinfo hints = {0}, *res = NULL;
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM; // doesn’t matter, just to force resolution

            int err = getaddrinfo(optarg, NULL, &hints, &res);
            if (err != 0) {
                fprintf(stderr, "Failed to resolve host '%s': %s\n",
                        optarg, gai_strerror(err));
                exit(1);
            }

            g_filters.host_addr_count = 0;
            for (struct addrinfo *ai = res; ai && g_filters.host_addr_count < MAX_HOST_ADDRS; ai = ai->ai_next) {
                if (ai->ai_family == AF_INET) {
                    struct sockaddr_in *sa = (struct sockaddr_in *)ai->ai_addr;
                    g_filters.host_v4[g_filters.host_addr_count++] = sa->sin_addr;
                } else if (ai->ai_family == AF_INET6) {
                    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ai->ai_addr;
                    g_filters.host_v6[g_filters.host_addr_count++] = sa6->sin6_addr;
                }
            }
            freeaddrinfo(res);
            if (g_filters.host_addr_count == 0) {
                fprintf(stderr, "No usable IPs found for host '%s'\n", optarg);
                exit(1);
            }
            break;
           
        case 'h':
            cli_usage(argv[0]);
            exit(0);
        case 'w':
            g_filters.write_pcap = true;
            strncpy(g_filters.write_file, optarg, sizeof(g_filters.write_file) - 1);
            g_filters.write_file[sizeof(g_filters.write_file) - 1] = '\0';
            break;

        case '?': // unknown option; skip
        default:
            // let DPDK handle it later
            break;
        }
    }
}
