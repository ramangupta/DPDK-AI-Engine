#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

// Debug classes
#define DBG_PARSER    (1 << 0)
#define DBG_TCP_REASS (1 << 1)
#define DBG_L4        (1 << 2)
#define DBG_IP        (1 << 3)
#define DBG_ETH       (1 << 4)
#define DBG_TCP       (1 << 5)
#define DBG_UDP       (1 << 6)
#define DBG_HTTP      (1 << 7)
#define DBG_DNS       (1 << 8)
#define DBG_DHCP      (1 << 9)
#define DBG_ARP       (1 << 10)
#define DBG_IPFRAG    (1 << 11)

// Global debug mask (set at runtime)
extern unsigned int DEBUG_MASK;

// ANSI colors for parser logs
#define COLOR_RESET   "\033[0m"
#define COLOR_ETH     "\033[35m"  // magenta
#define COLOR_IP      "\033[36m"  // cyan
#define COLOR_IP_FRAG "\033[91m" // bright red
#define COLOR_TCP     "\033[32m"  // green
#define COLOR_UDP     "\033[33m"  // yellow
#define COLOR_ICMP    "\033[34m"  // blue
#define COLOR_TUNNEL  "\033[95m"  // bright magenta
#define COLOR_HTTP    "\033[96m"   // bright cyan (stands out for text-based HTTP)
#define COLOR_TLS     "\033[94m"   // bright blue (for TLS/SSL handshake/records)
#define COLOR_DNS     "\033[93m"   // bright yellow
#define COLOR_DHCP    "\033[92m"   // bright green
#define COLOR_ARP     "\033[90m"   // bright gray (stands out, not too flashy)


// Standard debug logging
#define DEBUG_LOG(class, fmt, ...)                          \
    do {                                                    \
        if (DEBUG_MASK & (class)) {                         \
            debug_log(#class, __func__, __LINE__, fmt, ##__VA_ARGS__); \
        }                                                   \
    } while(0)

// Parser-style logs with optional layer color
#define PARSER_LOG_LAYER(layer, color, fmt, ...) \
    do { \
        if (DEBUG_MASK & DBG_PARSER) { \
            print_layer(layer, color, __func__, __LINE__, fmt, ##__VA_ARGS__); \
        } \
    } while(0)

// Function declarations
void debug_log(const char *class_name, const char *func, int line, const char *fmt, ...);
void print_layer(const char *layer, const char *color, const char *func, int line, const char *fmt, ...);

#endif
