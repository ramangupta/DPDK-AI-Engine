// parse_http.c

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#include "utils/utils.h"
#include "stats/stats.h"
#include "engine/capture.h"

// --- Helper: trim leading/trailing whitespace ---
static void trim(char *s) {
    // Trim leading
    char *start = s;
    while (*start && isspace((unsigned char)*start)) start++;

    // Shift string if needed
    if (start != s) memmove(s, start, strlen(start) + 1);

    // Trim trailing
    char *end = s + strlen(s) - 1;
    while (end >= s && isspace((unsigned char)*end)) *end-- = '\0';
}


// --- HTTP parser ---
void parse_http(const pkt_view *pv) {
    if (pv->len < 4) return;

    const char *data = (const char *)pv->data;
    const char *end = memchr(data, '\n', pv->len);
    if (!end) return;

    size_t line_len = end - data;
    if (line_len > 200) line_len = 200;

    char line[201];
    memcpy(line, data, line_len);
    line[line_len] = '\0';

    char hostbuf[128] = {0};
    const char *method_str = NULL;
    const char *uri_str = NULL;
    char statusbuf[64] = {0};
    int code = 0;
    char reason[64] = {0};


    DEBUG_LOG(DBG_HTTP, "%.*s\n----\n", (int)pv->len, (const char*)pv->data);

    
    // --- Detect request line ---
    if (!strncasecmp(line, "GET ", 4) || !strncasecmp(line, "POST ", 5) ||
        !strncasecmp(line, "PUT ", 4) || !strncasecmp(line, "DELETE ", 7) ||
        !strncasecmp(line, "HEAD ", 5) || !strncasecmp(line, "OPTIONS ", 8)) {
        
        method_str = strtok(line, " ");
        uri_str = strtok(NULL, " ");
        PARSER_LOG_LAYER("HTTP", COLOR_HTTP, "      HTTP Request: %s %s\n", method_str, uri_str ? uri_str : "");

    } else if (!strncmp(line, "HTTP/", 5)) {
        // Response
        if (sscanf(line, "HTTP/%*s %d %63[^\r\n]", &code, reason) >= 1) {
            reason[sizeof(reason)-1] = '\0';
            size_t max_reason = sizeof(statusbuf) - 8;  // leave space for code + space + null
            if (max_reason > sizeof(reason)-1) max_reason = sizeof(reason)-1;
            snprintf(statusbuf, sizeof(statusbuf), "%d %.*s", code, (int)max_reason, reason);
            PARSER_LOG_LAYER("HTTP", COLOR_HTTP, "      HTTP Response: %s\n", statusbuf);
        } else {
            statusbuf[0] = '\0';
        }
    }

    // --- Extract Host header ---
    const char *p = data;
    size_t remaining = pv->len;
    while (remaining > 0) {
        const char *eol = memchr(p, '\n', remaining);
        if (!eol) break;

        size_t len = eol - p;
        if (len > sizeof(hostbuf)-1) len = sizeof(hostbuf)-1;

        if (!strncasecmp(p, "Host:", 5)) {
            const char *host_start = p + 5;
            while (*host_start == ' ' || *host_start == '\t') host_start++;
            size_t hlen = eol - host_start;
            if (hlen > sizeof(hostbuf)-1) hlen = sizeof(hostbuf)-1;
            strncpy(hostbuf, host_start, hlen);
            hostbuf[hlen] = '\0';
            trim(hostbuf);
            break;
        }

        remaining -= (eol - p) + 1;
        p = eol + 1;
    }

    // --- Update stats ---
    char srcbuf[80], dstbuf[80];
    snprintf(srcbuf, sizeof(srcbuf), "%s:%u", pv->src_ip, pv->src_port);
    snprintf(dstbuf, sizeof(dstbuf), "%s:%u", pv->dst_ip, pv->dst_port);

    stats_http_update(srcbuf, dstbuf,
                      hostbuf[0] ? hostbuf : NULL,
                      method_str,
                      uri_str,
                      statusbuf[0] ? statusbuf : NULL,
                      pv->len);
    
    stats_update(PROTO_HTTP, pv->len);
}
