// parse_http.c
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "capture.h"   // for pkt_view
#include "utils.h"
#include "stats.h"

void parse_http(const pkt_view *pv) {
    if (pv->len < 4) return;

    const char *data = (const char *)pv->data;
    const char *end = memchr(data, '\n', pv->len);
    if (!end) return;

    size_t line_len = end - data;
    if (line_len > 200) line_len = 200;  // cap for sanity

    char line[201];
    memcpy(line, data, line_len);
    line[line_len] = '\0';

    const char *method_str = NULL;
    const char *uri_str = NULL;
    const char *status_str = NULL;
    const char *host_str = NULL;

    // --- Detect request line ---
    if (!strncmp(line, "GET ", 4) || !strncmp(line, "POST ", 5) ||
        !strncmp(line, "PUT ", 4) || !strncmp(line, "DELETE ", 7) ||
        !strncmp(line, "HEAD ", 5) || !strncmp(line, "OPTIONS ", 8)) {
        // Request
        method_str = strtok(line, " ");
        uri_str = strtok(NULL, " ");
        status_str = NULL;  // not applicable for requests

        printf("      HTTP Request: %s %s\n", method_str, uri_str ? uri_str : "");
    }
    else if (!strncmp(line, "HTTP/", 5)) {
        // Response
        status_str = line;   // full "HTTP/1.1 200 OK"
        method_str = NULL;
        uri_str = NULL;

        printf("      HTTP Response: %s\n", status_str);
    }

    // --- Look for Host header ---
    const char *p = data;
    size_t remaining = pv->len;
    while (remaining > 0) {
        const char *eol = memchr(p, '\n', remaining);
        if (!eol) break;
        size_t len = eol - p;
        if (len > 200) len = 200;

        if (!strncasecmp(p, "Host:", 5)) {
            static char hostbuf[128];
            size_t hostlen = len - 5;
            if (hostlen > sizeof(hostbuf) - 1) hostlen = sizeof(hostbuf) - 1;
            while (hostlen > 0 && (p[5] == ' ' || p[5] == '\t')) { p++; hostlen--; }
            strncpy(hostbuf, p + 5, hostlen);
            hostbuf[hostlen] = '\0';
            host_str = hostbuf;
            break;
        }

        remaining -= (eol - p) + 1;
        p = eol + 1;
    }

    // --- Update stats ---
    char srcbuf[80], dstbuf[80];
    snprintf(srcbuf, sizeof(srcbuf), "%s:%u",
         pv->src_ip, pv->src_port);
    snprintf(dstbuf, sizeof(dstbuf), "%s:%u",
            pv->dst_ip, pv->dst_port);

    stats_http_update(srcbuf, dstbuf,
                    host_str, method_str, uri_str, status_str,
                    pv->len);
    stats_update(PROTO_HTTP, pv->len);
}

