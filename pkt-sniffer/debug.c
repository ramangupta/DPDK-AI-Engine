#include "debug.h"
#include <stdlib.h>
#include <string.h>

unsigned int DEBUG_MASK = 0; // default: no logs

void debug_log(const char *class_name, const char *func, int line, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    // timestamp
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char time_buf[9];
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm_info);

    fprintf(stdout, "[%s][%s][%s:%d] ", time_buf, class_name, func, line);
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");

    va_end(args);
}

void print_layer(const char *layer, const char *color, const char *func, int line, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    // timestamp
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char time_buf[9];
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm_info);

    fprintf(stdout, "[%s][PARSER][%s:%d] %s[%s] ", time_buf, func, line, color, layer);
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "%s\n", COLOR_RESET);

    va_end(args);
}
