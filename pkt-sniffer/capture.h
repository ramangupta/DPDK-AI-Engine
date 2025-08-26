// capture.h
#pragma once
#include <stdint.h>

// Return 0 on success, nonzero on failure
int capture_init(void);

// Capture a single packet, return length, or -1 on error/EOF
// buf: caller-provided buffer
// buflen: size of buffer
// returns: number of bytes written to buf, or -1 if no more packets / error
int capture_next(uint8_t *buf, uint16_t buflen);

// Cleanup resources
void capture_close(void);
