#include "capture.h"
#include "parse_eth.h"

int main(void) {
    if (capture_init() != 0) {
        fprintf(stderr, "Failed to init capture\n");
        return 1;
    }

    uint8_t buf[2048];
    while (1) {
        int len = capture_next(buf, sizeof(buf));
        if (len <= 0) continue;
        parse_packet(buf, (uint16_t)len);
    }

    capture_close();
    return 0;
}

