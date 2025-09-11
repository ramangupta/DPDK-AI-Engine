#ifndef PCAP_WRITER_H
#define PCAP_WRITER_H

#include "engine/capture.h"

int  pcap_writer_init(void);
void pcap_writer_write(const uint8_t *data, size_t len);
void pcap_writer_close(void);

#endif // PCAP_WRITER_H
