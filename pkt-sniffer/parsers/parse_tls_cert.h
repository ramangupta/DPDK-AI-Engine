// parse_tls_cert.h
#ifndef PARSE_TLS_CERT_H
#define PARSE_TLS_CERT_H

#include <stddef.h>
#include <stdint.h>

void tls_parse_cert(const uint8_t *buf, size_t len,
                    char *subject, size_t subj_len,
                    char *issuer, size_t issuer_len);

#endif
