// parse_tls_cert.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

/*
 * Minimal ASN.1 DER walker to extract:
 *  - Issuer CN (2.5.4.3)
 *  - Subject CN (2.5.4.3)
 *  - SAN dNSName (2.5.29.17) or iPAddress
 *
 * This is intentionally limited: it does not fully validate certs or parse certificates
 * for cryptographic purposes. It attempts to be robust against truncated/malformed DER
 * by guarding bounds carefully.
 */

static const uint8_t OID_CN[]  = { 0x55, 0x04, 0x03 };  // 2.5.4.3
static const uint8_t OID_SAN[] = { 0x55, 0x1D, 0x11 };  // 2.5.29.17

// read length (per DER rules). Updates *pp and *remain. Returns length or (size_t)-1 on error.
static size_t asn1_read_len(const uint8_t **pp, size_t *remain) {
    if (*remain < 1) return (size_t)-1;
    uint8_t b = *(*pp)++;
    (*remain)--;
    if ((b & 0x80) == 0) {
        return (size_t)(b);
    }
    int n = b & 0x7F;
    if (n == 0 || n > 4) return (size_t)-1; // unrealistic length bytes >4
    if (*remain < (size_t)n) return (size_t)-1;
    size_t len = 0;
    for (int i = 0; i < n; i++) {
        len = (len << 8) | *(*pp)++;
        (*remain)--;
    }
    return len;
}

// read an ASN.1 TLV: expect tag byte already present at *pp, return tag and length, set value_ptr.
// On success: returns tag byte (0..255) and sets *valp and *vallen and advances *pp past tag+len bytes.
// On error returns -1.
static int asn1_get_tlv(const uint8_t **pp, size_t *remain, const uint8_t **valp, size_t *vallen) {
    if (*remain < 1) return -1;
    uint8_t tag = *(*pp)++;
    (*remain)--;
    size_t len = asn1_read_len(pp, remain);
    if (len == (size_t)-1) return -1;
    if (*remain < len) return -1;
    *valp = *pp;
    *vallen = len;
    *pp += len;
    *remain -= len;
    return tag;
}

// compare OID (raw DER bytes) with expected
static int oid_equals(const uint8_t *oid, size_t oidlen, const uint8_t *pat, size_t patlen) {
    if (oidlen < patlen) return 0;
    // OID could be longer (e.g. has prefix). We'll check suffix equality for the 2.5.4.3 pattern or exact for SAN.
    if (patlen == sizeof(OID_CN)) {
        // OID for CN often is exactly 3 bytes 55 04 03; match suffix
        if (oidlen >= patlen && memcmp(oid + (oidlen - patlen), pat, patlen) == 0) return 1;
        return 0;
    }
    return (oidlen == patlen && memcmp(oid, pat, patlen) == 0);
}

// copy ASN.1 string (many types possible) into buffer (null terminated). Accepts UTF8String(0x0C),
// PrintableString(0x13), IA5String(0x16), BMPString(0x1E) (we'll treat BMP as bytes).
static void asn1_copy_string(const uint8_t *p, size_t plen, char *out, size_t outlen) {
    if (outlen == 0) return;
    out[0] = '\0';
    if (plen == 0) return;
    // tag is first byte of p (caller sometimes passes value area; here we expect tag+len+value)
    const uint8_t *ptr = p;
    size_t rem = plen;
    // Some callers pass value already (no tag). To support both, detect if first byte looks like a string tag.
    uint8_t tag = ptr[0];
    if (tag == 0x0C || tag == 0x13 || tag == 0x16 || tag == 0x1E) {
        // TLV form
        ptr++; rem--;
        size_t vlen = asn1_read_len(&ptr, &rem);
        if (vlen == (size_t)-1 || rem < vlen) return;
        size_t copy = (vlen < outlen-1) ? vlen : outlen-1;
        memcpy(out, ptr, copy);
        out[copy] = '\0';
    } else {
        // Assume raw value (no tag/len)
        size_t copy = (plen < outlen-1) ? plen : outlen-1;
        memcpy(out, p, copy);
        out[copy] = '\0';
    }
}

// parse Name (RDNSequence) to extract first CN found. Input is pointer to SEQUENCE value area and its length.
// Returns 1 if CN found and copied to out, 0 otherwise.
static int parse_name_for_cn(const uint8_t *p, size_t len, char *out, size_t outlen) {
    const uint8_t *ptr = p;
    size_t rem = len;
    // Name is SEQUENCE of RDNs (each RDN is SET of SEQUENCEs)
    while (rem > 0) {
        // Expect a SET or SEQUENCE tag for each RDN (usually SET tag 0x31)
        if (rem < 1) break;
        uint8_t tag = *ptr;
        if (tag != 0x31 && tag != 0x30) {
            // not a set/sequence, try to bail
            break;
        }
        // read this RDN TLV
        const uint8_t *rdn_val;
        size_t rdn_len;
        const uint8_t *tmp = ptr;
        size_t tmp_rem = rem;
        if (asn1_get_tlv(&tmp, &tmp_rem, &rdn_val, &rdn_len) < 0) break;
        // rdn_val is content of SET (sequence inside)
        const uint8_t *seq_ptr = rdn_val;
        size_t seq_rem = rdn_len;
        // inside should be SEQUENCE(s) each containing OID + value
        while (seq_rem > 0) {
            // get inner SEQUENCE TLV
            if (seq_rem < 1) break;
            if (*seq_ptr != 0x30) { // expected SEQUENCE
                // skip if not sequence
                break;
            }
            const uint8_t *attr_val;
            size_t attr_len;
            const uint8_t *inner_tmp = seq_ptr;
            size_t inner_rem = seq_rem;
            if (asn1_get_tlv(&inner_tmp, &inner_rem, &attr_val, &attr_len) < 0) break;
            // attr_val contains SEQUENCE(OID + value)
            // parse OID (should start with 0x06)
            const uint8_t *a = attr_val;
            size_t a_rem = attr_len;
            if (a_rem < 1) goto seq_next;
            if (a[0] == 0x06) {
                const uint8_t *oid_val;
                size_t oid_len;
                const uint8_t *tmp2 = a;
                size_t tmp2_rem = a_rem;
                if (asn1_get_tlv(&tmp2, &tmp2_rem, &oid_val, &oid_len) < 0) goto seq_next;
                // the rest should be a value (string) TLV
                if (tmp2_rem >= 1) {
                    // read the value TLV header and copy its string
                    const uint8_t *valp;
                    size_t vallen;
                    if (asn1_get_tlv(&tmp2, &tmp2_rem, &valp, &vallen) == -1) goto seq_next;
                    if (oid_equals(oid_val, oid_len, OID_CN, sizeof(OID_CN))) {
                        // We have CN; copy string (valp includes string bytes)
                        // valp points to value bytes (already advanced past tag? our asn1_get_tlv returns val pointer at value start)
                        // But asn1_get_tlv returns valp pointing to value region (NOT including the tag+len) so we need to copy directly.
                        size_t copy = (vallen < outlen-1) ? vallen : outlen-1;
                        memcpy(out, valp, copy);
                        out[copy] = '\0';
                        return 1;
                    }
                }
            }
seq_next:
            // advance seq_ptr to next element
            // asn1_get_tlv didn't advance the original seq_ptr; we have inner_tmp/inner_rem pointing after the SEQUENCE attr
            seq_ptr = inner_tmp;
            seq_rem = inner_rem;
        }
        // advance ptr to next RDN
        ptr = tmp;
        rem = tmp_rem;
    }
    return 0;
}

// parse extensions to find SAN dNSName or iPAddress. Input is extensions SEQUENCE content area.
// parse_extensions_for_san (fixed checks and minor robustness)
static int parse_extensions_for_san(const uint8_t *p, size_t len, char *out, size_t outlen) {
    const uint8_t *ptr = p;
    size_t rem = len;
    // extensions is SEQUENCE of extension SEQUENCEs
    while (rem > 0) {
        const uint8_t *ext_val;
        size_t ext_len;
        const uint8_t *tmp = ptr;
        size_t tmp_rem = rem;
        if (asn1_get_tlv(&tmp, &tmp_rem, &ext_val, &ext_len) < 0) break;
        // ext_val contains OID + optional critical + extnValue (OCTET STRING)
        const uint8_t *e = ext_val;
        size_t e_rem = ext_len;
        // OID
        if (e_rem < 1) { ptr = tmp; rem = tmp_rem; continue; }
        if (e[0] != 0x06) { ptr = tmp; rem = tmp_rem; continue; }
        const uint8_t *oid_val;
        size_t oid_len;
        const uint8_t *e_tmp = e;
        size_t e_tmp_rem = e_rem;
        if (asn1_get_tlv(&e_tmp, &e_tmp_rem, &oid_val, &oid_len) < 0) { ptr = tmp; rem = tmp_rem; continue; }
        // skip optional critical BOOLEAN (0x01)
        if (e_tmp_rem > 0 && e_tmp[0] == 0x01) {
            const uint8_t *bool_val;
            size_t bool_len;
            if (asn1_get_tlv(&e_tmp, &e_tmp_rem, &bool_val, &bool_len) < 0) { ptr = tmp; rem = tmp_rem; continue; }
        }
        // extnValue (OCTET STRING)
        if (e_tmp_rem < 1) { ptr = tmp; rem = tmp_rem; continue; }
        const uint8_t *extn_val;
        size_t extn_val_len;
        if (asn1_get_tlv(&e_tmp, &e_tmp_rem, &extn_val, &extn_val_len) < 0) { ptr = tmp; rem = tmp_rem; continue; }
        // if this is SAN OID, parse extn_val (which itself is DER encoded payload)
        if (oid_equals(oid_val, oid_len, OID_SAN, sizeof(OID_SAN))) {
            const uint8_t *gptr = extn_val;
            size_t grem = extn_val_len;
            // If extn_val contains a nested TLV (often it does), handle it:
            if (grem >= 1 && gptr[0] == 0x30) {
                const uint8_t *seq_val;
                size_t seq_len;
                const uint8_t *tmp2 = gptr;
                size_t tmp2_rem = grem;
                // NOTE: fix here: check for non-negative tag (>=0), not == 0
                if (asn1_get_tlv(&tmp2, &tmp2_rem, &seq_val, &seq_len) >= 0) {
                    gptr = seq_val; grem = seq_len;
                } else {
                    // fallback: treat extn_val as raw
                }
            }
            // iterate GeneralNames: context-specific tags like [2] dNSName, [7] iPAddress
            while (grem > 0) {
                uint8_t tag = gptr[0];
                if ((tag & 0xE0) == 0x80) { // context-specific
                    const uint8_t *valp;
                    size_t vallen;
                    const uint8_t *tptr = gptr;
                    size_t trem = grem;
                    if (asn1_get_tlv(&tptr, &trem, &valp, &vallen) < 0) break;
                    int tagnum = tag & 0x1F;
                    if (tagnum == 2) { // dNSName (IA5String)
                        size_t copy = (vallen < outlen-1) ? vallen : outlen-1;
                        memcpy(out, valp, copy);
                        out[copy] = '\0';
                        return 1;
                    } else if (tagnum == 7) { // iPAddress
                        if (vallen == 4) {
                            snprintf(out, outlen, "%u.%u.%u.%u", valp[0], valp[1], valp[2], valp[3]);
                            return 1;
                        } else if (vallen == 16) {
                            int pos = 0;
                            char tmpbuf[64];
                            tmpbuf[0] = '\0';
                            for (int i = 0; i < 16; i += 2) {
                                pos += snprintf(tmpbuf + pos, sizeof(tmpbuf) - pos, "%02x%02x", valp[i], valp[i+1]);
                                if (i < 14) pos += snprintf(tmpbuf + pos, sizeof(tmpbuf) - pos, ":");
                            }
                            strncpy(out, tmpbuf, outlen-1); out[outlen-1] = '\0';
                            return 1;
                        }
                    }
                    // advance
                    gptr = tptr;
                    grem = trem;
                    continue;
                } else {
                    // Unexpected tag; try to skip a TLV
                    const uint8_t *skip_val;
                    size_t skip_len;
                    const uint8_t *t2 = gptr;
                    size_t r2 = grem;
                    if (asn1_get_tlv(&t2, &r2, &skip_val, &skip_len) < 0) break;
                    gptr = t2; grem = r2;
                }
            }
        }
        ptr = tmp;
        rem = tmp_rem;
    }
    return 0;
}

static int peek_tag(const uint8_t *q, size_t qrem) {
    if (qrem < 1) return -1;
    return q[0];  // example: just return first byte as tag
}

void tls_parse_cert(const uint8_t *cert, size_t cert_len,
                    char *subject, size_t subj_len,
                    char *issuer, size_t iss_len)
{
    // default
    if (subj_len) subject[0] = '\0';
    if (iss_len) issuer[0] = '\0';

    if (!cert || cert_len < 10) return;

    const uint8_t *p = cert;
    size_t rem = cert_len;

    // Expect SEQUENCE (Certificate)
    if (rem < 1 || *p != 0x30) return;
    p++; rem--;
    size_t cert_seq_len = asn1_read_len(&p, &rem);
    if (cert_seq_len == (size_t)-1 || cert_seq_len > rem) return;

    // Now we are at the Certificate sequence contents: first is tbsCertificate (SEQUENCE)
    if (rem < 1 || *p != 0x30) return;
    const uint8_t *tbs_ptr = p;
    size_t tbs_rem = rem;
    // read tbsCertificate TLV
    const uint8_t *tbs_val;
    size_t tbs_len;
    if (asn1_get_tlv(&p, &rem, &tbs_val, &tbs_len) < 0) return;
    // tbs_val points to value of tbsCertificate
    const uint8_t *tp = tbs_val;
    size_t trem = tbs_len;

    // tbsCertificate layout: [0]version? serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, [1]issuerUniqueID?
    // We need to advance through optional fields to get to issuer then subject then extensions.
    // We'll walk fields one by one.

    // Helper to peek tag
    int tag = peek_tag(p, rem);
    if (tag < 0)
        return;
        
    // Skip optional version ([0] EXPLICIT)
    if (trem > 0 && tp[0] == 0xA0) {
        const uint8_t *tmp = tp;
        size_t tmprem = trem;
        const uint8_t *vval;
        size_t vlen;
        if (asn1_get_tlv(&tmp, &tmprem, &vval, &vlen) < 0) return;
        tp = tmp; trem = tmprem;
    }

    // serialNumber (INTEGER)
    if (trem < 1 || tp[0] != 0x02) return;
    {
        const uint8_t *tmp = tp;
        size_t tmprem = trem;
        const uint8_t *val;
        size_t vlen;
        if (asn1_get_tlv(&tmp, &tmprem, &val, &vlen) < 0) return;
        tp = tmp; trem = tmprem;
    }

    // signature Algorithm (SEQUENCE)
    if (trem < 1 || tp[0] != 0x30) return;
    {
        const uint8_t *tmp = tp;
        size_t tmprem = trem;
        const uint8_t *val;
        size_t vlen;
        if (asn1_get_tlv(&tmp, &tmprem, &val, &vlen) < 0) return;
        tp = tmp; trem = tmprem;
    }

    // Issuer (Name SEQUENCE)
    if (trem < 1 || tp[0] != 0x30) return;
    const uint8_t *issuer_val;
    size_t issuer_len;
    {
        const uint8_t *tmp = tp;
        size_t tmprem = trem;
        if (asn1_get_tlv(&tmp, &tmprem, &issuer_val, &issuer_len) < 0) return;
        // parse issuer for CN
        if (!parse_name_for_cn(issuer_val, issuer_len, issuer, iss_len)) {
            // leave issuer empty
            if (iss_len) issuer[0] = '\0';
        }
        tp = tmp; trem = tmprem;
    }

    // Validity (SEQUENCE)
    if (trem < 1 || tp[0] != 0x30) return;
    {
        const uint8_t *tmp = tp;
        size_t tmprem = trem;
        const uint8_t *val;
        size_t vlen;
        if (asn1_get_tlv(&tmp, &tmprem, &val, &vlen) < 0) return;
        tp = tmp; trem = tmprem;
    }

    // Subject (Name SEQUENCE)
    if (trem < 1) return;
    if (tp[0] != 0x30) return;
    const uint8_t *subject_val;
    size_t subject_len;
    {
        const uint8_t *tmp = tp;
        size_t tmprem = trem;
        if (asn1_get_tlv(&tmp, &tmprem, &subject_val, &subject_len) < 0) return;
        // parse subject for CN
        if (!parse_name_for_cn(subject_val, subject_len, subject, subj_len)) {
            // not found in subject; leave as empty for now
            if (subj_len) subject[0] = '\0';
        }
        tp = tmp; trem = tmprem;
    }

    // subjectPublicKeyInfo (SEQUENCE) -- skip
    if (trem > 0 && tp[0] == 0x30) {
        const uint8_t *tmp = tp;
        size_t tmprem = trem;
        const uint8_t *val;
        size_t vlen;
        if (asn1_get_tlv(&tmp, &tmprem, &val, &vlen) < 0) return;
        tp = tmp; trem = tmprem;
    }

    // Now we may have optional elements; look for extensions which are usually [3] EXPLICIT
    // We'll search remaining TBSCertificate region for tag 0xA3 (context-specific [3])
    const uint8_t *ext_search = tp;
    size_t ext_search_rem = trem;
    while (ext_search_rem > 0) {
        if (ext_search[0] == 0xA3) {
            // read the [3] EXPLICIT TLV; its value should be the extensions SEQUENCE
            const uint8_t *ext_val;
            size_t ext_len;
            const uint8_t *tmp = ext_search;
            size_t tmprem = ext_search_rem;
            if (asn1_get_tlv(&tmp, &tmprem, &ext_val, &ext_len) == -1) break;
            // ext_val likely contains a SEQUENCE (extensions)
            // if ext_val begins with 0x30, parse its content for SAN
            if (ext_len > 0) {
                if (ext_val[0] == 0x30) {
                    const uint8_t *sev = ext_val;
                    size_t sev_rem = ext_len;
                    const uint8_t *seq_val;
                    size_t seq_len;
                    const uint8_t *tmp2 = sev;
                    size_t tmp2_rem = sev_rem;
                    if (asn1_get_tlv(&tmp2, &tmp2_rem, &seq_val, &seq_len) == 0) {
                        // parse seq_val (extensions sequence)
                        if (parse_extensions_for_san(seq_val, seq_len, subject, subj_len)) {
                            // found SAN into subject (prefer SAN over Subject CN)
                        }
                    }
                } else {
                    // sometimes ext_val directly holds the extensions sequence (rare)
                    if (parse_extensions_for_san(ext_val, ext_len, subject, subj_len)) {
                        // found SAN
                    }
                }
            }
            break;
        } else {
            // try to skip one TLV to move forward
            const uint8_t *tmp = ext_search;
            size_t tmprem = ext_search_rem;
            const uint8_t *val;
            size_t vlen;
            if (asn1_get_tlv(&tmp, &tmprem, &val, &vlen) < 0) break;
            ext_search = tmp;
            ext_search_rem = tmprem;
        }
    }

    // If subject still empty, try to fallback to SAN parsing directly on remaining TBSCertificate
    if ((subj_len > 0 && subject[0] == '\0') || (iss_len > 0 && issuer[0] == '\0')) {
        // re-run search for SAN in TBSCertificate remainder (tp..tbs_end)
        // tbs_val and tbs_len were earlier recorded; parse extensions on whole tbs_val
        parse_extensions_for_san(tbs_val, tbs_len, subject, subj_len);
    }

    // Final: if subject/issuer empty, fill with "-"
    if (subj_len && subject[0] == '\0') {
        strncpy(subject, "-", subj_len);
        subject[subj_len-1] = '\0';
    }
    if (iss_len && issuer[0] == '\0') {
        strncpy(issuer, "-", iss_len);
        issuer[iss_len-1] = '\0';
    }
}
