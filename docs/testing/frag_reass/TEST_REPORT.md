# IPv4 Fragmentation & Reassembly Test Report

This document summarizes the functional and regression testing of the 
`frag_ipv4.c` module and its integration with `pkt-sniffer`.

---

## ✅ Test Harness

- **PCAP Mode:** Injects crafted fragmented IP packets via Scapy, replayed into sniffer with `--pcap`.


Reference test harness: `tests/frag_reassembly_test_harness.py`

---

## 🧪 Test Cases

| ID    | Description                                  | Expected Result  | Status |
|-------|----------------------------------------------|------------------|--------|
| 1000  | Happy path: in-order fragments               | Reassembled      | PASS   |
| 1001  | Out-of-order fragments                       | Reassembled      | PASS   |
| 1002  | Overlapping fragments                        | Reassembled      | PASS   |
| 1003  | Missing fragment (hole)                      | Drop             | PASS   |
| 1004  | Small final fragment (unaligned to 8 bytes)  | Reassembled      | PASS   |
| 1005  | Duplicate final fragment                     | Reassembled      | PASS   |
| 1006  | Malformed IPv4 (short header / raw payload)  | Drop             | PASS   |
| 1007  | Stress test: many tiny fragments             | Reassembled      | PASS   |

---

## 📊 Test Logs (Excerpt)

```text
ID=1000 expected=reassembled got=reassembled => PASS
ID=1001 expected=reassembled got=reassembled => PASS
ID=1002 expected=reassembled got=reassembled => PASS
ID=1003 expected=drop got=drop => PASS
ID=1004 expected=reassembled got=reassembled => PASS
ID=1005 expected=reassembled got=reassembled => PASS
ID=1006 expected=drop got=drop => PASS
ID=1007 expected=reassembled got=reassembled => PASS

🚩 Known Issues / Notes

AFP mode does not work directly on Wi-Fi interfaces (limitation of raw sockets).
Use lo or a TAP interface for AFP tests.

GC & flush (frag_ipv4_gc, frag_ipv4_flush_all) are critical for correctness;
without them, incomplete contexts would never be dropped.

Verified checksum re-calculation after reassembly.

🏁 Conclusion

All RFC-791 core cases have been covered.
The frag_ipv4 module correctly:

    - Buffers & merges intervals.
    - Handles out-of-order arrivals.
    - Drops incomplete assemblies.
    - Respects IPv4 header constraints.
    - Emits fully reassembled datagrams.