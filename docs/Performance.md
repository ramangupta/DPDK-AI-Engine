# Performance Benchmarks — DPDK-AI-Engine

This file records performance results after each optimization.
All captures are done with the same pcap input (unless noted).

---

## Baseline Run
**Timestamp:** 2025-09-09 14:53  
**Description:** Pre-optimization benchmark  


---

## Optimization #1 — Safe pkt_view free path
**Timestamp:** 2025-09-09 16:23  
**Change:** Fixed `capture_free()` → use `pv_free_to_pool()` and `rte_pktmbuf_free()` correctly.  


### Δ Compared to Baseline
| Metric           | Before (14:53) | After (16:23) | Δ Change |
|------------------|----------------|---------------|----------|
| Duration (s)     | 7.387          | 7.146         | –0.241 (faster) |
| Throughput (pps) | 31,875.08      | 32,948.04     | **+3.4%** |
| Throughput (Mbps)| 214.55         | 221.77        | **+3.3%** |
| TCP PPS          | 26,271.82      | 27,156.17     | **+3.4%** |
| UDP PPS          | 3,646.52       | 3,769.26      | **+3.4%** |
| Latency (max ms) | 2.920          | 0.728         | **–75%** |
| Latency (avg ms) | 0.052          | 0.050         | –4% |
| App Drops        | 820            | 822           | +2 (negligible) |

**Notes:**
- Clear throughput improvement across TCP/UDP.  
- Tail latency reduced drastically (max 2.9 ms → 0.7 ms).  
- No regressions in parsing, reassembly, or pool usage.  

---

## Next Steps
- Record each new optimization with timestamp + description.  
- Keep delta tables for quick comparison.  
- Eventually generate plots (pps, Mbps, latency) once we have 5–6 runs.  
