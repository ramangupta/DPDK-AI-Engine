✅ Batching
--------------

Process n packets at once (BURST_SIZE).
Keep parsing tight in a loop, no function call overhead inside hot path.

Action
capture_next() fetches bursts from DPDK (rte_eth_rx_burst) internally.
Maintains an internal array of pkt_view*.
Returns one packet at a time to main loop but keeps burst semantics.
Prefetching applied within the burst.
Benefits: Fewer syscalls, better CPU cache utilization, aligns with DPDK’s burst architecture.

✅ Prefetching & Cache Optimizations
-------------------------------------

Why prefetch helps

DPDK packets live in hugepages, so accessing them can still cause cache misses. If you know you’ll process n packets in a burst:

You can prefetch the next packet headers while processing the current one.

This reduces load-to-use latency, especially for AI workloads where you parse and analyze headers intensively.

Action
Prefetch next packet’s data and backing while processing current packet.
L1/L2 caches used effectively.
Optional: prefetch header offsets if you know AI pipeline reads only first 64–128 bytes.
Benefits: Reduces memory stalls during header parsing.

✅ Pipeline-Friendly Memory Layout
-----------------------------------

Use rte_pktmbuf_pool_create() to allocate mbufs from hugepages.

Avoid malloc/free per packet → use a pkt_view pool (or embed pkt_view in mbuf private area).

Actions needed
Use contiguous rte_mempool for mbufs (hugepages, cache-aligned).
Keep pkt_view structs in heap, but minimal per-packet allocation.
Avoid dynamic malloc inside main loop.
For tunnels: inner_pkt also points to zero-copy mbuf if possible.
Benefits: CPU-friendly memory access, avoids heap fragmentation.

✅ Zero-Copy

pkt_view wraps the rte_mbuf directly.
No memcpy() for mbuf packets.
pv->backing points to mbuf; capture_free() frees it correctly.
Heap/PCAP mode still supported.
Benefits: Eliminates memory copy overhead, huge speed boost.

✅ Parallelism

RX core → Parsing core(s) → AI inference core(s).

Use rte_ring for lockless handoff.

Each stage runs on separate lcores (NUMA-aware).

✅ Vectorization

Use DPDK’s SIMD intrinsics (rte_mov16, rte_mov256) for parsing headers in batches.

Example: process 4 Ethernet headers at once with AVX2.

✅ Offloads

Enable NIC offloads: checksum, VLAN strip, RSS → free CPU cycles.

5. Batch Header Parsing

Process N headers in vectorized loops if AI analysis allows.

Example: parse Ethernet/IP/UDP headers of 32 packets in one loop.

Can use compiler hints like __builtin_prefetch() or SIMD (optional advanced).

Benefits: CPU vectorization, better instruction-level parallelism.

6. Multithreaded Pipeline (Advanced)

RX Thread: polls DPDK, wraps mbufs into pkt_view, enqueue to lock-free ring.

Parser Thread(s): dequeues packets, parses headers, updates stats, talks to AI engine.

AI/Stats Thread: receives parsed metadata for inference and aggregation.

DPDK rings (rte_ring) for inter-thread communication (lock-free, cache-friendly).

Benefits: Near-linear scalability on multi-core CPUs, avoids RX blocking.

7. Bulk Freeing / Deferred Free

For high-throughput bursts, free packets in bulk (rte_pktmbuf_free_bulk) instead of one by one.

Can batch inner_pkt frees too if multiple tunnels are processed together.

Benefits: Reduces memory management overhead.

8. Tuning BURST_SIZE and Mempool Parameters

BURST_SIZE: balance between L1 cache size and throughput (32–128 typical).

Mempool size: must accommodate bursts + max inflight packets.

Cache size: match CPU L1/L2 caches.

Benefits: Prevents packet drops and cache thrashing.

9. Optional: Hugepage & NUMA Optimizations

Pin RX queues to cores with same NUMA node as NIC.

Allocate mempools on NUMA-local memory.

Align pkt_view arrays to cache lines if batching.

Benefits: Low latency, high throughput, reduces cross-NUMA memory penalties.

10. Optional: Vectorized/AI-Friendly Packet Format

Keep minimal header offsets inside pkt_view.

Avoid repeated parsing: store Ethernet/IP/UDP/TCP offsets once.

AI engine reads structured packet metadata directly.

Benefits: Reduces CPU cycles spent parsing same headers repeatedly.