1) What happens if we crank BURST_SIZE to max?

rte_eth_rx_burst(port, queue, pkts, BURST_SIZE) fetches packets already sitting in NIC RX ring.
NIC RX rings usually have 512, 1024, or 2048 descriptors (configurable).
If you set BURST_SIZE = 1024, you might pull everything in the ring in one go.

👉 That sounds fast, but:

CPU cache miss risk: Handling 1024 packet descriptors at once may blow out L1/L2 caches.
Latency vs throughput: Big bursts improve throughput but increase per-packet latency. AI use cases sometimes need low jitter, not just raw throughput.
Diminishing returns: Past ~64, you don’t gain much, because the RX ring is refilled anyway.

Recommended Strategy

Instead of “insanely max BURST_SIZE”, the best-practice is:

Start with 32 or 64 → usually optimal for CPU cache.
Benchmark at 128 → check if throughput increases without latency explosion.
Only go >128 if you’re in offline batch processing mode (not real-time AI).

2) Prefetch 

Why prefetch helps

DPDK packets live in hugepages, so accessing them can still cause cache misses. If you know you’ll process n packets in a burst:

You can prefetch the next packet headers while processing the current one.

This reduces load-to-use latency, especially for AI workloads where you parse and analyze headers intensively.