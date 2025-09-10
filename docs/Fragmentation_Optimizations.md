Pv6 Fragmentation / Reassembly Optimizations
1. Pre-allocated Context Pool

All fragment contexts (frag_ctx6_t) are pre-allocated in a static array:

static frag_ctx6_t table[MAX_FRAG_CTX];

Avoids per-packet malloc overhead.
MAX_FRAG_CTX can be tuned; pool exhaustion is unlikely under real-world traffic.
Free-list allows O(1) allocation and deallocation.

2. Hash-Based Context Lookup

Contexts are inserted into a hash table on allocation:

static frag_ctx6_t* hash_table[HASH_SIZE];


Lookup uses a simple XOR hash of src/dst addresses, ID, proto:

hash = src_bytes ^ dst_bytes ^ id ^ proto;


Chaining via next pointers in each context.
Reduces linear scan over entire pool to average O(1) hash lookup.

3. Active List for Timeout Management

All active contexts are linked via active_list.

Periodic stale flushes (frag_ipv6_flush_stale()) traverse only active contexts instead of entire pool.

Minimizes overhead for timeout-based cleanup.

4. Efficient Payload Management

Payloads are dynamically resized with exponential growth:

new_cap = max(2048, old_cap*2) until >= required;


Reduces frequency of realloc.

Tracks statistics for expansions and drops.

5. Interval Tracking for Reassembly

Fragment intervals stored in sorted array iv[MAX_INTERVALS].

New fragments are merged with existing intervals.

intervals_cover_full() quickly checks if full payload is assembled.

Guarantees correct reassembly with minimal operations.

6. Stale & Shutdown Handling

Stale fragments are flushed after timeout (FRAG_V6_TIMEOUT_NS) via active list.

At shutdown, all remaining fragments are flushed safely.

Avoids memory leaks and ensures accurate stats.

7. Performance Results
Before Optimizations

IPv6 contexts allocated: ~25k

Reassembled: ~8.5k

Stale timeouts: 4–6k

Throughput: ~211–217 Mbps

After Full Optimizations

Drops (alloc/realloc): 0

Stale timeouts: ~2

Throughput: ~31444 pps, 211 Mbps

Memory & CPU usage significantly reduced

8. Key Benefits

Minimal allocation overhead → no per-fragment malloc in hot path.

Fast lookup → hash table replaces linear scan.

O(1) free/allocate via free-list.

Efficient flush → active list ensures stale fragments are cleared without scanning full table.

Scales well for realistic traffic, even under tens of thousands of fragments.

Highly predictable performance, with near-zero drops in stress tests.