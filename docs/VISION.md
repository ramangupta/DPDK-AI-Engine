🔮 What This Can Become

The Wireshark of AI-era — not just packets → flows, but packets → insights.

The Zeek of modern networks — lightweight DSL for defining custom detections.

The Kafka of network telemetry — structured events streaming to ML pipelines.

The Bloomberg Terminal for raw packet feeds — decoding market signals before they hit the tape.


DPDK-AI-Engine/
├── pkt-sniffer/                # Main binary (CLI entrypoint)
│   ├── main.c
│   ├── cli.c / cli.h           # CLI handling
│   └── Makefile / meson.build
│
├── src/
│   ├── engine/                 # Core engine: capture + processing
│   │   ├── capture_dpdk.c
│   │   ├── capture_pcap.c
│   │   ├── capture_afpacket.c
│   │   ├── pipeline.c
│   │   └── time/               # abstraction layer
│   │       ├── time_dpdk.c
│   │       ├── time_pcap.c
│   │       ├── time_afp.c
│   │       └── tsc.h
│   │
│   ├── parsers/                # Protocol-specific parsers
│   │   ├── eth.c / eth.h
│   │   ├── ipv4.c / ipv4.h
│   │   ├── ipv6.c / ipv6.h
│   │   ├── tcp.c / tcp.h
│   │   ├── udp.c / udp.h
│   │   ├── http.c / http.h
│   │   └── tls.c / tls.h
│   │
│   ├── exporters/              # Data output sinks
│   │   ├── console_exporter.c
│   │   ├── json_exporter.c
│   │   ├── kafka_exporter.c    # future
│   │   └── db_exporter.c       # future
│   │
│   ├── stats/                  # Metrics + perf
│   │   ├── stats.c / stats.h
│   │   ├── latency.c / latency.h
│   │   └── perf.c / perf.h
│   │
│   ├── ai/                     # Future AI/ML integration
│   │   ├── anomaly.c / anomaly.h
│   │   └── intent.c / intent.h
│   │
│   └── utils/                  # Shared helpers
│       ├── log.c / log.h
│       ├── filter.c / filter.h
│       └── memory.c / memory.h
│
├── include/                    # Public headers
│
├── tests/                      # Unit + integration tests
│
├── scripts/                    # Helper scripts (setup hugepages, run, etc.)
│
├── docs/                       # Documentation (README, ARCHITECTURE.md)
│
└── README.md
