# Generate 2048-bit RSA private key
openssl genrsa -out server.key 2048


openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/C=IN/ST=State/L=City/O=TestOrg/OU=IT/CN=localhost"


  
pkt-sniffer/
├── ai/                 # ML/AI models, feature extraction, anomaly detection
│   └── placeholder.c
├── build/              # meson/ninja build dir
├── capture_examples/   # example pcap/afp/dpdk capture setups
├── engine/             # capture engines + timing (dpdk, afp, pcap)
│   ├── capture_dpdk.c
│   ├── capture_pcap.c
│   ├── capture_afp.c
│   └── time/
│       ├── time_dpdk.c
│       ├── time_pcap.c
│       └── time_afp.c
├── logs/               # runtime logs
├── parsers/            # protocol-specific parsers + reassembly
│   ├── parse_eth.c/h
│   ├── parse_ipv4.c/h
│   ├── parse_ipv6.c/h
│   ├── parse_l4.c/h
│   ├── parse_http.c/h
│   ├── parse_tls.c/h
│   ├── parse_tls_cert.c/h
│   ├── parse_dns.c/h
│   ├── parse_dhcp.c/h
│   ├── parse_arp.c/h
│   ├── parse_tunnel.c/h
│   ├── frag_ipv4.c/h
│   ├── frag_ipv6.c/h
│   └── tcp_reass.c/h
├── stats/              # statistics collection, JSON export, latency, perf
│   ├── stats.c/h
│   ├── stats_json.c/h
│   ├── latency.c/h
│   └── perf.c/h
├── tests/              # unit tests, regression pcaps
├── utils/              # helpers, signal handling, debug, pcap writer
│   ├── utils.c/h
│   ├── flows.c/h
│   ├── filter.c/h
│   ├── talkers.c/h
│   ├── debug.c/h
│   ├── pcap_writer.c/h
│   └── sniffer_signal.c/h
├── tmp/                # scratch, generated intermediate files
├── cli.c/h             # CLI interface
├── main.c              # entry point
├── meson.build         # main build script
├── meson_options.txt   # meson options (capture_backend, etc.)
├── sniffer_proto.h     # protocol/struct definitions shared across modules
├── tunnel_types.h      # tunnel types definitions
├── tsc.h               # timestamp counter utils
└── backup.c            # scratch / old code
