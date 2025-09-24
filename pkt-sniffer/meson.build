project('pkt-sniffer', 'c',
        version: '0.1',
        default_options: ['c_std=gnu11'])

capture_backend = get_option('capture_backend')

# --- Dependencies ---
deps = []
jsonc_dep = dependency('json-c', required: true)
pcap_dep  = dependency('pcap', required: true)
deps += [jsonc_dep, pcap_dep]

# --- Source groups ---
engine_src = []

if capture_backend == 'afp'
  engine_src += files(
    'engine/capture_afp.c',
    'engine/time/time_afp.c',
  )
  deps += [pcap_dep]

elif capture_backend == 'pcap'
  engine_src += files(
    'engine/capture_pcap.c',
    'engine/time/time_pcap.c',
  )
  deps += [pcap_dep]

elif capture_backend == 'dpdk'
  engine_src += files(
    'engine/capture_dpdk.c',
    'engine/time/time_dpdk.c',
  )
  deps += [dependency('libdpdk')]
  add_global_arguments('-DUSE_DPDK', language: 'c')

  if get_option('buildtype') == 'debug'
    add_project_arguments(
      '-fsanitize=address',
      '-fno-omit-frame-pointer',
      '-g',
      '-O0',
      '-fno-stack-protector',
      language: 'c'
    )
    add_project_link_arguments('-fsanitize=address', language: 'c')
  endif

else
  error('Unsupported capture backend: ' + capture_backend)
endif

parser_src = files(
  'parsers/frag_ipv4.c',
  'parsers/frag_ipv6.c',
  'parsers/tcp_reass.c',
  'parsers/parse_arp.c',
  'parsers/parse_eth.c',
  'parsers/parse_ipv4.c',
  'parsers/parse_ipv6.c',
  'parsers/parse_l4.c',
  'parsers/parse_tls.c',
  'parsers/parse_http.c',
  'parsers/parse_tunnel.c',
  'parsers/parse_dns.c',
  'parsers/parse_dhcp.c',
  'parsers/parse_tls_cert.c',
)

stats_src = files(
  'stats/stats.c',
  'stats/stats_json.c',
)

utils_src = files(
  'utils/filter.c',
  'utils/flows.c',
  'utils/talkers.c',
  'utils/utils.c',
  'utils/debug.c',
  'utils/pcap_writer.c',
  'utils/sniffer_signal.c',
)

ai_src = files(
  'ai/placeholder.c',
)

market_src = files(
  'parsers/market/parse_fix.c',
  'parsers/market/parse_itch.c',
  'parsers/market/parse_sbe.c',
  'parsers/market/parse_data.c',
  'anomaly/anomaly.c',
  'anomaly/fno_data.c',
  'anomaly/futures_options.c',
  'anomaly/rule_based/burst_detection.c',
  'anomaly/rule_based/inter_arrival.c',
  'anomaly/rule_based/protocol_coverage.c',
)

all_src = engine_src + parser_src + stats_src + utils_src + ai_src +  market_src + files(
  'main.c',
  'cli.c',
)

# --- Include dirs ---
inc = include_directories(
  '.',
  'engine',
  'engine/time',
  'parsers',
  'stats',
  'utils',
  'ai',
)

# --- Target ---
executable('pkt-sniffer',
           all_src,
           include_directories: inc,
           dependencies: deps,
           install: true)

# --- Synthetic test executables ---
synthetic_src = engine_src + parser_src + stats_src + utils_src + ai_src + market_src + files(
  'parsers/market/gen_fix.c',
  'parsers/market/gen_itch.c',
  'parsers/market/gen_sbe.c',
  'parsers/market/gen_main.c',
)

executable('synthetic', synthetic_src,
           include_directories: inc,
           dependencies: deps)



# --- Build-time hints ---
message('==========================================================')
message(' Selected capture backend: ' + capture_backend)
if capture_backend == 'dpdk'
  message(' Usage: sudo ./build/pkt-sniffer -l 0-1 -n 4 --vdev=...')
  message(' Note: Requires a DPDK-supported NIC (not Wi-Fi).')
elif capture_backend == 'afp'
  message(' Usage: sudo ./build/pkt-sniffer --no-pci -vdev=net_af_packet0,iface=<ifname>')
  message(' Example: sudo ./build/pkt-sniffer --no-pci -vdev=net_af_packet0,iface=wlo1')
elif capture_backend == 'pcap'
  message(' Usage: ./build/pkt-sniffer --pcap <file.pcap>')
endif
message('==========================================================')
