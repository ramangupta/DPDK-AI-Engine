project('pkt-sniffer', 'c',
        version: '0.1',
        default_options: ['c_std=gnu11'])

capture_backend = get_option('capture_backend')

sources = [
  'main.c',
  'parse_eth.c',
  'parse_ipv4.c',
  'parse_ipv6.c',
  'parse_l4.c',
  'parse_dns.c',
  'stats.c',
  'utils.c',
  'talkers.c',
  'frag_ipv4.c',
  'frag_ipv6.c',
  'capture_common.c',
  'parse_arp.c',
  'parse_dhcp.c',
  'parse_http.c',
  'parse_tls.c',
  'cli.c',
  'filter.c',
  'pcap_writer.c',
  'sniffer_signal.c',
  'tcp_reass.c',
  'flows.c',
  'parse_tunnel.c',
  'parse_tls_cert.c',
  'stats_json.c',
  'debug.c',
]

deps = []

# Dependencies
jsonc_dep = dependency('json-c', required: true)
pcap_dep  = dependency('pcap', required: true)

if capture_backend == 'afp'
  sources += ['capture_afp.c', 'time_afp.c']
  deps += [pcap_dep]

elif capture_backend == 'pcap'
  sources += ['capture_pcap.c', 'time_pcap.c']
  deps += [pcap_dep]

elif capture_backend == 'dpdk'
  sources += ['capture_dpdk.c', 'time_dpdk.c']
  deps += [dependency('libdpdk')]
  add_global_arguments('-DUSE_DPDK', language: 'c')

  # Enable ASan only for debug builds
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

# Add json-c and pcap globally
deps += [jsonc_dep, pcap_dep]

executable('pkt-sniffer',
           sources,
           dependencies: deps,
           install: true)

# Build-time hints
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
