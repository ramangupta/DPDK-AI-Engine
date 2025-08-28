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
  'capture_common.c',
]

deps = []

if capture_backend == 'afp'
  sources += ['capture_afp.c', 'time_afp.c']
  deps += [dependency('pcap')]
elif capture_backend == 'pcap'
  sources += ['capture_pcap.c', 'time_pcap.c']
  deps += [dependency('pcap')]
elif capture_backend == 'dpdk'
  sources += ['capture_dpdk.c', 'time_dpdk.c']
  deps += [dependency('libdpdk')]
  add_project_arguments('-DUSE_DPDK', language: 'c')
else
  error('Unsupported capture backend: ' + capture_backend)
endif

executable('pkt-sniffer',
           sources,
           dependencies: deps,
           install: true)
