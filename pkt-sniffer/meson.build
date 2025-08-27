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
]

deps = []   # always initialize

# Choose backend
if capture_backend == 'afp'
  sources += 'capture_afp.c'
  deps += [dependency('pcap', required: true)]
elif capture_backend == 'dpdk'
  sources += 'capture_dpdk.c'
  deps += [dependency('libdpdk', required: true)]
else
  error('Unsupported capture backend: ' + capture_backend)
endif

executable('pkt-sniffer',
           sources,
           dependencies: deps,
           install: true)
