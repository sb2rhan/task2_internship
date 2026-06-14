project('packet_forwarder100G', 'c',
        version : '1.0.0',
        default_options : ['warning_level=3', 'werror=true', 'optimization=3'])

# Find the DPDK dependency
dpdk_dep = dependency('libdpdk', required : true)
sources = files('main.c')

PacketForwarder100G = executable(
        'packet_forwarder100G',
        sources,
        dependencies: dpdk_dep,
        install : false)

test('test', PacketForwarder100G)