# DPDK 100G Packet Forwarder & Go Analyzer

This project implements a high-performance, 100Gbps packet processing pipeline using a dual-process architecture. It consists of a **C-based DPDK Primary Process** that handles line-rate packet forwarding and header parsing, and a **Go-based DPDK Secondary Process** that asynchronously analyzes traffic metadata (like Shannon Entropy and unique IP counts) via shared memory.

## Architecture Overview

The pipeline leverages DPDK's Multi-Process architecture to separate the raw packet forwarding logic from the analytical business logic:

1. **The C Forwarder (Primary Process):** Receives packets from the NIC, parses the 5-tuple metadata (IPv4/IPv6), and forwards the packets back out. It places a sampled subset (1-in-10) of the metadata into a lockless shared memory ring (`DUMP_RING`).
2. **The Go Analyzer (Secondary Process):** Attaches to the same hugepage memory segment. It dequeues metadata from the `DUMP_RING` in a highly optimized, zero-allocation loop, calculating real-time traffic statistics without interrupting the forwarding path.

---

## Prerequisites

### 1. System Dependencies
You need standard DPDK build tools, PCAP libraries (for local testing), and Go.

```bash
sudo apt-get update
sudo apt-get install build-essential meson ninja-build pkg-config libpcap-dev tcpdump
```

## Building the Project

### Building the C Forwarder
The C application uses Meson and Ninja.

```bash
cd ./pf
meson setup build
ninja -C build
```

### Building the Go Analyzer
The Go application uses cgo to link against the DPDK libraries.
```bash
cd ./analyzer
CGO_CFLAGS_ALLOW="-mrtm" go build -o go_analyzer main.go
```

## Testing Locally (Laptop / PCAP Mode)
You do not need a physical 100G NIC to test or develop this pipeline. You can use DPDK Virtual Devices (`vdev`) to simulate hardware using `.pcap` files.

### 1. Capture Test Traffic
Capture strict-sized packets (max 1514 bytes) from your local interface to prevent DPDK multi-segment buffer crashes during infinite loop testing.
```bash
# Replace 'wlan0' or 'eth0' with your active network interface
sudo tcpdump -i wlan0 -w input.pcap -c 5000 -s 1514
```

### 2. Run the C Forwarder (Stress Test Mode)
Launch the forwarder using the PCAP poll-mode driver. This command instructs DPDK to infinitely loop the 5,000 packets into the engine as fast as your CPU cache can handle, discarding the output to /dev/null.

```bash
sudo ./build/packet_forwarder100G \
    -l 0-1 -n 1 \
    --no-pci \
    --vdev 'net_pcap0,rx_pcap=input.pcap,infinite_rx=1,tx_pcap=/dev/null' \
    --proc-type=primary
```

### 3. Run the Go Analyzer
In a separate terminal, launch the Go analyzer. It will automatically attach to the Primary Process's memory and begin reporting metrics.

```bash
sudo ./go_analyzer
```

## Deploying to the 100G Server

When running on the actual server, you must configure Hugepages and bind the NICs to the `vfio-pci` driver.

### 1. Configure Hugepages
DPDK requires reserved memory to bypass the kernel. To allocate and mount 1GB Hugepages:
```bash
echo 4 | sudo tee /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
sudo mkdir -p /mnt/huge_1gb
sudo mount -t hugetlbfs -o pagesize=1G none /mnt/huge_1gb
```

### 2. Bind the NICs
Check your device PCI addresses and bind them to DPDK:
```bash
sudo dpdk-devbind.py --status
sudo dpdk-devbind.py -b vfio-pci 0000:04:00.0
```

### 3. Run the Application
Launch the Forwarder, explicitly pointing to the 1GB Hugepage mount, followed by the Analyzer.
```bash
# Terminal 1: C Forwarder
sudo ./build/packet_forwarder100G -l 0-3 -n 4 --huge-dir=/mnt/huge_1gb --proc-type=primary

# Terminal 2: Go Analyzer
sudo ./go_analyzer
```
To validate performance at 100G, use a traffic generator like **Cisco TRex** connected back-to-back with the DUT (Device Under Test).

## Performance Monitoring & Tuning
This pipeline includes built-in telemetry to identify bottlenecks. If the system is under extreme load, packets will drop in one of two places:
- **NIC Drops (imissed)**: The hardware NIC dropped packets because the C Forwarder's RX loop was too slow. **Fix**: Pin the C Forwarder to more CPU cores (-l 0-7) and enable Receive Side Scaling (RSS) on the NIC to distribute the load across multiple RX queues.
- **Ring Drops (ring_drops)**: The C Forwarder successfully processed the packet, but the DUMP_RING was full because the Go Analyzer was too slow at dequeuing metadata. **Fix**: Increase the size of the DUMP_RING (e.g., from 8192 to 262144 slots), or decrease the packet sampling rate.

