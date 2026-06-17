package main

/*
#cgo pkg-config: libdpdk
#cgo CFLAGS: -O3
#cgo LDFLAGS: -lm

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_ring.h>
#include <rte_mempool.h>

// Flattened, cache-aligned struct perfectly compatible with cgo
struct __attribute__((__aligned__(64))) packet_meta {
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  ip_version; 
};

struct rte_ring *dump_ring = NULL;
struct rte_mempool *meta_pool = NULL;

int init_dpdk_secondary(int argc, char **argv) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) return -1;

    dump_ring = rte_ring_lookup("DUMP_RING");
    meta_pool = rte_mempool_lookup("META_POOL");

    if (!dump_ring || !meta_pool) return -2;
    return 0;
}

struct packet_meta* dequeue_meta() {
    struct packet_meta *meta;
    if (rte_ring_sc_dequeue(dump_ring, (void **)&meta) == 0) {
        return meta;
    }
    return NULL;
}

void free_meta(struct packet_meta *meta) {
    rte_mempool_put(meta_pool, meta);
}
*/
import "C"
import (
	"fmt"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"
)

const samplingRate = 10
const dumpIntervalSec = 10

func main() {
	args := []string{"go_analyzer", "--proc-type=secondary"}
	cArgs := make([]*C.char, len(args))
	for i, arg := range args {
		cArgs[i] = C.CString(arg)
		defer C.free(unsafe.Pointer(cArgs[i]))
	}

	ret := C.init_dpdk_secondary(C.int(len(args)), &cArgs[0])
	if ret == -1 {
		fmt.Println("[Fatal] Failed to initialize DPDK EAL.")
		os.Exit(1)
	} else if ret == -2 {
		fmt.Println("[Fatal] Could not find DUMP_RING or META_POOL. Is C Forwarder running?")
		os.Exit(1)
	}

	fmt.Println("[Analyzer] Successfully attached to C Forwarder shared memory.")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// CHANGE 1: Use a fixed array as the map key instead of a string
	peerMap := make(map[[16]byte]uint64)
	var totalSampled uint64 = 0
	
	ticker := time.NewTicker(dumpIntervalSec * time.Second)
	defer ticker.Stop()

	fmt.Printf("[Analyzer] Starting analysis loop (Reporting every %d seconds)...\n", dumpIntervalSec)

	for {
		select {
		case <-sigChan:
			fmt.Println("\n[Analyzer] Shutting down...")
			return

		case <-ticker.C:
			printMetrics(peerMap, totalSampled, dumpIntervalSec)
			// CHANGE 2: Re-initialize with the new array type
			peerMap = make(map[[16]byte]uint64)
			totalSampled = 0

		default:
			cMeta := C.dequeue_meta()
			if cMeta == nil {
				time.Sleep(time.Microsecond)
				continue
			}

			totalSampled++

			// CHANGE 3: The Zero-Allocation Trick
			// Cast the C memory directly to a Go array pointer. 
			// Dereferencing it copies the 16 bytes straight into the map without hitting the heap.
			ipArrayPtr := (*[16]byte)(unsafe.Pointer(&cMeta.src_ip[0]))
			peerMap[*ipArrayPtr]++

			C.free_meta(cMeta)
		}
	}
}

// CHANGE 4: Update the function signature to accept the new map type
func printMetrics(peerMap map[[16]byte]uint64, totalSampled uint64, seconds int) {
	fmt.Printf("\n--- TRAFFIC METRICS REPORT (Last %d Seconds) ---\n", seconds)
	if totalSampled == 0 {
		fmt.Println("No packets dumped in this window.")
		fmt.Println("---------------------------------------------------")
		return
	}

	var entropy float64 = 0.0
	for _, count := range peerMap {
		probability := float64(count) / float64(totalSampled)
		entropy -= probability * math.Log2(probability)
	}

	fmt.Printf("Total Packets Sampled : %d\n", totalSampled)
	fmt.Printf("Estimated Wire Pkts   : %d\n", totalSampled*samplingRate)
	fmt.Printf("Unique Source IPs     : %d\n", len(peerMap))
	fmt.Printf("Traffic Source Entropy: %.4f\n", entropy)
	fmt.Println("---------------------------------------------------")
}