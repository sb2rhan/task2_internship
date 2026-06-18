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

const samplingRate    = 10
const dumpIntervalSec = 10

// ewmaAlpha=0.2 weights roughly the last 4–5 windows as the baseline.
const ewmaAlpha = 0.2

// Alert when either entropy metric drops more than 2 bits below its EWMA baseline.
// 2 bits is large enough to ignore normal variance but catches focused floods.
const alertDropBits = 2.0

// EWMA state; -1.0 means uninitialised — first window sets the baseline directly.
var ewmaShannon = -1.0
var ewmaRenyi   = -1.0

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

	peerMap := make(map[[16]byte]uint64)
	var totalSampled uint64

	ticker := time.NewTicker(dumpIntervalSec * time.Second)
	defer ticker.Stop()

	fmt.Printf("[Analyzer] Starting analysis loop (reporting every %d seconds)...\n", dumpIntervalSec)

	for {
		select {
		case <-sigChan:
			fmt.Println("\n[Analyzer] Shutting down...")
			return

		case <-ticker.C:
			printMetrics(peerMap, totalSampled, dumpIntervalSec)
			peerMap = make(map[[16]byte]uint64)
			totalSampled = 0

		default:
			cMeta := C.dequeue_meta()
			if cMeta == nil {
				time.Sleep(time.Microsecond)
				continue
			}

			totalSampled++
			// Direct cast into hugepage memory — no heap allocation, no copy.
			ipArrayPtr := (*[16]byte)(unsafe.Pointer(&cMeta.src_ip[0]))
			peerMap[*ipArrayPtr]++
			C.free_meta(cMeta)
		}
	}
}

func printMetrics(peerMap map[[16]byte]uint64, totalSampled uint64, seconds int) {
	fmt.Printf("\n--- TRAFFIC METRICS REPORT (Last %d Seconds) ---\n", seconds)
	if totalSampled == 0 {
		fmt.Println("No packets sampled in this window.")
		fmt.Println("---------------------------------------------------")
		return
	}

	n := float64(totalSampled)

	// Shannon entropy: H = -Σ p·log₂(p)
	// Maximised for uniform traffic (~log₂(unique IPs)); collapses toward 0 in a flood.
	var shannon float64
	// Rényi entropy α=2: H₂ = -log₂(Σ p²)
	// More sensitive to dominant sources than Shannon — a single IP sending 90 % of
	// traffic shows a larger drop here than in Shannon. Also cheaper: no log per IP.
	var sumSq float64
	for _, count := range peerMap {
		p := float64(count) / n
		shannon -= p * math.Log2(p)
		sumSq += p * p
	}
	renyi := -math.Log2(sumSq)

	// Update EWMA baselines (or initialise on first window).
	if ewmaShannon < 0 {
		ewmaShannon = shannon
		ewmaRenyi   = renyi
	} else {
		ewmaShannon = ewmaAlpha*shannon + (1-ewmaAlpha)*ewmaShannon
		ewmaRenyi   = ewmaAlpha*renyi   + (1-ewmaAlpha)*ewmaRenyi
	}

	fmt.Printf("Total Packets Sampled : %d\n", totalSampled)
	fmt.Printf("Estimated Wire Pkts   : %d\n", totalSampled*samplingRate)
	fmt.Printf("Unique Source IPs     : %d\n", len(peerMap))
	fmt.Printf("Shannon Entropy       : %.4f bits  (baseline EWMA: %.4f)\n", shannon, ewmaShannon)
	fmt.Printf("Rényi Entropy (α=2)   : %.4f bits  (baseline EWMA: %.4f)\n", renyi, ewmaRenyi)

	// Anomaly detection: alert when either metric falls significantly below its baseline.
	shannonDrop := ewmaShannon - shannon
	renyiDrop   := ewmaRenyi   - renyi
	anomaly := shannonDrop > alertDropBits || renyiDrop > alertDropBits
	if anomaly {
		fmt.Println()
		fmt.Println("*** ANOMALY DETECTED ***")
		if shannonDrop > alertDropBits {
			fmt.Printf("  Shannon drop : %.4f bits below baseline (threshold %.1f)\n", shannonDrop, alertDropBits)
		}
		if renyiDrop > alertDropBits {
			fmt.Printf("  Rényi drop   : %.4f bits below baseline (threshold %.1f)\n", renyiDrop, alertDropBits)
		}
		fmt.Println("  Possible cause: volumetric flood or scanning from concentrated sources.")
	}

	fmt.Println("---------------------------------------------------")
}