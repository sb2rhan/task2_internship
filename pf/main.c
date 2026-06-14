#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_lcore.h>

#define BURST_SIZE 64
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define META_POOL_SIZE 16384

// 64-byte cache-aligned 5-tuple structure supporting IPv4 and IPv6
// Must exactly match the struct defined in the Go Analyzer!
struct __attribute__((__aligned__(64))) packet_meta {
    union {
        uint32_t ipv4_src;
        uint8_t  ipv6_src[16];
    };
    union {
        uint32_t ipv4_dst;
        uint8_t  ipv6_dst[16];
    };
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  ip_version;
};


struct rte_mempool *pktmbuf_pool = NULL;
struct rte_mempool *meta_pool = NULL;
struct rte_ring *dump_ring = NULL;

volatile bool keep_running = true;
uint32_t sampling_rate = 10; // Must match the sampling rate in Go to estimate total wire traffic

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n[Forwarder] Shutting down gracefully...\n");
        keep_running = false;
    }
}


/* * High-speed Inline Parser for IPv4 and IPv6
 */
static inline void parse_5tuple(const struct rte_mbuf *m, struct packet_meta *meta) {
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);

    if (eth_type == RTE_ETHER_TYPE_IPV4) {
        struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
        meta->ip_version = 4;
        meta->ipv4_src = ipv4_hdr->src_addr;
        meta->ipv4_dst = ipv4_hdr->dst_addr;
        meta->proto  = ipv4_hdr->next_proto_id;

        if (meta->proto == IPPROTO_UDP) {
            struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1);
            meta->src_port = udp_hdr->src_port;
            meta->dst_port = udp_hdr->dst_port;
        } else if (meta->proto == IPPROTO_TCP) {
            struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ipv4_hdr + 1);
            meta->src_port = tcp_hdr->src_port;
            meta->dst_port = tcp_hdr->dst_port;
        }
    } else if (eth_type == RTE_ETHER_TYPE_IPV6) {
        struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
        meta->ip_version = 6;
        rte_memcpy(meta->ipv6_src, &ipv6_hdr->src_addr, 16);
        rte_memcpy(meta->ipv6_dst, &ipv6_hdr->dst_addr, 16);
        meta->proto = ipv6_hdr->proto;

        if (meta->proto == IPPROTO_UDP) {
            struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ipv6_hdr + 1);
            meta->src_port = udp_hdr->src_port;
            meta->dst_port = udp_hdr->dst_port;
        } else if (meta->proto == IPPROTO_TCP) {
            struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ipv6_hdr + 1);
            meta->src_port = tcp_hdr->src_port;
            meta->dst_port = tcp_hdr->dst_port;
        }
    }
}

/*
 * Data-Plane Forwarding Loop (Runs on isolated core)
 */
int lcore_forwarder(__attribute__((unused)) void *arg) {
    uint16_t port = 0; // Assuming port 0 is handling RX/TX for this example
    struct rte_mbuf *bufs[BURST_SIZE];
    uint32_t pkt_count = 0;

    printf("[Forwarder] Processing 100G fast-path on Core %u (Port %u)\n", rte_lcore_id(), port);

    while (keep_running) {
        uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
        if (unlikely(nb_rx == 0)) continue;

        // Prefetch packet data into CPU cache
        for (int i = 0; i < nb_rx; i++) {
            rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));
        }

        // Sampling and extraction
        for (int i = 0; i < nb_rx; i++) {
            pkt_count++;
            if ((pkt_count % sampling_rate) == 0) {
                struct packet_meta *meta;

                // Fetch a metadata block from the shared mempool
                if (rte_mempool_get(meta_pool, (void **)&meta) == 0) {
                    parse_5tuple(bufs[i], meta);

                    // Enqueue to the lockless ring for the Go Analyzer
                    if (unlikely(rte_ring_sp_enqueue(dump_ring, meta) < 0)) {
                        rte_mempool_put(meta_pool, meta); // Drop metadata if ring is full
                    }
                }
            }
        }

        // Reflect traffic immediately back out
        uint16_t nb_tx = rte_eth_tx_burst(port, 0, bufs, nb_rx);

        // Free unsent packets to prevent memory leaks
        if (unlikely(nb_tx < nb_rx)) {
            for (uint16_t buf = nb_tx; buf < nb_rx; buf++) {
                rte_pktmbuf_free(bufs[buf]);
            }
        }
    }
    return 0;
}

/*
 * EAL Setup and Primary Process Initialization
 */
int main(int argc, char **argv) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 1. Initialize DPDK EAL as Primary Process
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL Initialization\n");


    // 2. Allocate Shared Memory Resources
    // These strings ("MBUF_POOL", "META_POOL", "DUMP_RING") must exactly match what Go looks up
    pktmbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE,
                                           0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!pktmbuf_pool) rte_exit(EXIT_FAILURE, "Cannot initialize mbuf pool\n");

    meta_pool = rte_mempool_create("META_POOL", META_POOL_SIZE, sizeof(struct packet_meta),
                                   0, 0, NULL, NULL, NULL, NULL, rte_socket_id(), 0);
    if (!meta_pool) rte_exit(EXIT_FAILURE, "Cannot initialize metadata pool\n");

    dump_ring = rte_ring_create("DUMP_RING", META_POOL_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!dump_ring) rte_exit(EXIT_FAILURE, "Cannot create lockless ring\n");


    // 3. Configure Network Port
    uint16_t port_id = 0; // Hardcoded to port 0 for demonstration
    struct rte_eth_conf port_conf = { .rxmode = { .max_lro_pkt_size = RTE_ETHER_MAX_LEN } };

    if (rte_eth_dev_configure(port_id, 1, 1, &port_conf) < 0)
        rte_exit(EXIT_FAILURE, "Cannot configure port %u\n", port_id);

    if (rte_eth_rx_queue_setup(port_id, 0, 1024, rte_eth_dev_socket_id(port_id), NULL, pktmbuf_pool) < 0)
        rte_exit(EXIT_FAILURE, "RX Queue configuration failed\n");

    if (rte_eth_tx_queue_setup(port_id, 0, 1024, rte_eth_dev_socket_id(port_id), NULL) < 0)
        rte_exit(EXIT_FAILURE, "TX Queue configuration failed\n");

    if (rte_eth_dev_start(port_id) < 0)
        rte_exit(EXIT_FAILURE, "Cannot start port %u\n", port_id);

    rte_eth_promiscuous_enable(port_id);
    printf("[Forwarder] Port %u initialized and running.\n", port_id);


    // 4. Launch the Forwarder Loop on a worker core
    unsigned int lcore_id = rte_get_next_lcore(rte_lcore_id(), 0, 0);
    if (lcore_id == RTE_MAX_LCORE) {
        // Fallback to main core if no worker cores are provided via EAL args
        lcore_forwarder(NULL);
    } else {
        rte_eal_remote_launch(lcore_forwarder, NULL, lcore_id);
        rte_eal_mp_wait_lcore();
    }


    // 5. Teardown
    printf("\n[Forwarder] Stopping network ports...\n");
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    printf("[Forwarder] Cleaning up EAL resources...\n");
    int cleanup_ret = rte_eal_cleanup();
    if (cleanup_ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL cleanup: %s\n", rte_strerror(rte_errno));
    }

    printf("[Forwarder] Clean exit.\n");
    return 0;
}