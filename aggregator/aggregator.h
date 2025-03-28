#ifndef _AGGREGATOR_H
#define _AGGREGATOR_H

#include <errno.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_per_lcore.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>

#include "util.h"
#define MAX_PKT_BURST 32
#define MAX_FLOW_PER_CORE 4096
#define MAX_AGGREGATE_PER_FLOW 16
#define READY_QUEUE_RESERVED 4096
#define MAX_CORE_NUM 40
#define NB_MBUF 8192
#define MEMPOOL_CACHE_SIZE 256
#define TOTAL_PACKET_COUNT (MAX_PKT_BURST * 1)
#define QUEUE_PER_PORT 1

struct packet_mbuf {
  struct rte_mbuf *mbuf;
  TAILQ_ENTRY(packet_mbuf)
  tailq;
};


TAILQ_HEAD(packet_head, packet_mbuf);
TAILQ_HEAD(flow_entry_head, flow_entry);

struct packet_mbuf_mempool {
  struct packet_head head;
  struct packet_mbuf *pool;
};

struct flow_entry {
  uint64_t created_tsc;
  int total_byte_count;

  int pkt_cnt;
  int nb_max_per_flow_batch_size;
  struct packet_head head;
  TAILQ_ENTRY(flow_entry)
  tailq;
};

struct aggregator {
  /* data */

  struct rte_hash *cucko_hashtable;

  struct flow_entry *entries;

  struct packet_head ready_queue;

  struct flow_entry_head flow_list;

  int flow_burst_max;

  uint64_t buffer_time_us;

  struct packet_mbuf_mempool *pool;
};

#define _NF_COMMON
struct thread_context {
  struct rte_mempool *pool;
  struct rte_mbuf *tx_pkts[MAX_PKT_BURST];
  int nb_tx_pkts;
  struct rte_mbuf *rx_pkts[MAX_PKT_BURST];
  int nb_rx_pkts;
  int port_id;
  int queue_id;
  int packet_size;
  struct rte_ether_addr *eth_addrs;
  void *send_priv_data;
  void *recv_priv_data;
};

typedef struct thread_context thread_context_t;
int check_if_ipv4(struct rte_mbuf *mbuf);
typedef void(dpdk_app_function_t)(thread_context_t *ctx);
void send_all(thread_context_t *ctx, struct rte_mbuf **tx_pkts,
              uint16_t nb_pkt);

struct dpdk_app {
  dpdk_app_function_t *send;
  dpdk_app_function_t *receive;
  dpdk_app_function_t *send_init;
  dpdk_app_function_t *send_free;
  dpdk_app_function_t *recv_init;
  dpdk_app_function_t *recv_free;
};

enum {
  SEND_SIDE,
  RECEIVE_SIDE,
};

extern struct dpdk_app one_way_app;
extern struct dpdk_app echo_app;
extern struct dpdk_app firewall_app;
extern struct dpdk_app nat_app;

struct config {
  char *pcap_file_name;
};
extern struct config CONFIG;

struct pktgen_pcap {
  int total_pkt_cnt;
  struct packet *pkts;
  int cur_idx;
};
struct pktgen_pcap *pktgen_pcap_create();
void pktgen_pcap_free(struct pktgen_pcap *p);
struct packet *pktgen_pcap_get_packet(struct pktgen_pcap *p);
void print_ipv4_udp_info(void *ctx, struct rte_mbuf **mbufs, int length);

struct aggregator *aggregator_create();
void aggregator_free(struct aggregator *agg);
void aggregator_schedule(struct aggregator *agg);
struct rte_mbuf *aggregator_rx_one_packet(struct aggregator *agg,
                                          struct rte_mbuf *pkt);
extern struct config CONFIG;
// obtained directly from newer version DPDK
#define AGG_ETHER_ADDR_BYTES(mac_addrs)                           \
  ((mac_addrs)->addr_bytes[0]), ((mac_addrs)->addr_bytes[1]),     \
      ((mac_addrs)->addr_bytes[2]), ((mac_addrs)->addr_bytes[3]), \
      ((mac_addrs)->addr_bytes[4]), ((mac_addrs)->addr_bytes[5])
#endif
