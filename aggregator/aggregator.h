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
#define MAX_PKT_BURST 64
#define MAX_FLOW_PER_CORE 4096
#define MAX_AGGREGATE_PER_FLOW 16
#define READY_QUEUE_RESERVED 4096
#define MAX_CORE_NUM 40
#define NB_MBUF 8192
#define MEMPOOL_CACHE_SIZE 256
#define TOTAL_PACKET_COUNT (MAX_PKT_BURST * 100000)
#define QUEUE_PER_PORT 1

TAILQ_HEAD(packet_head, packet);
TAILQ_HEAD(flow_entry_head, flow_entry);
struct flow_entry {
  uint64_t created_tsc;
  int total_byte_count;

  int pkt_cnt;
  struct packet *pkts[MAX_AGGREGATE_PER_FLOW];
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
};

typedef struct thread_context thread_context_t;
int check_if_ipv4(struct rte_mbuf *mbuf);
typedef void(dpdk_app_function_t)(thread_context_t *ctx);

struct dpdk_app {
  dpdk_app_function_t *send;
  dpdk_app_function_t *receive;
};

enum {
  SEND_SIDE,
  RECEIVE_SIDE,
};

extern struct dpdk_app one_way_app;
extern struct dpdk_app echo_app;
#endif
