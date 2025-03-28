#include <errno.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_spinlock.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

#define DEFAULT_HASH_FUNC rte_hash_crc
#include <rte_malloc.h>
#include <rte_memory.h>
#include <stddef.h>
#include <stdio.h>

#include "aggregator.h"
#include "util.h"
struct rte_mbuf *aggregator_rx_one_packet(struct aggregator *agg,
                                          struct rte_mbuf *pkt);
struct packet_mbuf_mempool *packet_mbuf_mempool_create() {
  struct packet_mbuf_mempool *pool =
      rte_malloc("packet_mbuf", sizeof(struct packet_mbuf_mempool), 0);
  if (pool == NULL) {
    rte_panic("pool");
  }

  pool->pool =
      rte_zmalloc("packet pool", sizeof(struct packet_mbuf) * NB_MBUF, 0);
  if (pool->pool == NULL) {
    rte_panic("pool");
  }

  TAILQ_INIT(&pool->head);

  for (int i = 0; i < NB_MBUF; i++) {
    struct packet_mbuf *pkt = &pool->pool[i];
    TAILQ_INSERT_HEAD(&pool->head, pkt, tailq);
  }
  return pool;
}

struct packet_mbuf *packet_mbuf_get(struct packet_mbuf_mempool *pool) {
  if (TAILQ_EMPTY(&pool->head)) {
    return NULL;
  }
  struct packet_mbuf *p = TAILQ_FIRST(&pool->head);
  TAILQ_REMOVE(&pool->head, p, tailq);
  return p;
}

void packet_mbuf_put(struct packet_mbuf_mempool *pool,
                     struct packet_mbuf *pkt) {
  TAILQ_INSERT_HEAD(&pool->head, pkt, tailq);
}

void packet_mbuf_mempool_free(struct packet_mbuf_mempool *pool) {
  rte_free(pool->pool);
  rte_free(pool);
}
struct aggregator *aggregator_create() {
  // init the cucko hash table
  char ht_name[64];
  snprintf(ht_name, sizeof(ht_name), "aggregator-hashtable");
  struct rte_hash_parameters param = {
      .name = ht_name,
      .entries = MAX_FLOW_PER_CORE,
      .key_len = sizeof(struct ipv4_5tuple),
      .hash_func = DEFAULT_HASH_FUNC,
      .hash_func_init_val = 0,
  };
  // NUMA-aware memory allocation to avoid performance pitfall
  param.socket_id = rte_socket_id();
  struct rte_hash *ht = rte_hash_create(&param);

  if (ht == NULL) {
    printf("unable to create hash table\n");
    goto err;
  }
  // For NUMA-aware memory allocation
  struct flow_entry *fe = rte_zmalloc(
      "aggregator_flow", sizeof(struct flow_entry) * MAX_FLOW_PER_CORE, 0);

  if (fe == NULL) {
    rte_hash_free(ht);
    printf("unable to allocate memory\n");
    goto err;
  }

  for (int i = 0; i < MAX_FLOW_PER_CORE; i++) {
    TAILQ_INIT(&fe[i].head);
  }

  struct aggregator *agg =
      rte_zmalloc("aggregator", sizeof(struct aggregator), 0);

  if (agg == NULL) {
    rte_free(fe);
    rte_hash_free(ht);
    printf("unable to allocate aggregator\n");
    goto err;
  }

  agg->cucko_hashtable = ht;
  agg->entries = fe;
  TAILQ_INIT(&agg->ready_queue);
  TAILQ_INIT(&agg->flow_list);
  agg->flow_burst_max = 16;
  agg->buffer_time_us = 16;

  agg->pool = packet_mbuf_mempool_create();
  return agg;

err:
  return NULL;
}

struct rte_mbuf *aggregator_get_packet_from_ready_queue(
    struct aggregator *agg) {
  if (TAILQ_EMPTY(&agg->ready_queue)) {
    return NULL;
  }
  struct packet_mbuf *pm = TAILQ_FIRST(&agg->ready_queue);

  TAILQ_REMOVE(&agg->ready_queue, pm, tailq);
  packet_mbuf_put(agg->pool, pm);
  return pm->mbuf;
}

void aggregator_free(struct aggregator *agg) {
  if (agg == NULL) {
    return;
  }
  rte_free(agg->entries);
  rte_hash_free(agg->cucko_hashtable);
  packet_mbuf_mempool_free(agg->pool);
  rte_free(agg);
}

RTE_INIT(init_aggregator_context) {}

uint16_t aggregator_rx_burst(struct aggregator *agg, uint16_t port_id,
                             uint16_t queue_id, struct rte_mbuf **rx_pkts,
                             const uint16_t nb_pkts) {
  // port_id + queue_id = ?? TODO?
  struct rte_mbuf *private_bufs[MAX_PKT_BURST];
  int total = rte_eth_rx_burst(port_id, queue_id, private_bufs, MAX_PKT_BURST);

  struct rte_mbuf *m;

  int cnt = 0;
  for (int i = 0; i < total; i++) {
    m = aggregator_rx_one_packet(agg, private_bufs[i]);
    if (m != NULL) {
      rx_pkts[cnt] = m;
      cnt++;
    }
  }
  m = NULL;
  while (cnt < nb_pkts) {
    m = aggregator_get_packet_from_ready_queue(agg);
    if (m == NULL) {
      break;
    }
    rx_pkts[cnt] = m;
    cnt++;
  }
  return cnt;
}

void aggregator_schedule(struct aggregator *agg) {
  uint64_t cur_tsc = rte_get_tsc_cycles();
  while (!TAILQ_EMPTY(&agg->flow_list)) {
    struct flow_entry *fe = TAILQ_FIRST(&agg->flow_list);
    uint64_t interval_us =
        (cur_tsc - fe->created_tsc) * 1000 * 1000 / rte_get_timer_hz();
    // TODO: calculate the exact time here
    if (interval_us >= agg->buffer_time_us) {
      // get batch
      TAILQ_CONCAT(&agg->ready_queue, &fe->head, tailq);
      TAILQ_REMOVE(&agg->flow_list, fe, tailq);
      // it's important to delete key here
      rte_hash_del_key(agg->cucko_hashtable, &fe->tuple);
    } else {
      break;
    }
  }
}

struct rte_mbuf *aggregator_rx_one_packet(struct aggregator *agg,
                                          struct rte_mbuf *pkt) {
  if (pkt == NULL) {
    rte_exit(EXIT_FAILURE, "NULL pointer\n");
  }
  uint8_t *data = rte_pktmbuf_mtod(pkt, uint8_t *);
  int len = pkt->data_len;
  if (len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)) {
    return pkt;
  }

  struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;

  if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
    return pkt;
  }

  struct rte_ipv4_hdr *ipv4 =
      (struct rte_ipv4_hdr *)(data + sizeof(struct rte_ether_hdr));

  if (ipv4->next_proto_id != IPPROTO_TCP &&
      ipv4->next_proto_id != IPPROTO_UDP) {
    return pkt;
  }
  struct ipv4_5tuple tuple;
  tuple.ip_dst = ipv4->dst_addr;
  tuple.ip_src = ipv4->src_addr;
  if (ipv4->next_proto_id == IPPROTO_TCP) {
    if (len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                  sizeof(struct rte_tcp_hdr)) {
      return pkt;
    }
    struct rte_tcp_hdr *tcp =
        (struct rte_tcp_hdr *)(data + sizeof(struct rte_ether_hdr) +
                               sizeof(struct rte_ipv4_hdr));
    tuple.proto = IPPROTO_TCP;
    tuple.port_dst = tcp->dst_port;
    tuple.port_src = tcp->src_port;
  } else if (ipv4->next_proto_id == IPPROTO_UDP) {
    if (len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                  sizeof(struct rte_udp_hdr)) {
      return pkt;
    }
    struct rte_udp_hdr *udp =
        (struct rte_udp_hdr *)(data + sizeof(struct rte_ether_hdr) +
                               sizeof(struct rte_ipv4_hdr));
    tuple.proto = IPPROTO_UDP;
    tuple.port_src = udp->src_port;
    tuple.port_dst = udp->dst_port;
  }

  // init tuple done
  int ret = rte_hash_lookup(agg->cucko_hashtable, &tuple);
  struct packet_mbuf *pm = packet_mbuf_get(agg->pool);
  if (pm == NULL) {
    return pkt;
  }
  pm->mbuf = pkt;

  if (ret < 0) {
    int idx = rte_hash_add_key(agg->cucko_hashtable, &tuple);
    if (idx < 0) {
      printf("not enough space for hashtable\n");
      packet_mbuf_put(agg->pool, pm);
      return pkt;
    }

    struct flow_entry *fe = &agg->entries[idx];
    TAILQ_INIT(&fe->head);
    TAILQ_INSERT_TAIL(&agg->flow_list, fe, tailq);

    TAILQ_INSERT_TAIL(&agg->entries[idx].head, pm, tailq);
    fe->pkt_cnt = 1;
    fe->created_tsc = rte_get_tsc_cycles();
    fe->total_byte_count = pm->mbuf->data_len;
    fe->tuple = tuple;
    return NULL;
  }
  struct flow_entry *e = &agg->entries[ret];
  TAILQ_INSERT_TAIL(&e->head, pm, tailq);
  e->pkt_cnt++;
  if (e->pkt_cnt == agg->flow_burst_max) {
    TAILQ_CONCAT(&agg->ready_queue, &e->head, tailq);
    TAILQ_REMOVE(&agg->flow_list, e, tailq);
    rte_hash_del_key(agg->cucko_hashtable, &tuple);

    e->pkt_cnt = 0;
  }
  e->total_byte_count += pkt->data_len;

  return NULL;
}
