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
#define HASH_ENTRIES 2048
#include <rte_acl.h>
#include <rte_memory.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/time.h>

#include "../aggregator.h"
#include "../util.h"
#include "../dpdk_app.h"
#include <regex.h>
// ACL reference
// https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html
#define MAX_ACL_RULES 20000
#define MAX_LINE_CHARACTER 64
#define MAX_RULE_NUM 30000

#define MAX_NAT_FLOW_NUM 65535
/*
  Code obtained from one_way
*/

#define BURST_TX_DRAIN_US 5
#define MAX_INFLIGHT_PACKET (128 * 1)

struct chain {
  struct firewall *fw;
  struct flow_counter *fc;
  struct nat *nat;
  struct router *route;
};

struct chain * chain_create(){
  struct chain *c = rte_malloc("chain", sizeof(struct chain), 0);
  c->nat = nat_create();
  c->fc = flow_counter_create();
  c->route = router_create();
  c->fw = firewall_create();
  return c;
}

void chain_free(struct chain* c){
    nat_free(c->nat);
    firewall_free(c->fw);
    router_free(c->route);
    flow_counter_free(c->fc);
    rte_free(c);
}

static void replenish_tx_mbuf(struct thread_context *ctx) {
  for (int i = 0; i < MAX_PKT_BURST; i++) {
    ctx->tx_pkts[i] = rte_pktmbuf_alloc(ctx->pool);
    if (unlikely(ctx->tx_pkts[i] == NULL)) {
      rte_panic("can not allocate tx mbuf\n");
    }
  }
}

static void fill_packets(struct thread_context *ctx) {
  int offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
               sizeof(struct rte_udp_hdr);
  for (int i = 0; i < MAX_PKT_BURST; i++) {
    struct rte_mbuf *m = ctx->tx_pkts[i];

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    m->pkt_len = m->data_len = ctx->packet_size;

    m->nb_segs = 1;
    m->next = NULL;

    struct packet *p = pktgen_pcap_get_packet(ctx->send_priv_data);

    memcpy(eth, p->data, offset);
    // just for experiment here
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    uint64_t start = rte_get_tsc_cycles();

    uint64_t *t = rte_pktmbuf_mtod_offset(m, uint64_t *, offset);
    *t = rte_cpu_to_be_64(start);
  }
}

static uint64_t calculate_latency(struct rte_mbuf **rx_pkts, uint16_t nb_pkts,
                                  int *total_byte) {
  uint64_t total = 0;
  static int idx = 0;
  uint64_t end = rte_get_tsc_cycles();
  int offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
               sizeof(struct rte_udp_hdr);
  for (int i = 0; i < nb_pkts; i++) {
    struct rte_mbuf *mbuf = rx_pkts[i];
    rte_prefetch0(rte_pktmbuf_mtod(mbuf, void *));
    if (unlikely(mbuf->data_len <= offset)) {
      rte_panic("unexpected data_len: %d\n", mbuf->data_len);
    }

    uint64_t *p = rte_pktmbuf_mtod_offset(mbuf, uint64_t *, offset);
    uint64_t start = rte_be_to_cpu_64(*p);
    total = total + (end - start);
    *total_byte = *total_byte + mbuf->data_len;
  }
  total = (total * 1000 * 1000) / rte_get_tsc_hz();
  return total;
}

static void chain_sender(thread_context_t *ctx) {
  uint16_t lcore_id = rte_lcore_id();

  int cnt = 0;
  uint64_t back_pressure_cnt = 0;
  const uint64_t drain_tsc =
      ((rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S) * BURST_TX_DRAIN_US;

  uint64_t prev_tsc = 0, cur_tsc = 0, difftsc;
  printf("sender start\n");
  replenish_tx_mbuf(ctx);
  uint16_t ret = 0;
  uint64_t total_latency_us = 0, total_byte_cnt = 0, inflight_packet = 0;
  uint64_t start, end;
  uint64_t inflight_stat = 0, inflight_stat_cnt = 0;
  start = rte_get_tsc_cycles();
  int rx_cnt = 0;
  while (cnt < TOTAL_PACKET_COUNT || inflight_packet > 0) {
    cur_tsc = rte_rdtsc();

    difftsc = cur_tsc - prev_tsc;
    // if (inflight_packet < MAX_INFLIGHT_PACKET && cnt < TOTAL_PACKET_COUNT) {
    if (difftsc > drain_tsc && cnt < TOTAL_PACKET_COUNT &&
        inflight_packet < MAX_INFLIGHT_PACKET) {
      // if (difftsc > drain_tsc && cnt<TOTAL_PACKET_COUNT ) {
      fill_packets(ctx);

      send_all(ctx, ctx->tx_pkts, MAX_PKT_BURST);
      cnt += MAX_PKT_BURST;
      replenish_tx_mbuf(ctx);
      prev_tsc = cur_tsc;
      inflight_stat += inflight_packet;
      inflight_packet += MAX_PKT_BURST;
      inflight_stat_cnt++;

    } else if (cnt < TOTAL_PACKET_COUNT &&
               inflight_packet >= MAX_INFLIGHT_PACKET) {
      back_pressure_cnt++;
    }

    ret = rte_eth_rx_burst(ctx->port_id, ctx->queue_id, ctx->rx_pkts,
                           MAX_PKT_BURST);
    inflight_packet -= ret;
    int bytes_cnt = 0;
    if (ret > 0) {
      total_latency_us += calculate_latency(ctx->rx_pkts, ret, &bytes_cnt);
    }

    total_byte_cnt += bytes_cnt;
    for (int i = 0; i < ret; i++) {
      rte_pktmbuf_free(ctx->rx_pkts[i]);
    }
  }
  // TODO: calculate tail latency(more important for SLO)
  printf(
      "average latency: %f us total backpressure: %ld average inflight:%f "
      "%ld/%ld\n",
      (double)total_latency_us / (double)TOTAL_PACKET_COUNT, back_pressure_cnt,
      (double)inflight_stat / (double)(inflight_stat_cnt), inflight_stat,
      inflight_stat_cnt);

  end = rte_get_tsc_cycles();
  uint64_t hz = rte_get_tsc_hz();

  double us = ((double)(end - start)) / (double)hz;

  printf("Sender Queue %d Throughput: %f Gbps\n", ctx->queue_id,
         8.0 * (double)(total_byte_cnt) / (double)(1000 * 1000 * 1000) / us);
}

static void echo_back(struct rte_mbuf **rx_pkts, uint16_t nb_pkt) {
  for (int i = 0; i < nb_pkt; i++) {
    struct rte_mbuf *m = rx_pkts[i];
    rte_prefetch0(rte_pktmbuf_mtod(m, void *));
    if (unlikely(m->data_len <= sizeof(struct rte_ether_addr))) {
      rte_panic("Unexpected recv packets len:%d\n", m->data_len);
    }

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ether_addr tmp;

    memcpy(&tmp, &eth->d_addr, sizeof(struct rte_ether_addr));
    memcpy(&eth->d_addr, &eth->s_addr, sizeof(struct rte_ether_addr));
    memcpy(&eth->s_addr, &tmp, sizeof(struct rte_ether_addr));
  }
}

static void chain_receiver(thread_context_t *ctx) {
  int lcore_id = rte_lcore_id();
  printf("server side lcore:%d port_id=%d queue_id=%d\n", lcore_id,
         ctx->port_id, ctx->queue_id);

  uint64_t hz = rte_get_tsc_hz();

  uint64_t start, end;
  start = rte_get_tsc_cycles();
  int cnt = 0;
  int ret = -1;
  int loop_cnt = 0;
  uint64_t total_byte_cnt = 0;
  uint64_t pure_process_time = 0, pure_start = 0;
  struct chain *chain = (struct chain *)ctx->recv_priv_data;
  while (cnt < TOTAL_PACKET_COUNT) {
    pure_start = rte_get_tsc_cycles();

    ret = rte_eth_rx_burst(ctx->port_id, ctx->queue_id, ctx->rx_pkts,
                           MAX_PKT_BURST);
    if (ret < 0) {
      break;
    }
    if (ret == 0) {
      loop_cnt++;
    } else {
      loop_cnt = 0;
    }
    if (loop_cnt == 100000000) {
      printf("No packet can be received, total_byte_cnt=%ld Exit!\n",
             total_byte_cnt);
      return;
    }
    if (ret == 0) {
      continue;
    }
    cnt += ret;
    for (int i = 0; i < ret; i++) {
      total_byte_cnt += ctx->rx_pkts[i]->data_len;
    }

    for (int i = 0; i < 1; i++) {
      nat_process_packet_burst(chain->nat, ctx->rx_pkts, ret);
      firewall_process_packet_burst(chain->fw, ctx->rx_pkts, ret);
      flow_counter_process_packet_burst(chain->fc, ctx->rx_pkts, ret);
      router_process_burst(chain->route, ctx->rx_pkts, ret);
    }
    echo_back(ctx->rx_pkts, ret);
    send_all(ctx, ctx->rx_pkts, ret);
    pure_process_time += (rte_get_tsc_cycles() - pure_start);

  }
  end = rte_get_tsc_cycles();
  double us = ((double)(end - start)) / (double)hz;

  printf("Receiver Queue %d Throughput: %f Gbps\n", ctx->queue_id,
         8.0 * (double)(total_byte_cnt) / (double)(1000 * 1000 * 1000) / us);
  printf("Average per packet processing time:%f average cycle %f\n",
         1000 * 1000 *
             ((double)pure_process_time / (double)(rte_get_tsc_hz())) /
             (double)TOTAL_PACKET_COUNT,
         (double)pure_process_time / (double)TOTAL_PACKET_COUNT);
}

static void init_chain_recv(struct thread_context *ctx) {
  ctx->recv_priv_data = chain_create();
}

static void free_chain_recv(struct thread_context *ctx) {
  chain_free((struct chain *)ctx->recv_priv_data);
}

static void init_chain_send(struct thread_context *ctx) {
  ctx->send_priv_data = pktgen_pcap_create();
}

static void free_chain_send(struct thread_context *ctx) {
  pktgen_pcap_free((struct pktgen_pcap *)(ctx->send_priv_data));
}

struct dpdk_app chain_app = {
    .receive = chain_receiver,
    .send = chain_sender,
    .send_init = init_chain_send,
    .send_free = free_chain_send,
    .recv_free = free_chain_recv,
    .recv_init = init_chain_recv,
};
