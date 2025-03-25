// server echo back what the client send

#include "../aggregator.h"

#define BURST_TX_DRAIN_US 46
#define MAX_INFLIGHT_PACKET (256 * 1)

static void replenish_tx_mbuf(struct thread_context *ctx) {
  for (int i = 0; i < MAX_PKT_BURST; i++) {
    ctx->tx_pkts[i] = rte_pktmbuf_alloc(ctx->pool);
    if (unlikely(ctx->tx_pkts[i] == NULL)) {
      rte_panic("can not allocate tx mbuf\n");
    }
  }
}

static void fill_packets(struct thread_context *ctx) {
  for (int i = 0; i < MAX_PKT_BURST; i++) {
    struct rte_mbuf *m = ctx->tx_pkts[i];

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    m->pkt_len = m->data_len = ctx->packet_size;

    m->nb_segs = 1;
    m->next = NULL;
    memcpy(&eth->s_addr, &ctx->eth_addrs[SEND_SIDE],
           sizeof(struct rte_ether_addr));
    memcpy(&eth->d_addr, &ctx->eth_addrs[RECEIVE_SIDE],
           sizeof(struct rte_ether_addr));
    // just for experiment here

    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    uint64_t start = rte_get_tsc_cycles();

    uint64_t *p =
        rte_pktmbuf_mtod_offset(m, uint64_t *, sizeof(struct rte_ether_hdr));
    *p = rte_cpu_to_be_64(start);
  }
}

static uint64_t calculate_latency(struct rte_mbuf **rx_pkts, uint16_t nb_pkts,
                                  int *total_byte) {
  uint64_t total = 0;
  static int idx = 0;
  uint64_t end = rte_get_tsc_cycles();
  for (int i = 0; i < nb_pkts; i++) {
    struct rte_mbuf *mbuf = rx_pkts[i];
    rte_prefetch0(rte_pktmbuf_mtod(mbuf, void *));
    int offset = sizeof(struct rte_ether_hdr);
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

static void echo_sender(thread_context_t *ctx) {
  uint16_t lcore_id = rte_lcore_id();

  int cnt = 0;
  const uint64_t drain_tsc =
      (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

  uint64_t prev_tsc = 0, cur_tsc = 0, difftsc;
  printf("sender start\n");
  replenish_tx_mbuf(ctx);
  uint16_t ret = 0;
  uint64_t total_latency_us = 0, total_byte_cnt = 0, inflight_packet = 0;
  uint64_t start, end;
  start = rte_get_tsc_cycles();
  int rx_cnt = 0;
  while (cnt < TOTAL_PACKET_COUNT) {
    cur_tsc = rte_rdtsc();

    difftsc = cur_tsc - prev_tsc;
    if (inflight_packet < MAX_INFLIGHT_PACKET) {
      // if (difftsc > drain_tsc) {
      fill_packets(ctx);

      send_all(ctx, ctx->tx_pkts, MAX_PKT_BURST);
      cnt += MAX_PKT_BURST;
      replenish_tx_mbuf(ctx);
      prev_tsc = cur_tsc;
      inflight_packet += MAX_PKT_BURST;
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
  printf("average latency: %f us\n",
         (double)total_latency_us / (double)TOTAL_PACKET_COUNT);

  end = rte_get_tsc_cycles();
  uint64_t hz = rte_get_tsc_hz();

  double us = ((double)(end - start)) / (double)hz;

  printf("Sender Queue %d Throughput: %f Gbps\n", ctx->queue_id,
         8.0 * (double)(total_byte_cnt) / (double)(1024 * 1024 * 1024) / us);
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

static void echo_receiver(thread_context_t *ctx) {
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
  while (cnt < TOTAL_PACKET_COUNT) {
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
    cnt += ret;
    for (int i = 0; i < ret; i++) {
      total_byte_cnt += ctx->rx_pkts[i]->data_len;
    }

    echo_back(ctx->rx_pkts, ret);

    send_all(ctx, ctx->rx_pkts, ret);
  }
  end = rte_get_tsc_cycles();
  double us = ((double)(end - start)) / (double)hz;

  printf("Receiver Queue %d Throughput: %f Gbps\n", ctx->queue_id,
         8.0 * (double)(total_byte_cnt) / (double)(1024 * 1024 * 1024) / us);
}
struct dpdk_app echo_app = {
    .receive = echo_receiver,
    .send = echo_sender,
};