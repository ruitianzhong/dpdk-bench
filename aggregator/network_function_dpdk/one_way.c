// Traffic sent from the client and the server do not respond to it(we call it
// 'one-way')
#include "../aggregator.h"

static void replenish_tx_mbuf(struct thread_context *ctx) {
  for (int i = 0; i < MAX_PKT_BURST; i++) {
    ctx->tx_pkts[i] = rte_pktmbuf_alloc(ctx->pool);
    if (ctx->tx_pkts[i] == NULL) {
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
  }
}

static void one_way_sender(thread_context_t *ctx) {
  uint16_t lcore_id = rte_lcore_id();

  int cnt = 0;

  replenish_tx_mbuf(ctx);
  int ret = 0;
  while (cnt < TOTAL_PACKET_COUNT) {
    fill_packets(ctx);
    int remain = MAX_PKT_BURST;
    struct rte_mbuf **mp = ctx->tx_pkts;
    do {
      ret = rte_eth_tx_burst(ctx->port_id, ctx->queue_id, mp, remain);

      mp += ret;
      remain -= ret;

    } while (remain > 0);
    cnt += MAX_PKT_BURST;
    replenish_tx_mbuf(ctx);
  }
  printf("client exit\n");
}

static void one_way_receiver(thread_context_t *ctx) {
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

    for (int i = 0; i < ret; i++) {
      rte_pktmbuf_free(ctx->rx_pkts[i]);
    }
  }
  end = rte_get_tsc_cycles();

  double us = ((double)(end - start)) / (double)hz;

  printf("Queue %d Throughput: %f Gbps\n", ctx->queue_id,
         8.0 * (double)(total_byte_cnt) / (double)(1000 * 1000 * 1000) / us);
}

struct dpdk_app one_way_app = {
    .receive = one_way_receiver,
    .send = one_way_sender,
};
