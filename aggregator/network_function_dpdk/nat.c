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

#include "../aggregator.h"
#include "../util.h"
// ACL reference
// https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html
#define MAX_ACL_RULES 20000
#define MAX_LINE_CHARACTER 64
#define MAX_RULE_NUM 30000

#define MAX_NAT_FLOW_NUM 65535

// From my perspective, category is similar to `namespace`

struct lan2wan_entry{
    uint32_t src_ip;
    uint16_t src_port;
    int cnt;
};

struct wan2lan_entry{
    uint32_t dst_ip;
    uint16_t dst_port;
    int cnt;
};

struct nat {
  uint16_t current_port;
  struct rte_hash *lan2wan;
  struct rte_hash *wan2lan;
  struct lan2wan_entry l2w_entries[MAX_NAT_FLOW_NUM];
  struct wan2lan_entry w2l_entries[MAX_NAT_FLOW_NUM];
};

static struct nat *nat_create() {
  struct nat *nat = calloc(1, sizeof(struct nat));
  if (nat == NULL) {
    rte_exit(EXIT_FAILURE, "failed to allocate mem @%s\n", __func__);
  }

  struct rte_hash_parameters param = {
      .entries = MAX_NAT_FLOW_NUM,
      .hash_func = rte_hash_crc,
      .key_len = sizeof(struct ipv4_5tuple),
      .socket_id = rte_socket_id(),
      .hash_func_init_val = 0,
  };

  param.name = "lan2wan";
  nat->lan2wan = rte_hash_create(&param);
  if (nat->lan2wan == NULL) {
    rte_exit(EXIT_FAILURE, "failed to allocate lan2wan\n");
  }

  param.name = "wan2lan";
  nat->wan2lan = rte_hash_create(&param);
  if (nat->wan2lan == NULL) {
    rte_exit(EXIT_FAILURE, "failed to allocate wan2lan\n");
  }
  nat->current_port = 1024;
  return nat;
}

static void nat_free(struct nat *nat) {
  rte_hash_free(nat->lan2wan);
  rte_hash_free(nat->wan2lan);

  free(nat);
}

static void process_packet_burst(struct nat *nat, struct rte_mbuf **bufs,
                                 size_t length) {
  for (int i = 0; i < length; i++) {
    struct rte_mbuf *m = bufs[i];
    if (!check_if_ipv4(m)) {
      continue;
    }
    struct rte_udp_hdr *udp;
    struct rte_ipv4_hdr *ipv4;
    struct ipv4_5tuple lan2wan, wan2lan;

    udp = rte_pktmbuf_mtod_offset(
        m, struct rte_udp_hdr *,
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

    ipv4 = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
                                   sizeof(struct rte_ether_hdr));

    lan2wan.ip_dst = ipv4->dst_addr;
    lan2wan.ip_src = ipv4->src_addr;
    lan2wan.port_src = udp->src_port;
    lan2wan.port_dst = udp->dst_port;
    lan2wan.proto = ipv4->next_proto_id;

    int ret = rte_hash_lookup(nat->lan2wan, &lan2wan);
    struct lan2wan_entry *entry = NULL;

    if (ret < 0) {
      ret = rte_hash_add_key(nat->lan2wan, &lan2wan);

      entry = &nat->l2w_entries[ret];

      if (nat->current_port == 65535) {
        rte_panic("Not enough port\n");
      }

      entry->src_port = rte_cpu_to_be_16(nat->current_port);
      entry->src_ip = RTE_IPV4(127, 0, 0, 1);
      entry->cnt = 0;

      wan2lan.ip_dst = RTE_IPV4(127, 0, 0, 1);
      wan2lan.ip_src = ipv4->dst_addr;
      wan2lan.port_src = udp->dst_port;
      wan2lan.port_dst = rte_cpu_to_be_16(nat->current_port);
      wan2lan.proto = ipv4->next_proto_id;

      ret = rte_hash_add_key(nat->wan2lan, &wan2lan);
      struct wan2lan_entry *w2l_e = &nat->w2l_entries[ret];

      w2l_e->dst_ip = ipv4->src_addr;
      w2l_e->dst_port = udp->src_port;

      nat->current_port++;
    } else {
      entry = &nat->l2w_entries[ret];
      entry->cnt++;
    }

    // udp->src_port = entry->src_port;
    // ipv4->src_addr = entry->src_ip;
  }
}
/*
  Code obtained from one_way
*/

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

static void nat_sender(thread_context_t *ctx) {
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
  while (cnt < TOTAL_PACKET_COUNT || inflight_packet > 0) {
    cur_tsc = rte_rdtsc();

    difftsc = cur_tsc - prev_tsc;
    if (inflight_packet < MAX_INFLIGHT_PACKET && cnt < TOTAL_PACKET_COUNT) {
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

static void nat_receiver(thread_context_t *ctx) {
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
  uint64_t pure_process_time=0,pure_start=0;
  while (cnt < TOTAL_PACKET_COUNT) {
    pure_start=rte_get_tsc_cycles();
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
    // for (int i = 0; i < 9; i++)
      process_packet_burst((struct nat *)ctx->recv_priv_data, ctx->rx_pkts,
                           ret);

    echo_back(ctx->rx_pkts, ret);

    send_all(ctx, ctx->rx_pkts, ret);
    pure_process_time += (rte_get_tsc_cycles() - pure_start);
  }
  end = rte_get_tsc_cycles();
  double us = ((double)(end - start)) / (double)hz;

  printf("Receiver Queue %d Throughput: %f Gbps\n", ctx->queue_id,
         8.0 * (double)(total_byte_cnt) / (double)(1000 * 1000 * 1000) / us);
  printf("Average per packet processing time:%f\n",
         1000 * 1000 *
             ((double)pure_process_time / (double)(rte_get_tsc_hz())) /
             (double)TOTAL_PACKET_COUNT);
}

static void init_nat_recv(struct thread_context *ctx) {
  ctx->recv_priv_data = nat_create();
}

static void free_nat_recv(struct thread_context *ctx) {
  nat_free((struct nat *)ctx->recv_priv_data);
}

static void init_nat_send(struct thread_context *ctx) {
  ctx->send_priv_data = pktgen_pcap_create();
}

static void free_nat_send(struct thread_context *ctx) {
  pktgen_pcap_free((struct pktgen_pcap *)(ctx->send_priv_data));
}

struct dpdk_app nat_app = {
    .receive = nat_receiver,
    .send = nat_sender,
    .send_init = init_nat_send,
    .send_free = free_nat_send,
    .recv_free = free_nat_recv,
    .recv_init = init_nat_recv,
};
