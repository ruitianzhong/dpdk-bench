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
#include <rte_acl.h>
#include <rte_memory.h>
#include <stddef.h>
#include <stdio.h>

#include "../aggregator.h"
#include "../dpdk_app.h"
#include "../util.h"
// ACL reference
// https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html
#define MAX_ACL_RULES 30000
#define MAX_LINE_CHARACTER 64

enum { FIREWALL_ALLOW };

enum {
  PACKET_IPV4,
  PACKET_OTHER,
};

// To achieve zero-copy in the data path here
struct rte_acl_field_def ipv4_defs[5] = {
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof(uint8_t),
        .field_index = 0,
        .input_index = 0,
        .offset = 0,
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = 1,
        .input_index = 2,
        .offset = offsetof(struct rte_ipv4_hdr, src_addr) -
                  offsetof(struct rte_ipv4_hdr, next_proto_id),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = 2,
        .input_index = 3,
        .offset = offsetof(struct rte_ipv4_hdr, dst_addr) -
                  offsetof(struct rte_ipv4_hdr, next_proto_id),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = 3,
        .input_index = 4,
        .offset = sizeof(struct rte_ipv4_hdr) -
                  offsetof(struct rte_ipv4_hdr, next_proto_id),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = 4,
        .input_index = 4,
        .offset = sizeof(struct rte_ipv4_hdr) -
                  offsetof(struct rte_ipv4_hdr, next_proto_id) +
                  sizeof(uint16_t),
    }

};

RTE_ACL_RULE_DEF(acl_ipv4_rule, RTE_DIM(ipv4_defs));

int parse_ipv4(char *str, int len, uint32_t *ipv4, int *netmask) {
  int mask;
  uint8_t ip[4];

  int current = 0;
  int idx = 0, ip_idx = 0;
  int start = 0;
  for (int i = 0; i < 4; i++) {
    if (idx >= len) {
      return -1;
    }
    int cnt = 0;
    current = 0;
    while (idx < len) {
      if (str[idx] == '.' || str[idx] == '/') {
        idx++;
        break;
      }

      if (str[idx] > '9' || str[idx] < '0') {
        return -1;
      }
      if (cnt == 3) {
        return -1;
      }
      current = current * 10 + (str[idx] - '0');
      idx++;
      cnt++;
    }
    ip[i] = current;
  }

  if (idx >= len) {
    return -1;
  }

  current = 0;
  for (int i = 0; i < 2 && idx < len; i++, idx++) {
    if (str[idx] < '0' || str[idx] > '9') {
      return -1;
    }
    current = current * 10 + str[idx] - '0';
  }

  *ipv4 = RTE_IPV4(ip[0], ip[1], ip[2], ip[3]);
  *netmask = current;
  return 0;
}

void read_acl_from_file(char *filename, struct acl_ipv4_rule *rules,
                        uint32_t max_num_rules, struct firewall *fw) {
  FILE *file;
  char line[MAX_LINE_CHARACTER];
  file = fopen(filename, "r");

  if (NULL == file) {
    perror("firewall");
    rte_exit(EXIT_FAILURE, "failed to open the file %s\n", filename);
  }

  while (fgets(line, sizeof(line), file) != NULL) {
    if (fw->num_rule >= max_num_rules) {
      break;
    }

    int len = strlen(line);
    uint32_t ipv4_addr;
    int mask;
    if (parse_ipv4(line, len, &ipv4_addr, &mask) < 0) {
      printf("can not parse ipv4 addr %s\n", line);
      continue;
    }

    struct acl_ipv4_rule rule = {
        .data = {.userdata = 1, .category_mask = 1, .priority = 1},
        .field[2] =
            {
                .value.u32 = ipv4_addr,
                .mask_range.u32 = mask,
            },
        .field[3] =
            {
                .value.u16 = 0,
                .mask_range.u16 = 0xffff,
            },
        .field[4] =
            {
                .value.u16 = 0,
                .mask_range.u16 = 0xffff,
            },
    };

    rules[fw->num_rule++] = rule;
  }
}

struct firewall *firewall_create() {
  struct firewall *fw;
  printf("\n************ FIREWALL INIT ****************\n\n");
  fw = rte_zmalloc("firewall_ctx", sizeof(struct firewall), 0);

  if (NULL == fw) {
    rte_exit(EXIT_FAILURE, "failed to allocate firewall");
  }
  struct rte_acl_ctx *acx;
  struct rte_acl_config cfg;
  int ret;

  struct rte_acl_param param = {
      .name = "firewall_acl",
      .socket_id = SOCKET_ID_ANY,
      .rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs)),
      .max_rule_num = MAX_ACL_RULES,
  };

  struct acl_ipv4_rule *acl_rules =
      rte_malloc("acl_rule", sizeof(struct acl_ipv4_rule) * MAX_ACL_RULES, 0);

  if (acl_rules == NULL) {
    rte_panic("not enough memory");
  }

  read_acl_from_file(CONFIG.fw_rules_file_name, acl_rules, MAX_ACL_RULES, fw);

  if ((acx = rte_acl_create(&param)) == NULL) {
    rte_exit(EXIT_FAILURE, "failed to create acl context");
  }

  ret = rte_acl_add_rules(acx, (struct rte_acl_rule *)acl_rules, fw->num_rule);
  if (ret != 0) {
    rte_exit(EXIT_FAILURE, "failed to add rules");
  }

  cfg.num_categories = 1;
  cfg.num_fields = RTE_DIM(ipv4_defs);

  memcpy(cfg.defs, ipv4_defs, sizeof(ipv4_defs));

  ret = rte_acl_build(acx, &cfg);

  if (ret != 0) {
    rte_exit(EXIT_FAILURE, "fail to build acl");
  }
  rte_acl_dump(acx);
  fw->acl_ctx = acx;
  fw->num_rule = 0;
  fw->num_ipv4 = 0;
  // rte_acl_classify(acx, data, results, 1, 4);
  printf("************ FIREWALL INIT END ****************\n\n");

  return fw;
}
// From my perspective, category is similar to `namespace`

void firewall_free(struct firewall *fw) {
  if (NULL == fw) {
    return;
  }

  rte_acl_free(fw->acl_ctx);
  rte_free(fw);
}

static inline uint8_t *get_ipv4_next_proto_ptr(uint8_t *data) {
  return data + sizeof(struct rte_ether_hdr) +
         offsetof(struct rte_ipv4_hdr, next_proto_id);
}

void firewall_process_packet_burst(struct firewall *fw, struct rte_mbuf **bufs,
                                   size_t length) {
  if (length > MAX_PKT_BURST) {
    rte_panic("len=%ld\n", length);
  }
  if (length == 0) {
    return;
  }
  fw->num_ipv4 = 0;
  for (int i = 0; i < length; i++) {
    if (check_if_ipv4(bufs[i])) {
      uint8_t *ptr = rte_pktmbuf_mtod(bufs[i], uint8_t *);
      fw->types[i] = PACKET_IPV4;
      fw->data_ipv4[fw->num_ipv4++] = get_ipv4_next_proto_ptr(ptr);
    } else {
      fw->types[i] = PACKET_OTHER;
    }
  }

  if (rte_acl_classify(fw->acl_ctx, fw->data_ipv4, fw->res_ipv4, fw->num_ipv4,
                       1) != 0) {
    rte_panic("wrong parameter");
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

static void firewall_sender(thread_context_t *ctx) {
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

static void firewall_receiver(thread_context_t *ctx) {
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
    firewall_process_packet_burst(ctx->recv_priv_data, ctx->rx_pkts, ret);
    echo_back(ctx->rx_pkts, ret);

    send_all(ctx, ctx->rx_pkts, ret);
  }
  end = rte_get_tsc_cycles();
  double us = ((double)(end - start)) / (double)hz;

  printf("Receiver Queue %d Throughput: %f Gbps\n", ctx->queue_id,
         8.0 * (double)(total_byte_cnt) / (double)(1024 * 1024 * 1024) / us);
}

static void init_firewall_recv(struct thread_context *ctx) {
  ctx->recv_priv_data = firewall_create();
}

static void free_firewall_recv(struct thread_context *ctx) {
  firewall_free((struct firewall *)ctx->recv_priv_data);
}

static void init_firewall_send(struct thread_context *ctx) {
  ctx->send_priv_data = pktgen_pcap_create();
}

static void free_firewall_send(struct thread_context *ctx) {
  pktgen_pcap_free((struct pktgen_pcap *)(ctx->send_priv_data));
}

struct dpdk_app firewall_app = {
    .receive = firewall_receiver,
    .send = firewall_sender,
    .send_init = init_firewall_send,
    .send_free = free_firewall_send,
    .recv_free = free_firewall_recv,
    .recv_init = init_firewall_recv,
};
