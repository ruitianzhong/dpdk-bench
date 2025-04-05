#include <rte_hash_crc.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <sys/time.h>

#include "../aggregator.h"
#include "../dpdk_app.h"

struct flow_counter* flow_counter_create() {
  struct rte_hash* ht;
  struct rte_hash_parameters param = {
      .key_len = sizeof(struct ipv4_5tuple),
      .name = "flow_counter",
      .socket_id = rte_socket_id(),
      .hash_func = rte_hash_crc,
      .entries = MAX_FLOW_NUM,
      .hash_func_init_val = 0,
  };
  ht = rte_hash_create(&param);
  if (ht == NULL) {
    rte_panic("Can not allocate rte_hash\n");
  }
  struct flow_counter* fc =
      (struct flow_counter*)rte_zmalloc("fc", sizeof(struct flow_counter), 0);
  assert(fc != NULL);
  fc->flow_table = ht;
  TAILQ_INIT(&fc->flow_list);
  fc->cache_idx = -1;
  return fc;
}

void flow_counter_free(struct flow_counter* fc) {
  rte_hash_free(fc->flow_table);
  rte_free(fc);
}

static struct ipv4_5tuple extract_tuple_from_udp(struct rte_mbuf* m) {
  struct ipv4_5tuple tuple;
  struct rte_udp_hdr* udp;
  struct rte_ipv4_hdr* ipv4;
  udp = rte_pktmbuf_mtod_offset(
      m, struct rte_udp_hdr*,
      sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
  ipv4 = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr*,
                                 sizeof(struct rte_ether_hdr));
  tuple.ip_src = ipv4->src_addr;
  tuple.ip_dst = ipv4->dst_addr;
  tuple.port_dst = udp->dst_port;
  tuple.port_src = udp->src_port;
  tuple.proto = ipv4->next_proto_id;
  return tuple;
}

static void check(struct flow_counter* fc) {
  struct timeval tv;
  while (!TAILQ_EMPTY(&fc->flow_list)) {
    struct flow_counter_entry* fe = TAILQ_FIRST(&fc->flow_list);
    gettimeofday(&tv, NULL);
    if (fe->last_seen_sec + 10 < tv.tv_sec) {
      rte_panic("eviction not implemented\n");
    } else {
      break;
    }
  }
}

static void update_fc(struct flow_counter_entry* fe, struct rte_mbuf* m) {
  fe->byte_cnt += m->data_len;
  fe->pkt_cnt++;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  fe->last_seen_sec = tv.tv_sec;
}

void flow_counter_process_packet_burst(struct flow_counter* fc,
                                       struct rte_mbuf** bufs, int len) {
  for (int i = 0; i < len; i++) {
    struct rte_mbuf* m = bufs[i];
    struct ipv4_5tuple tuple = extract_tuple_from_udp(m);
    struct flow_counter_entry* fe = NULL;

    if (fc->cache_idx != -1 &&
        (memcmp(&tuple, &fc->cache_tuple, sizeof(struct ipv4_5tuple)) == 0)) {
      fe = &fc->entries[fc->cache_idx];
      update_fc(fe, m);
      check(fc);
      continue;
    }

    int ret = rte_hash_lookup(fc->flow_table, &tuple);

    if (ret < 0) {
      ret = rte_hash_add_key(fc->flow_table, &tuple);
      assert(ret >= 0);
      fe = &fc->entries[ret];
      fe->byte_cnt = 0;
      fe->pkt_cnt = 0;
      fe->tuple = tuple;

      TAILQ_INSERT_TAIL(&fc->flow_list, fe, tailq);
    } else {
      fe = &fc->entries[ret];

      TAILQ_REMOVE(&fc->flow_list, fe, tailq);
      TAILQ_INSERT_TAIL(&fc->flow_list, fe, tailq);
    }
    fc->cache_idx = ret;
    fc->cache_tuple = tuple;
    update_fc(fe, m);
    check(fc);
  }
}
