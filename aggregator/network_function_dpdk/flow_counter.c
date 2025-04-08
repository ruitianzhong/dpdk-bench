#include <sys/time.h>

#include "../aggregator.h"
#include "../dpdk_app.h"

struct flow_counter* flow_counter_create() {
  struct flow_counter* fc =
      (struct flow_counter*)rte_zmalloc("fc", sizeof(struct flow_counter), 0);
  assert(fc != NULL);
  TAILQ_INIT(&fc->flow_list);
  fc->cached_entry = NULL;
  fc->ht = hash_table_create(1000);
  assert(fc->ht != NULL);
  return fc;
}

void flow_counter_free(struct flow_counter* fc) {
  hash_table_free(fc->ht);
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
    if (fe->last_seen_sec + 100 < tv.tv_sec) {
      rte_panic("eviction not implemented in flow counter\n");
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

    if (fc->cached_entry != NULL && tuple_equal(&tuple, &fc->cache_tuple)) {
      fe = fc->cached_entry;
      update_fc(fe, m);
      check(fc);
      continue;
    }

    fe = hash_table_look_up(fc->ht, tuple);

    if (fe == NULL) {
      struct flow_counter_entry* temp =
          malloc(sizeof(struct flow_counter_entry));
      assert(temp != NULL);
      hash_table_insert(fc->ht, tuple, temp);
      fe = temp;
      fe->byte_cnt = 0;
      fe->pkt_cnt = 0;
      fe->tuple = tuple;
      TAILQ_INSERT_TAIL(&fc->flow_list, fe, tailq);
    } else {
      TAILQ_REMOVE(&fc->flow_list, fe, tailq);
      TAILQ_INSERT_TAIL(&fc->flow_list, fe, tailq);
    }
    fc->cache_tuple = tuple;
    fc->cached_entry = fe;

    update_fc(fe, m);
    check(fc);
  }
}
