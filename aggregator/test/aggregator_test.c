#include "../aggregator.h"

#include <errno.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_memory.h>
#include <rte_per_lcore.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
/*
  Unit test for aggregator module
*/
static void fill_packet(struct pktgen_pcap* pktgen, struct rte_mbuf* m) {
  struct packet* p = pktgen_pcap_get_packet(pktgen);
  assert(p != NULL);
  m->data_len = m->pkt_len = p->len;
  m->next = NULL;
  m->nb_segs = 1;

  uint8_t* data = rte_pktmbuf_mtod(m, uint8_t*);

  assert(data != NULL);

  memcpy(data, p->data, p->len);
}

static void inject_packet(int pkt_cnt, struct pktgen_pcap* pktgen,
                          struct rte_mempool* mp, struct aggregator* agg) {
  for (int i = 0; i < pkt_cnt; i++) {
    struct rte_mbuf* buf = rte_pktmbuf_alloc(mp);
    assert(buf != NULL);
    fill_packet(pktgen, buf);
    // print_ipv4_udp_info(NULL, &buf, 1);
    buf = aggregator_rx_one_packet(agg, buf);
    assert(buf == NULL);
  }
}

static void get_packet_burst(int pkt_cnt, struct pktgen_pcap* pktgen,
                             struct rte_mempool* mp, struct aggregator* agg) {
  for (int i = 0; i < pkt_cnt; i++) {
    struct rte_mbuf* buf = aggregator_get_packet_from_ready_queue(agg);
    assert(buf != NULL);
    // print_ipv4_udp_info(NULL, &buf, 1);
    rte_pktmbuf_free(buf);
  }
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

static void multi_flow_test(int batch_size, int flow_num) {
  assert(batch_size <= MAX_AGGREGATE_PER_FLOW);
  struct pktgen_pcap* pktgen = pktgen_pcap_create();

  struct aggregator* agg = aggregator_create();

  struct rte_mempool* mp =
      rte_pktmbuf_pool_create("test_mempool", NB_MBUF, MEMPOOL_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  assert(mp != NULL);

  inject_packet(batch_size * flow_num, pktgen, mp, agg);

  rte_delay_us(20);
  aggregator_schedule(agg);
  for (int i = 0; i < flow_num; i++) {
    uint32_t src_ip;
    struct ipv4_5tuple tuple;
    for (int j = 0; j < batch_size; j++) {
      struct rte_mbuf* buf = aggregator_get_packet_from_ready_queue(agg);
      assert(buf != NULL);
      if (j == 0) {
        tuple = extract_tuple_from_udp(buf);
        // print_ipv4_udp_info(NULL, &buf, 1);
        rte_pktmbuf_free(buf);
        continue;
      }
      struct ipv4_5tuple temp = extract_tuple_from_udp(buf);
      // print_ipv4_udp_info(NULL, &buf, 1);
      assert(memcmp(&temp, &tuple, sizeof(struct ipv4_5tuple)) == 0);
      rte_pktmbuf_free(buf);
    }
  }

  // tear down allocated resource
  aggregator_free(agg);

  pktgen_pcap_free(pktgen);
  rte_mempool_free(mp);
}

static void single_flow_test() {
  struct pktgen_pcap* pktgen = pktgen_pcap_create();

  struct aggregator* agg = aggregator_create();

  struct rte_mempool* mp =
      rte_pktmbuf_pool_create("test_mempool", NB_MBUF, MEMPOOL_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  assert(mp != NULL);

  inject_packet(16, pktgen, mp, agg);
  assert(TAILQ_EMPTY(&agg->flow_list));

  rte_delay_us(20);
  aggregator_schedule(agg);
  get_packet_burst(16, pktgen, mp, agg);
  assert(TAILQ_EMPTY(&agg->ready_queue));
  assert(TAILQ_EMPTY(&agg->flow_list));

  // timeout
  printf("\ntimeout test start\n");
  inject_packet(1, pktgen, mp, agg);
  rte_delay_us(20);
  aggregator_schedule(agg);
  get_packet_burst(1, pktgen, mp, agg);
  assert(TAILQ_EMPTY(&agg->flow_list));

  printf("\nmax_burst_size test starts\n");
  inject_packet(16, pktgen, mp, agg);
  get_packet_burst(16, pktgen, mp, agg);

  printf("test done!\n");
  // tear down allocated resource
  aggregator_free(agg);

  pktgen_pcap_free(pktgen);
  rte_mempool_free(mp);
}

int main(int argc, char** argv) {
  int ret;
  unsigned lcore_id;

  ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_panic("Cannot init EAL\n");

  CONFIG.pcap_file_name = "./pcap/synthetic_slf1_flow_num1_count1_seed42.pcap";
  single_flow_test();

  CONFIG.pcap_file_name = "./pcap/synthetic_slf1_flow_num2_count1_seed42.pcap";
  for (int i = 1; i < MAX_AGGREGATE_PER_FLOW; i++) {
    multi_flow_test(i, 2);
  }

  CONFIG.pcap_file_name = "./pcap/synthetic_slf1_flow_num3_count1_seed42.pcap";
  for (int i = 1; i < MAX_AGGREGATE_PER_FLOW; i++) {
    multi_flow_test(i, 3);
  }

  CONFIG.pcap_file_name =
      "./pcap/synthetic_slf1_flow_num2000_count1_seed42.pcap";
  for (int i = 1; i < MAX_AGGREGATE_PER_FLOW && i < 4; i++) {
    multi_flow_test(i, 2000);
  }

  rte_eal_cleanup();
  return 0;
}
