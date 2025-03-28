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

static void inject_single_flow_packet(int pkt_cnt, struct pktgen_pcap* pktgen,
                                      struct rte_mempool* mp,
                                      struct aggregator* agg) {
  for (int i = 0; i < pkt_cnt; i++) {
    struct rte_mbuf* buf = rte_pktmbuf_alloc(mp);
    assert(buf != NULL);
    fill_packet(pktgen, buf);
    buf = aggregator_rx_one_packet(agg, buf);
    assert(buf == NULL);
  }
}

static void get_packet_burst(int pkt_cnt, struct pktgen_pcap* pktgen,
                             struct rte_mempool* mp, struct aggregator* agg) {
  for (int i = 0; i < pkt_cnt; i++) {
    struct rte_mbuf* buf = aggregator_get_packet_from_ready_queue(agg);
    assert(buf != NULL);
    rte_pktmbuf_free(buf);
  }
}

static void single_flow_test() {
  struct pktgen_pcap* pktgen = pktgen_pcap_create();

  struct aggregator* agg = aggregator_create();

  struct rte_mempool* mp =
      rte_pktmbuf_pool_create("test_mempool", NB_MBUF, MEMPOOL_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  assert(mp != NULL);

  inject_single_flow_packet(16, pktgen, mp, agg);
  assert(TAILQ_EMPTY(&agg->flow_list));

  rte_delay_us(20);
  aggregator_schedule(agg);
  get_packet_burst(16, pktgen, mp, agg);
  assert(TAILQ_EMPTY(&agg->ready_queue));
  assert(TAILQ_EMPTY(&agg->flow_list));

  // timeout
  printf("\ntimeout test start\n");
  inject_single_flow_packet(1, pktgen, mp, agg);
  rte_delay_us(20);
  aggregator_schedule(agg);
  get_packet_burst(1, pktgen, mp, agg);
  assert(TAILQ_EMPTY(&agg->flow_list));

  printf("\nmax_burst_size test starts\n");
  inject_single_flow_packet(16, pktgen, mp, agg);
  get_packet_burst(16, pktgen, mp, agg);

  printf("test done!\n");
  // tear down allocated resource
  aggregator_free(agg);

  pktgen_pcap_free(pktgen);
}

int main(int argc, char** argv) {
  int ret;
  unsigned lcore_id;

  ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_panic("Cannot init EAL\n");

  single_flow_test();
  rte_eal_cleanup();
  return 0;
}
