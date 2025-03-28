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

int main(int argc, char** argv) {
  int ret;
  unsigned lcore_id;

  ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_panic("Cannot init EAL\n");

  struct pktgen_pcap* pktgen = pktgen_pcap_create();

  struct aggregator* agg = aggregator_create();

  struct rte_mempool* mp =
      rte_pktmbuf_pool_create("test_mempool", NB_MBUF, MEMPOOL_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  assert(mp != NULL);

  for (int i = 0; i < 16; i++) {
    printf("packet %d\n", i);
    struct rte_mbuf* buf = rte_pktmbuf_alloc(mp);
    assert(buf != NULL);
    fill_packet(pktgen, buf);
    buf = aggregator_rx_one_packet(agg, buf);
    assert(buf == NULL);
  }

  rte_delay_us(15);
  aggregator_schedule(agg);

  printf("test done!\n");
  aggregator_free(agg);

  pktgen_pcap_free(pktgen);

  rte_eal_cleanup();
  return 0;
}
