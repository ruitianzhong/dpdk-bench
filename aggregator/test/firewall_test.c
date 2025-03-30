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

#include "../aggregator.h"
#include "../dpdk_app.h"

/*
   firewall unit test
*/

#define TOTAL_RULES 20000

int main(int argc, char** argv) {
  int ret;
  unsigned lcore_id;

  ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_panic("Cannot init EAL\n");

  CONFIG.pcap_file_name = "./rules/synthetic_slf1_flow_num20000_seed42.pcap";
  CONFIG.fw_rules_file_name = "./rules/fw20000.rules";

  struct firewall* fw = firewall_create();

  struct pktgen_pcap* pktgen = pktgen_pcap_create();

  int cnt = 0;

  struct rte_mempool* mp =
      rte_pktmbuf_pool_create("test_mempool", NB_MBUF, MEMPOOL_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  struct rte_mbuf* mbuf[MAX_PKT_BURST];
  int remain = TOTAL_RULES;

  while (remain > 0) {
    int batch = remain > MAX_PKT_BURST ? MAX_PKT_BURST : remain;
    for (int i = 0; i < batch; i++) {
      struct packet* packet = pktgen_pcap_get_packet(pktgen);
      struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
      m->nb_segs = 1;
      m->data_len = m->pkt_len = packet->len;
      memcpy(rte_pktmbuf_mtod(m, void*), packet->data, packet->len);
      mbuf[i] = m;
    }

    firewall_process_packet_burst(fw, mbuf, batch);

    for (int i = 0; i < batch; i++) {
      // match result is expected
      assert(fw->res_ipv4[i] > 0);
    }

    rte_pktmbuf_free_bulk(mbuf, batch);
    remain -= batch;
  }
  printf("All tests passed\n");
  rte_mempool_free(mp);

  rte_eal_cleanup();
  return 0;
}