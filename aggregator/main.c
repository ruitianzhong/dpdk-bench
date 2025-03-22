#include <errno.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_lcore_var.h>
#include <rte_memory.h>
#include <rte_per_lcore.h>
#include <rte_spinlock.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#define DEFAULT_HASH_FUNC rte_hash_crc
#define HASH_ENTRIES 2048
#include <stdlib.h>
#define MAX_CORE_NUM 40
#define NB_MBUF 8192
#define MEMPOOL_CACHE_SIZE 256
#define TOTAL_PACKET_COUNT (MAX_PKT_BURST * 500)
#define MAX_CPU_NUM 64
#define QUEUE_PER_PORT 4
static uint64_t timer_period = 10;
#include "aggregator.h"

// Descriptor
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;
static int num_threads = MAX_CPU_NUM;
static int packet_size = 1000;
// TODO: max_queue, rss_key setup
struct thread_context {
  struct rte_mempool *pool;
  struct rte_mbuf *tx_pkts[MAX_PKT_BURST];
  int nb_tx_pkts;
  struct rte_mbuf *rx_pkts[MAX_PKT_BURST];
  int nb_rx_pkts;
  int port_id;
  int queue_id;
};

struct thread_context thread_ctxs[MAX_CPU_NUM];

static RTE_LCORE_VAR_HANDLE(int, per_core_counts);
// portid 0 -> generate traffic
// portid 1 -> receive traffic
struct __rte_cache_aligned lcore_queue_conf{

};

// obtained from mtcp source code directly
static uint8_t key[] = {
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 10 */
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 20 */
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 30 */
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 40 */
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 50 */
    0x05, 0x05                                                  /* 60 - 8 */
};
static struct rte_eth_conf port_conf = {
    .txmode =
        {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
    .rxmode =
        {
            .mq_mode = RTE_ETH_MQ_RX_RSS,
        },

    .rx_adv_conf =
        {
            .rss_conf = {.rss_key = NULL,
                         .rss_hf = RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP |
                                   RTE_ETH_RSS_IP | RTE_ETH_RSS_L2_PAYLOAD},
        },
};

struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

// print all NIC info we care about
static void print_dev_info(uint16_t portid, struct rte_eth_dev_info *info) {
  printf("port idx %d driver name %s\n", portid, info->driver_name);
  printf("max_rx_queue: %d max_tx_queue %d max MTU:%d min MTU:%d\n",
         info->max_rx_queues, info->max_tx_queues, info->max_mtu,
         info->min_mtu);

  printf("RSS hash key size: %d\n", info->hash_key_size);

  printf("\n\n");
}
void replenish_tx_mbuf(struct thread_context *ctx) {
  for (int i = 0; i < MAX_PKT_BURST; i++) {
    ctx->tx_pkts[i] = rte_pktmbuf_alloc(ctx->pool);
  }
}

void fill_packets(struct thread_context *ctx) {
  for (int i = 0; i < MAX_PKT_BURST; i++) {
    struct rte_mbuf *m = ctx->tx_pkts[i];

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
    m->pkt_len = m->data_len = packet_size;

    m->nb_segs = 1;
    m->next = NULL;
    memcpy(&eth->src_addr, &ports_eth_addr[1], sizeof(struct rte_ether_addr));
    memcpy(&eth->dst_addr, &ports_eth_addr[0], sizeof(struct rte_ether_addr));
    // just for experiment here
    eth->ether_type = rte_cpu_to_be_16(0x0101);
  }
}

void client_main_loop() {
  uint16_t lcore_id = rte_lcore_id();

  if (lcore_id > MAX_CPU_NUM) {
    rte_panic("unexpected lcore_id");
  }
  int cnt = 0;
  struct thread_context *ctx = &thread_ctxs[lcore_id];

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
}

void server_main_loop() {
  int lcore_id = rte_lcore_id();
  struct thread_context *ctx = &thread_ctxs[lcore_id];
  uint64_t hz = rte_get_tsc_hz();

  uint64_t start, end;
  start = rte_get_tsc_cycles();
  int cnt = 0;
  int ret = -1;
  uint64_t total_byte_cnt = 0;
  while (cnt < TOTAL_PACKET_COUNT) {
    ret = rte_eth_rx_burst(ctx->port_id, ctx->queue_id, &ctx->rx_pkts,
                           MAX_PKT_BURST);
    if (ret < 0) {
      break;
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

  printf("xput: %f\n", (double)(total_byte_cnt) / us);
}
// port 0 client port 1 server
static int lcore_function(__rte_unused void *dummy) {
  uint16_t lcore_id = rte_lcore_id();

  if (lcore_id < QUEUE_PER_PORT) {
    server_main_loop();
  } else {
    client_main_loop();
  }
  return 0;
}

/* Initialization of Environment Abstraction Layer (EAL). 8< */
int main(int argc, char **argv) {
  int ret, nb_ports;
  unsigned lcore_id;
  unsigned int nb_mbufs;
  uint16_t portid;

  ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_panic("Invalid EAL arguments\n");
  // adjust cmdline parameters
  argc -= ret;
  argv += ret;

  timer_period = timer_period * rte_get_timer_hz();

  nb_ports = rte_eth_dev_count_avail();

  if (nb_ports == 0) {
    rte_exit(EXIT_FAILURE, "No Ethernet ports\n");
  }

  for (int core_id = 0; core_id < QUEUE_PER_PORT * 2; core_id++) {
    struct thread_context *ctx = &thread_ctxs[core_id];
    ctx->nb_rx_pkts = 0;
    ctx->nb_tx_pkts = 0;

    ctx->port_id = core_id / QUEUE_PER_PORT;
    ctx->queue_id = core_id % QUEUE_PER_PORT;

    char name[64];

    sprintf(name, "mbuf_pool_%d", core_id);
    ctx->pool =
        rte_pktmbuf_pool_create(name, NB_MBUF, MEMPOOL_CACHE_SIZE, 0,
                                RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (ctx->pool == NULL) {
      rte_exit(EXIT_FAILURE, "Can not init mbuf pool\n");
    }
  }
  int nb_port = 0;
  RTE_ETH_FOREACH_DEV(portid) {
    if (portid != 0 || portid != 1) {
      continue;
    }

    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_conf local_port_conf = port_conf;
    struct rte_eth_dev_info dev_info;

    // set up RSS
    local_port_conf.rx_adv_conf.rss_conf.rss_key = key;
    local_port_conf.rx_adv_conf.rss_conf.rss_key_len = sizeof(key);

    printf("Init port %u...\n", portid);

    ret = rte_eth_dev_info_get(portid, &dev_info);

    print_dev_info(portid, &dev_info);

    if (ret != 0) {
      rte_exit(EXIT_FAILURE, "Error during getting device (port %u) info: %s\n",
               portid, strerror(-ret));
    }

    ret = rte_eth_dev_configure(portid, MAX_CPU_NUM, MAX_CPU_NUM,
                                &local_port_conf);

    if (ret < 0) {
      rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", ret,
               portid);
    }

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);

    if (ret < 0) {
      rte_exit(EXIT_FAILURE,
               "Cannot adjust number of descriptors: err=%d port=%u\n", ret,
               portid);
    }

    rxq_conf = dev_info.default_rxconf;
    // rxq_conf.offloads = local_port_conf.rxmode.offloads;

    txq_conf = dev_info.default_txconf;

    for (int core_id = QUEUE_PER_PORT * nb_port;
         core_id < QUEUE_PER_PORT * nb_port + QUEUE_PER_PORT; core_id++) {
      ret = rte_eth_rx_queue_setup(portid, core_id, nb_rxd,
                                   rte_eth_dev_socket_id(portid), &rxq_conf,
                                   thread_ctxs[core_id].pool);
      if (ret < 0) {
        rte_exit(EXIT_FAILURE, "rx_queue_setup port:%u err:%d\n", portid, ret);
      }

      ret = rte_eth_tx_queue_setup(portid, core_id, nb_txd,
                                   rte_eth_dev_socket_id(portid), &txq_conf);

      if (ret < 0) {
        rte_exit(EXIT_FAILURE, "tx_queue_setup port:%u err:%d\n", portid, ret);
      }
    }

    ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);

    if (ret < 0) {
      rte_exit("Cannot get MAC address: err=%d, port=%u\n", ret, portid);
    }

    // enable promiscuous mode
    ret = rte_eth_promiscuous_enable(portid);
    if (ret != 0) {
      rte_exit(EXIT_FAILURE, "rte_eth_promiscuous_enable: err=%d, port=%u\n",
               ret, portid);
    }
    printf("Port %u, Mac address: " RTE_ETHER_ADDR_PRT_FMT "\n\n", portid,
           RTE_ETHER_ADDR_BYTES(&ports_eth_addr[portid]));

    ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL, 0);
    // diable ptype parsing
    if (ret < 0) {
      rte_exit(EXIT_FAILURE, "failed to disable ptype parsing\n", portid);
    }

    ret = rte_eth_dev_start(portid);
    if (ret < 0) {
      rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%u\n", ret,
               portid);
    }

    nb_port++;
  }

  RTE_ETH_FOREACH_DEV(portid) {
    if (portid != 0 || portid != 1) {
      continue;
    }
    printf("Closing port %d\n", portid);
    ret = rte_eth_dev_stop(portid);
    if (ret != 0) {
      printf("rte_eth_dev_stop err=%d port=%d\n", ret, portid);
    }
    rte_eth_dev_close(portid);
    printf("Done!\n");
  }

  /* >8 End of initialization of Environment Abstraction Layer */
  rte_eal_cleanup();
  printf("Exit ...\n");

  return 0;
}
