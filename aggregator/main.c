#include <errno.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
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

#include "aggregator.h"

// Descriptor
// It need to be adjusted carefully to avoid packet drop
#define RX_DESC_DEFAULT 4096
#define TX_DESC_DEFAULT 4096
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;
static int packet_size = 1500;
// TODO: max_queue, rss_key setup
struct thread_context thread_ctxs[RTE_MAX_LCORE];

// portid 0 -> generate traffic
// portid 1 -> receive traffic

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
            .mq_mode = ETH_MQ_TX_NONE,
        },
    .rxmode =
        {
            .mq_mode = ETH_MQ_RX_NONE,
        },

    .rx_adv_conf =
        {
            .rss_conf = {.rss_key = NULL, .rss_hf = 0},
        },
};

struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

// print all NIC info we care about
static void print_dev_info(uint16_t portid, struct rte_eth_dev_info *info) {
  printf("port idx %d driver name %s\n", portid, info->driver_name);
  printf("max_rx_queue: %d max_tx_queue %d max MTU:%d min MTU:%d\n",
         info->max_rx_queues, info->max_tx_queues, info->max_mtu,
         info->min_mtu);

  printf("RSS hash key size: %d\n", info->hash_key_size);
  // printf("");
  printf("\n\n");
}
void replenish_tx_mbuf(struct thread_context *ctx) {
  for (int i = 0; i < MAX_PKT_BURST; i++) {
    ctx->tx_pkts[i] = rte_pktmbuf_alloc(ctx->pool);
    if (ctx->tx_pkts[i] == NULL) {
      rte_panic("can not allocate tx mbuf\n");
    }
  }
}

void print_eth_stat(int portid) {
  struct rte_eth_stats stat;
  printf("\n----------- Statistic for port %d ----------------\n", portid);
  int ret = rte_eth_stats_get(portid, &stat);
  if (ret != 0) {
    rte_panic("Cannot get stat from port %d\n", portid);
  }
  printf(
      "Ingress:  pkt_cnt: %ld total byte: %ld ierror: %ld "
      "imiss:%ld\n",
      stat.ipackets, stat.ibytes, stat.ierrors, stat.imissed);
  printf("Egress: pkt_cnt: %ld total byte: %ld oerror: %ld\n", stat.opackets,
         stat.obytes, stat.oerrors);
  printf("--------------------------------------------------\n\n");
}

// port 0 client port 1 server
static int lcore_function(__rte_unused void *dummy) {
  uint16_t lcore_id = rte_lcore_id();

  if (lcore_id >= QUEUE_PER_PORT * 2) {
    return 0;
  }
  if (lcore_id < QUEUE_PER_PORT) {
    CONFIG.app->send(&thread_ctxs[lcore_id]);
  } else {
    CONFIG.app->receive(&thread_ctxs[lcore_id]);
  }
  return 0;
}

// Obtained directly from mtcp. It's really necessary to wait for the link up
// link-up requires some time
static void check_all_ports_link_status(uint8_t port_num) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */

  uint8_t portid, count, all_ports_up, print_flag = 0;
  struct rte_eth_link link;

  printf("\nChecking link status\n");
  fflush(stdout);
  for (count = 0; count <= MAX_CHECK_TIME; count++) {
    all_ports_up = 1;
    for (portid = 0; portid < port_num; portid++) {
      memset(&link, 0, sizeof(link));
      rte_eth_link_get_nowait(portid, &link);
      /* print link status if flag set */
      if (print_flag == 1) {
        if (link.link_status)
          printf(
              "Port %d Link Up - speed %u "
              "Mbps - %s\n",
              (uint8_t)portid, (unsigned)link.link_speed,
              (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex")
                                                         : ("half-duplex\n"));
        else
          printf("Port %d Link Down\n", (uint8_t)portid);
        continue;
      }
      /* clear all_ports_up flag if any link down */
      if (link.link_status == 0) {
        all_ports_up = 0;
        break;
      }
    }
    /* after finally printing all link status, get out */
    if (print_flag == 1) break;

    if (all_ports_up == 0) {
      printf(".");
      fflush(stdout);
      rte_delay_ms(CHECK_INTERVAL);
    }

    /* set the print_flag if all ports up or timeout */
    if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
      print_flag = 1;
      printf("done\n");
    }
  }
}

/* Initialization of Environment Abstraction Layer (EAL). 8< */
int main(int argc, char **argv) {
  int ret, nb_ports;
  unsigned lcore_id;
  unsigned int nb_mbufs;
  uint16_t portid;
  uint64_t start, end;
  struct dpdk_app *app = NULL;
  ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_panic("Invalid EAL arguments\n");
  // adjust cmdline parameters
  argc -= ret;
  argv += ret;
  parse_args(argc, argv);
  app = CONFIG.app;

  nb_ports = rte_eth_dev_count_avail();

  if (nb_ports == 0) {
    rte_exit(EXIT_FAILURE, "No Ethernet ports\n");
  }

  for (int i = 0; i < nb_ports; i++) {
    struct rte_eth_dev_info dev_info;
    int ret = rte_eth_dev_info_get(i, &dev_info);
    if (ret < 0) {
      rte_exit(EXIT_FAILURE, "ret:%d\n", ret);
    }
    print_dev_info(i, &dev_info);
  }

  for (int core_id = 0; core_id < QUEUE_PER_PORT * 2; core_id++) {
    struct thread_context *ctx = &thread_ctxs[core_id];
    ctx->nb_rx_pkts = 0;
    ctx->nb_tx_pkts = 0;

    ctx->port_id = core_id / QUEUE_PER_PORT;
    ctx->queue_id = core_id % QUEUE_PER_PORT;

    ctx->packet_size = packet_size;

    ctx->eth_addrs = ports_eth_addr;

    char name[64];

    if (app->send_init != NULL && core_id % 2 == SEND_SIDE) {
      app->send_init(ctx);
    }

    if (app->recv_init != NULL && core_id % 2 == RECEIVE_SIDE) {
      app->recv_init(ctx);
    }

    sprintf(name, "mbuf_pool_%d", core_id);
    ctx->pool =
        rte_pktmbuf_pool_create(name, NB_MBUF, MEMPOOL_CACHE_SIZE, 0,
                                RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (ctx->pool == NULL) {
      rte_exit(EXIT_FAILURE, "Can not init mbuf pool\n");
    }
    printf("set up mempool for core %d\n", core_id);
  }
  int nb_port = 0;
  RTE_ETH_FOREACH_DEV(portid) {
    if (portid != 0 && portid != 1) {
      continue;
    }

    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_conf local_port_conf = port_conf;
    struct rte_eth_dev_info dev_info;

    // set up RSS
    // local_port_conf.rx_adv_conf.rss_conf.rss_key = key;
    // local_port_conf.rx_adv_conf.rss_conf.rss_key_len = sizeof(key);

    printf("Init port %u...\n", portid);

    ret = rte_eth_dev_info_get(portid, &dev_info);

    print_dev_info(portid, &dev_info);

    if (ret != 0) {
      rte_exit(EXIT_FAILURE, "Error during getting device (port %u) info: %s\n",
               portid, strerror(-ret));
    }

    ret = rte_eth_dev_configure(portid, QUEUE_PER_PORT, QUEUE_PER_PORT,
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
      uint16_t queue_id = core_id % QUEUE_PER_PORT;
      printf("configure queue %d\n", queue_id);
      ret = rte_eth_rx_queue_setup(portid, queue_id, nb_rxd,
                                   rte_eth_dev_socket_id(portid), &rxq_conf,
                                   thread_ctxs[core_id].pool);
      if (ret < 0) {
        rte_exit(EXIT_FAILURE, "rx_queue_setup port:%u err:%d\n", portid, ret);
      }

      ret = rte_eth_tx_queue_setup(portid, queue_id, nb_txd,
                                   rte_eth_dev_socket_id(portid), &txq_conf);

      if (ret < 0) {
        rte_exit(EXIT_FAILURE, "tx_queue_setup port:%u err:%d\n", portid, ret);
      }
    }

    ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);

    if (ret < 0) {
      rte_exit(EXIT_FAILURE, "Cannot get MAC address: err=%d, port=%u\n", ret,
               portid);
    }

    // enable promiscuous mode

    printf("Port %u, Mac address: %02X:%02X:%02X:%02X:%02X:%02X\n\n", portid,
           AGG_ETHER_ADDR_BYTES(&ports_eth_addr[portid]));

    ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL, 0);
    // diable ptype parsing
    if (ret < 0) {
      rte_exit(EXIT_FAILURE, "failed to disable ptype parsing portid %d\n",
               portid);
    }

    ret = rte_eth_dev_start(portid);
    if (ret < 0) {
      rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%u\n", ret,
               portid);
    }
    ret = rte_eth_promiscuous_enable(portid);
    if (ret < 0) {
      rte_exit(EXIT_FAILURE, "rte_eth_promiscuous_enable: err=%d, port=%u\n",
               ret, portid);
    }

    nb_port++;
  }
  check_all_ports_link_status(2);

  // rte_eth_stats_reset(0);
  // rte_eth_stats_reset(1);

  print_eth_stat(0);
  print_eth_stat(1);

  // pitfall in rte_eal_remote_launch?
  start = rte_get_tsc_cycles();
  rte_eal_mp_remote_launch(lcore_function, NULL, CALL_MAIN);

  RTE_LCORE_FOREACH_WORKER(lcore_id) {
    if (rte_eal_wait_lcore(lcore_id) < 0) {
      printf("Non zero return\n");
    }

    if (lcore_id >= 2) {
      continue;
    }

    if (app->send_free != NULL && lcore_id % 2 == SEND_SIDE) {
      app->send_free(&thread_ctxs[lcore_id]);
    }
    if (app->recv_free != NULL && lcore_id % 2 == RECEIVE_SIDE) {
      app->recv_free(&thread_ctxs[lcore_id]);
    }
  }
  end = rte_get_tsc_cycles();
  print_eth_stat(0);
  print_eth_stat(1);

  // close device here
  RTE_ETH_FOREACH_DEV(portid) {
    if (portid != 0 && portid != 1) {
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
  printf("Total time %f s\n", (double)(end - start) / (double)rte_get_tsc_hz());
  return 0;
}
