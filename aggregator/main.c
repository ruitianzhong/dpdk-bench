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
#define MEMPOOL_CACHE_SIZE		256


static uint64_t timer_period = 10;

// Descriptor
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

static RTE_LCORE_VAR_HANDLE(int, per_core_counts);
// portid 0 -> generate traffic
// portid 1 -> receive traffic
struct __rte_cache_aligned lcore_queue_conf{

};

static struct rte_eth_conf port_conf = {
    .txmode =
        {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
};

struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

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

  if (nb_ports==0){
    rte_exit(EXIT_FAILURE, "No Ethernet ports\n");
  }



  RTE_ETH_FOREACH_DEV(portid){
    if (portid != 0 || portid != 1) {
      continue;
    }

    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_conf local_port_conf = port_conf;
    struct rte_eth_dev_info dev_info;

    printf("Init port %u...\n", portid);

    ret = rte_eth_dev_info_get(portid, &dev_info);

    if (ret != 0) {
      rte_exit(EXIT_FAILURE, "Error during getting device (port %u) info: %s\n",
               portid, strerror(-ret));
    }

    ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);

    if (ret < 0) {
      rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", ret,
               portid);
    }

    

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);

    if (ret <0){
      rte_exit(EXIT_FAILURE,
               "Cannot adjust number of descriptors: err=%d port=%u\n", ret,
               portid);
    }

    ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);

    if (ret < 0) {
      rte_exit("Cannot get MAC address: err=%d, port=%u\n", ret, portid);
    }
    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = local_port_conf.rxmode.offloads;

    // ret = rte_eth_rx_queue_setup(portid,0,nb_rxd,rte_eth_dev_socket_id(portid),&rxq_conf,)

    // enable promiscuous mode
    ret = rte_eth_promiscuous_enable(portid);
    if (ret!=0){
      rte_exit(EXIT_FAILURE, "rte_eth_promiscuous_enable: err=%d, port=%u\n",
               ret, portid);
    }
    printf("Port %u, Mac address: " RTE_ETHER_ADDR_PRT_FMT "\n\n", portid,
           RTE_ETHER_ADDR_BYTES(&ports_eth_addr[portid]));

    ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL, 0);

    if (ret < 0) {
      rte_exit(EXIT_FAILURE, "failed to disable ptype parsing\n", portid);
    }

    ret = rte_eth_dev_start(portid);
    if (ret < 0) {
      rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%u\n", ret,
               portid);
    }
  }

  /* >8 End of initialization of Environment Abstraction Layer */
  rte_eal_cleanup();
  printf("Exit ...\n");

  return 0;
}
