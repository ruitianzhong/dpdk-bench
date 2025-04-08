#include <errno.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

#include <rte_memory.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/time.h>

#include "../aggregator.h"
#include "../util.h"
#include "../dpdk_app.h"
// ACL reference
// https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html

// From my perspective, category is similar to `namespace`
struct nat *nat_create() {
  struct nat *nat = (struct nat *)calloc(1, sizeof(struct nat));
  if (nat == NULL) {
    rte_exit(EXIT_FAILURE, "failed to allocate mem @%s\n", __func__);
  }

  struct rte_hash_parameters param = {
      .entries = MAX_NAT_FLOW_NUM,
      .hash_func = rte_hash_crc,
      .key_len = sizeof(struct ipv4_5tuple),
      .socket_id = rte_socket_id(),
      .hash_func_init_val = 0,
  };

  param.name = "wan2lan";
  nat->wan2lan = rte_hash_create(&param);
  if (nat->wan2lan == NULL) {
    rte_exit(EXIT_FAILURE, "failed to allocate wan2lan\n");
  }
  TAILQ_INIT(&nat->free_list);
  TAILQ_INIT(&nat->used_list);

  for (int i = 1024, idx = 0; i < MAX_NAT_FLOW_NUM; i++, idx++) {
    struct nat_flow_entry *entry = &nat->flow_entries[idx];
    entry->port = i;
    TAILQ_INSERT_TAIL(&nat->free_list, entry, tailq);
  }
  nat->cached_entry = NULL;
  nat->ht_lan2wan = hash_table_create(1000);
  return nat;
}

void nat_free(struct nat *nat) {
  rte_hash_free(nat->wan2lan);
  free(nat);
}

static struct nat_flow_entry *allocate_port(struct nat *nat) {
  if (TAILQ_EMPTY(&nat->free_list)) {
    // TODO:Implement LRU eviction
    rte_panic("not enough port\n");
  }
  struct nat_flow_entry *fe = TAILQ_FIRST(&nat->free_list);

  TAILQ_REMOVE(&nat->free_list, fe, tailq);
  return fe;
}

static void evict_packet_periodically(struct nat *nat) {
  struct timeval tval;
  gettimeofday(&tval, NULL);

  while (!TAILQ_EMPTY(&nat->used_list)) {
    struct nat_flow_entry *fe = TAILQ_FIRST(&nat->used_list);
    if (fe->timeout_sec <= tval.tv_sec) {
      // TODO: eviction
      rte_panic("Eviction is not implemented for now");
    } else {
      break;
    }
  }
}


void nat_process_packet_burst(struct nat *nat, struct rte_mbuf **bufs,
                              size_t length) {
  for (int i = 0; i < length; i++) {
    struct rte_mbuf *m = bufs[i];
    if (!check_if_ipv4(m)) {
      continue;
    }
    struct rte_udp_hdr *udp;
    struct rte_ipv4_hdr *ipv4;
    struct ipv4_5tuple lan2wan, wan2lan;

    udp = rte_pktmbuf_mtod_offset(
        m, struct rte_udp_hdr *,
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

    ipv4 = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
                                   sizeof(struct rte_ether_hdr));

    lan2wan.ip_dst = ipv4->dst_addr;
    lan2wan.ip_src = ipv4->src_addr;
    lan2wan.port_src = udp->src_port;
    lan2wan.port_dst = udp->dst_port;
    lan2wan.proto = ipv4->next_proto_id;
    struct lan2wan_entry *entry = NULL;

    if (nat->cached_entry != NULL && tuple_equal(&lan2wan, &nat->cache_tuple)) {
      entry = nat->cached_entry;
      evict_packet_periodically(nat);
      continue;
    }

    struct lan2wan_entry *data =
        (struct lan2wan_entry *)hash_table_look_up(nat->ht_lan2wan, lan2wan);
    if (data == NULL) {
      struct lan2wan_entry *temp = malloc(sizeof(struct lan2wan_entry));
      assert(temp != NULL);
      hash_table_insert(nat->ht_lan2wan, lan2wan, temp);

      entry = temp;

      struct nat_flow_entry *e = allocate_port(nat);
      e->tuple = lan2wan;
      struct timeval tval;

      gettimeofday(&tval, NULL);
      e->timeout_sec = tval.tv_sec + 1000;

      entry->src_port = rte_cpu_to_be_16(e->port);
      entry->src_ip = RTE_IPV4(127, 0, 0, 1);
      entry->cnt = 0;
      entry->fe = e;

      wan2lan.ip_dst = RTE_IPV4(127, 0, 0, 1);
      wan2lan.ip_src = ipv4->dst_addr;
      wan2lan.port_src = udp->dst_port;
      wan2lan.port_dst = rte_cpu_to_be_16(e->port);
      wan2lan.proto = ipv4->next_proto_id;

      int ret = rte_hash_add_key(nat->wan2lan, &wan2lan);
      struct wan2lan_entry *w2l_e = &nat->w2l_entries[ret];

      w2l_e->dst_ip = ipv4->src_addr;
      w2l_e->dst_port = udp->src_port;
      w2l_e->fe = e;
      TAILQ_INSERT_TAIL(&nat->used_list, e, tailq);

    } else {
      entry = data;
      entry->cnt++;
      TAILQ_REMOVE(&nat->used_list, entry->fe, tailq);
      TAILQ_INSERT_TAIL(&nat->used_list, entry->fe, tailq);
      struct timeval tval;
      gettimeofday(&tval, NULL);
      entry->fe->timeout_sec = tval.tv_sec + 60 * 10;
    }
    // udp->src_port = entry->src_port;
    // ipv4->src_addr = entry->src_ip;
    evict_packet_periodically(nat);
    nat->cached_entry = entry;
    nat->cache_tuple = lan2wan;
  }
}
