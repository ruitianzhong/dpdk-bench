
#include <rte_malloc.h>

#include "../aggregator.h"
#include "../dpdk_app.h"

struct router* router_create() {
  struct router* r = rte_zmalloc("router", sizeof(struct router), 0);
  assert(r != NULL);
  return r;
}

void router_free(struct router* router) { rte_free(router); }

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

int router_search(struct router* r, struct rte_mbuf* m) {
  struct ipv4_5tuple tuple = extract_tuple_from_udp(m);
  for (int i = 0; i < MAX_ROUTE_TABLE_SIZE; i++) {
    struct route_table_entry* e = &r->tables[i];
    uint32_t mask = ~((1 << (32 - e->mask)) - 1);
    if ((tuple.ip_dst & mask) == (e->address & mask)) {
      // Match
    }
  }
}

void router_process_burst(struct router* r, struct rte_mbuf** mbuf, int len) {
  for (int i = 0; i < len; i++) {
    struct rte_mbuf* m = mbuf[i];
    router_search(r, m);
  }
}
