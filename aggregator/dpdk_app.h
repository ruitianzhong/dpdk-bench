#include <rte_acl.h>
#include <stdint.h>

#include "aggregator.h"

struct hash_element {
  TAILQ_ENTRY(hash_element) tailq;
  struct ipv4_5tuple tuple;
  void *data;
};
TAILQ_HEAD(hash_head, hash_element);

struct hash_bucket {
  struct hash_head head;
  int cnt;
};

struct hash_table {
  struct hash_bucket *buckets;
  int nb_buckets;
};

struct acl_entry {
  int cnt;
};

struct firewall {
  struct rte_acl_ctx *acl_ctx;

  // used for rte_acl_
  uint32_t num_ipv4;
  uint32_t num_rule;

  uint8_t types[MAX_PKT_BURST];

  const uint8_t *data_ipv4[MAX_PKT_BURST];
  uint32_t res_ipv4[MAX_PKT_BURST];

  struct acl_entry *acl_entries;
};

struct firewall *firewall_create();
void firewall_free(struct firewall *fw);
void firewall_process_packet_burst(struct firewall *fw, struct rte_mbuf **bufs,
                                   size_t length);

struct route_table_entry {
  uint32_t address;
  int mask;
  int port;
};
#define MAX_ROUTE_TABLE_SIZE 1000

struct router {
  struct route_table_entry tables[MAX_ROUTE_TABLE_SIZE];
  struct ipv4_5tuple tuple;
  int result;
};

void router_process_burst(struct router *r, struct rte_mbuf **mbuf, int len);
struct router *router_create();
void router_free(struct router *router);

struct flow_counter_entry {
  struct ipv4_5tuple tuple;
  int byte_cnt;
  int pkt_cnt;
  uint64_t last_seen_sec;
  TAILQ_ENTRY(flow_counter_entry) tailq;
};

#define MAX_FLOW_NUM 65535
TAILQ_HEAD(fc_flow_head, flow_counter_entry);
struct flow_counter {
  struct rte_hash *flow_table;

  struct flow_counter_entry entries[MAX_FLOW_NUM];

  struct fc_flow_head flow_list;

  struct ipv4_5tuple cache_tuple;

  int cache_idx;

  struct hash_table *ht;
};

struct flow_counter *flow_counter_create();
void flow_counter_free(struct flow_counter *fc);

void flow_counter_process_packet_burst(struct flow_counter *fc,
                                       struct rte_mbuf **bufs, int len);

// NAT related

struct nat_flow_entry {
  TAILQ_ENTRY(nat_flow_entry) tailq;
  uint64_t timeout_sec;
  struct ipv4_5tuple tuple;
  uint16_t port;
};

#define MAX_NAT_FLOW_NUM 65535
TAILQ_HEAD(nat_flow_entry_head, nat_flow_entry);
#define BUF_SIZE 10000
struct lan2wan_entry {
  uint32_t src_ip;
  uint16_t src_port;
  int cnt;
  struct nat_flow_entry *fe;
  char buf[BUF_SIZE];
};

struct wan2lan_entry {
  uint32_t dst_ip;
  uint16_t dst_port;
  int cnt;
  struct nat_flow_entry *fe;
};

struct nat {
  struct rte_hash *lan2wan;
  struct rte_hash *wan2lan;
  struct lan2wan_entry l2w_entries[MAX_NAT_FLOW_NUM];
  struct wan2lan_entry w2l_entries[MAX_NAT_FLOW_NUM];
  struct nat_flow_entry flow_entries[MAX_NAT_FLOW_NUM];
  struct nat_flow_entry_head used_list;
  struct nat_flow_entry_head free_list;
  uint64_t last_check_time_sec;
  struct ipv4_5tuple cache_tuple;
  int cache_idx;
  struct hash_table *ht_lan2wan;
};

struct hash_table *hash_table_create(int nb_buckets);
void hash_table_free(struct hash_table *ht);

struct nat *nat_create();
void nat_free(struct nat *nat);

void nat_process_packet_burst(struct nat *nat, struct rte_mbuf **bufs,
                              size_t length);
void hash_table_insert(struct hash_table *ht, struct ipv4_5tuple tuple,
                       void *data);
void *hash_table_look_up(struct hash_table *ht, struct ipv4_5tuple tuple);