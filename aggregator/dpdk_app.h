#include <rte_acl.h>
#include <stdint.h>

#include "aggregator.h"

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