#include "../aggregator.h"

int check_if_ipv4(struct rte_mbuf *mbuf) {
  if (mbuf == NULL) {
    rte_panic("NULL in check ipv4");
  }
  if (mbuf->data_len <
      sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)) {
    return 0;
  }

  struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

  if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
    return 0;
  }

  struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(
      mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

  if (ipv4->next_proto_id != IPPROTO_TCP &&
      ipv4->next_proto_id != IPPROTO_UDP) {
    return 0;
  }
  return 1;
}

void send_all(thread_context_t *ctx, struct rte_mbuf **tx_pkts,
              uint16_t nb_pkt) {
  int remain = nb_pkt;
  if (!remain) {
    return;
  }

  struct rte_mbuf **mp = tx_pkts;
  int ret = 0;
  do {
    ret = rte_eth_tx_burst(ctx->port_id, ctx->queue_id, mp, remain);
    mp += ret;
    remain -= ret;
  } while (remain > 0);
}
// For debug only not used in the data path
void print_ipv4_udp_info(void *ctx, struct rte_mbuf **mbufs, int length) {
  for (int i = 0; i < length; i++) {
    struct rte_mbuf *m = mbufs[i];
    struct rte_udp_hdr *udp = rte_pktmbuf_mtod_offset(
        m, struct rte_udp_hdr *,
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(
        m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

    struct in_addr ip_addr;

    ip_addr.s_addr = rte_be_to_cpu_32(ipv4->src_addr);

    printf("src IP Address: %s Port:%d ", inet_ntoa(ip_addr),
           rte_be_to_cpu_16(udp->src_port));

    ip_addr.s_addr = rte_be_to_cpu_32(ipv4->dst_addr);
    printf("dst IP Address: %s Port:%d\n", inet_ntoa(ip_addr),
           rte_be_to_cpu_16(udp->dst_port));
  }
}