#include "../aggregator.h"

static int check_ipv4_header(struct rte_ipv4_hdr *ipv4, int plen) {
  if ((int)plen < (int)sizeof(struct rte_ipv4_hdr)) return 0;

  unsigned version = (ipv4->version_ihl & 0xf0) >> 4;
  unsigned hlen = (ipv4->version_ihl & 0x0f) << 2;

  if (version != 4) return 0;

  uint16_t len = rte_be_to_cpu_16(ipv4->total_length);


  if (len > plen || len < hlen) {
    return 0;
  }

  int val = in_cksum((const unsigned char *)ipv4,hlen);

  struct rte_udp_hdr *udp = (struct rte_udp_hdr *)((uint8_t *)ipv4 + hlen);
  int udp_len = plen - hlen;
  //  FIXME just to simulate the calculation here, not right here
  
    unsigned csum = in_cksum((uint8_t *)udp, udp_len);
  return 1;
}

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
  // return 1;
  return check_ipv4_header(ipv4, mbuf->data_len - sizeof(struct rte_ether_hdr));
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
// code borrow from fastclick
uint16_t in_cksum(const unsigned char *addr, int len) {
  int nleft = len;
  const uint16_t *w = (const uint16_t *)addr;
  uint32_t sum = 0;
  uint16_t answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(const unsigned char *)w;
    sum += answer;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);
  /* guaranteed now that the lower 16 bits of sum are correct */

  answer = ~sum; /* truncate to 16 bits */
  return answer;
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
