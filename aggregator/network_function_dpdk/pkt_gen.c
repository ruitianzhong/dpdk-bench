// copy from motivation packet.c
#include <linux/types.h>

#include "../aggregator.h"
#include "../util.h"
#include "pcap/pcap.h"

static int calculate_total_packets_in_pcap(pcap_t *p) {
  struct pcap_pkthdr pkthdr;
  const unsigned char *pkt = NULL;
  int cnt = 0;

  while ((pkt = pcap_next(p, &pkthdr)) != NULL) {
    cnt++;
  }
  return cnt;
}

static void load_packet(struct pktgen_pcap *ctx) {
  char ebuf[PCAP_ERRBUF_SIZE];
  pcap_t *p = pcap_open_offline(CONFIG.pcap_file_name, ebuf);
  if (!p) {
    rte_exit(EXIT_FAILURE, "pcap_open_offline failed. Reason: %s\n", ebuf);
  }

  ctx->total_pkt_cnt = calculate_total_packets_in_pcap(p);

  pcap_close(p);

  p = pcap_open_offline(CONFIG.pcap_file_name, ebuf);
  if (!p) {
    rte_exit(EXIT_FAILURE, "pcap_open_offline failed. Reason: %s\n", ebuf);
  }

  struct pcap_pkthdr pkthdr;
  const unsigned char *pkt = NULL;
  int idx = 0;

  ctx->pkts = calloc(ctx->total_pkt_cnt, sizeof(struct packet *));
  ctx->cur_idx = 0;
  if (ctx->pkts == NULL) {
    rte_exit(EXIT_FAILURE, "failed to allocate pkts\n");
  }

  while ((pkt = pcap_next(p, &pkthdr)) != NULL && idx < ctx->total_pkt_cnt) {
    uint8_t *buf = (uint8_t *)malloc(pkthdr.len);
    if (!buf) {
      rte_exit(EXIT_FAILURE, "failed to allocate function @%s\n", __func__);
    }

    memcpy(buf, pkt, pkthdr.len);
    struct packet *packet = calloc(1, pkthdr.len);

    packet->data = buf;
    packet->len = pkthdr.len;
    ctx->total_pkt_cnt++;

    ctx->pkts[idx] = packet;
    idx++;
    // pkt may become invalid after pcap_next, according to man page
    // It's the callee's duty to free  pkt, not the caller
  }
  pcap_close(p);
}
struct pktgen_pcap *pktgen_pcap_create() {
  struct pktgen_pcap *p = calloc(1, sizeof(struct pktgen_pcap));
  if (!p) {
    rte_exit(EXIT_FAILURE, "cannot allocate pktgen_pcap\n");
  }
  load_packet(p);
}

void pktgen_pcap_free(struct pktgen_pcap *p) {
  for (int i = 0; i < p->total_pkt_cnt; i++) {
    free(p->pkts[i]);
  }
  free(p->pkts);
  free(p);
}

struct packet *pktgen_pcap_get_packet(struct pktgen_pcap *p) {
  struct packet *packet = p->pkts[p->cur_idx];
  p->cur_idx = (p->cur_idx + 1) % p->total_pkt_cnt;
  return packet;
}