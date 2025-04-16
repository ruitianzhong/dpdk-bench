#include <arpa/inet.h>
#include <inttypes.h>
#include <string.h>
#include <sys/time.h>
#include <sys/unistd.h>
#include <x86intrin.h>

#include <cassert>
#include <iostream>
#include <unordered_map>

#include "util/common.hpp"

struct SNATContext {
  uint32_t src_ip;
  uint16_t src_port;
  int count;
};

struct DNATContext {
  uint32_t dst_ip;
  uint16_t dst_port;
  int count;
};

std::unordered_map<NetworkTuple, SNATContext *, TupleHasher> snat_map;
std::unordered_map<NetworkTuple, DNATContext *, TupleHasher> dnat_map;
// we do not use the reserved port here though
// we do not release the port for now
constexpr uint16_t MIN_PORT_NUM = 1024;
constexpr uint16_t MAX_PORT_NUM = 65535;
static int miss_cnt = 0;
uint16_t current_port = MIN_PORT_NUM;
void print_address_info(ipv4 *ip_p, udp *udp_p) {
  in_addr src, dst;
  src.s_addr = ip_p->ip_src;
  dst.s_addr = ip_p->ip_dst;
  std::cout << "src ip " << inet_ntoa(src) << " port:" << ntohs(udp_p->sport)
            << std::endl;
  std::cout << "dst ip " << inet_ntoa(dst) << " port:" << ntohs(udp_p->dport)
            << std::endl;
  std::cout << std::endl;
}

struct {
  std::string filename;
  bool cache;
} CONFIG;

NetworkTuple cached_tuple_key;
SNATContext *cached_context = nullptr;

bool tuple_equal(NetworkTuple &tuple1, NetworkTuple &tuple2) {
  return tuple1.dst_ip == tuple2.dst_ip && tuple1.src_ip == tuple2.src_ip &&
         tuple1.proto == tuple2.proto && tuple1.src_port == tuple2.src_port &&
         tuple1.dst_port == tuple2.dst_port;
}

void process_packet(Packet *packet) {
  if (nullptr == packet) {
    throw "Null pointer to Packet";
  }

  if (packet->len > 1500 || packet->len < 54) {
    std::cout << "Malformed packet" << std::endl;
    return;
  }
  // assume this is a eth/ip/udp packet, so do not handle error for now
  udp *udp_p = packet->get_udp_hdr();
  ipv4 *ip_p = packet->get_ipv4_hdr();
  eth *eth_p = packet->get_eth_hdr();
#ifdef NF_DEBUG
  print_address_info(ip_p, udp_p);
#endif
  NetworkTuple tu;
  // network order
  tu.src_ip = ntohl(ip_p->ip_src);
  tu.dst_ip = ntohl(ip_p->ip_dst);
  tu.dst_port = ntohs(udp_p->dport);
  tu.src_port = ntohs(udp_p->sport);
  SNATContext *ctx = nullptr;

  if (CONFIG.cache && cached_context != nullptr &&
      tuple_equal(tu, cached_tuple_key)) {
    ctx = cached_context;
  } else {
    // Miss
    auto iter = snat_map.find(tu);

    if (iter == snat_map.end()) {
      if (current_port == MAX_PORT_NUM) {
        throw "No port is available";  // FIXME in the future
      }
      int port = current_port++;
      SNATContext *sctx = new SNATContext();
      sctx->src_ip = MAKE_IP_ADDR(8, 8, 8, 8);
      sctx->src_port = port;
      // SNAT setup
      snat_map[tu] = sctx;

      // DNAT setup,we do not use it for now
      NetworkTuple reverse_tuple;
      reverse_tuple.dst_ip = MAKE_IP_ADDR(8, 8, 8, 8);
      reverse_tuple.src_ip = tu.dst_ip;
      reverse_tuple.src_port = tu.dst_port;
      reverse_tuple.dst_port = port;

      DNATContext *dctx = new DNATContext();
      dctx->dst_ip = tu.src_ip;
      dctx->dst_port = tu.src_port;

      dnat_map[reverse_tuple] = dctx;
      // reduce the number of hash table search
      ctx = sctx;
      if (CONFIG.cache) {
        cached_context = ctx;
        cached_tuple_key = tu;
      }
      miss_cnt++;
    } else {
      ctx = iter->second;
      if (CONFIG.cache) {
        cached_context = ctx;
        cached_tuple_key = tu;
      }
    }
  }

  ip_p->ip_src = htonl(ctx->src_ip);
  udp_p->sport = htons(ctx->src_port);

  // TODO: handle MAC address heree
  uint8_t ethaddr[ETHADDR_LEN];
  memcpy(ethaddr, eth_p->shost, ETHADDR_LEN);
  memcpy(eth_p->shost, eth_p->dhost, ETHADDR_LEN);
  memcpy(eth_p->dhost, ethaddr, ETHADDR_LEN);

#ifdef NF_DEBUG
  print_address_info(ip_p, udp_p);
#endif
  // for  loop processing(just to be memory efficient)
  ip_p->ip_src = htonl(tu.src_ip);
  udp_p->sport = htons(tu.src_port);
  ctx->count++;  // update per packet state
}

// TODO: Free all allocated resource
void teardown() {
  for (auto kv : snat_map) {
    assert(kv.second != nullptr);
    delete kv.second;
  }

  for (auto kv : dnat_map) {
    assert(kv.second != nullptr);
    delete kv.second;
  }
}

__inline__ uint64_t perf_counter(void) {
  __asm__ __volatile__("" ::: "memory");
  uint64_t r = __rdtsc();
  __asm__ __volatile__("" ::: "memory");
  return r;
}


void parse_config(int argc, char const *argv[]) {
  int i = 1;
  CONFIG.cache = 0;
  CONFIG.filename = "";
  while (i < argc) {
    std::string s(argv[i]);
    if (s == "--pcap") {
      if (i + 1 >= argc) {
        exit(EXIT_FAILURE);
      }
      CONFIG.filename = argv[i + 1];
      i += 2;
    } else if (s == "--enable-cache") {
      if (i + 1 >= argc) {
        exit(EXIT_FAILURE);
      }
      if (argv[i + 1][0] == '0') {
        CONFIG.cache = false;
      } else {
        CONFIG.cache = true;
      }

      i += 2;
    }
  }
}

int main(int argc, char const *argv[]) {
  parse_config(argc, argv);
  struct timeval start_time, end_time;
  uint64_t total_us = 0;
  uint64_t cnt = 0;
  // load the data before processing
  PacketsLoader pl =
      PacketsLoader(std::string(CONFIG.filename), 10000 * 16 * 600);
  std::cout << "NAT processing start" << std::endl;
  gettimeofday(&start_time, NULL);
  // the killer microsecond
  Packet *p = nullptr;
  while ((p = pl.get_next_packet()) != nullptr) {
    process_packet(p);
    cnt++;
  }

  gettimeofday(&end_time, NULL);
  std::cout << "NAT processing end" << std::endl;

  total_us = (end_time.tv_sec - start_time.tv_sec) * 1000000 +
             (end_time.tv_usec - start_time.tv_usec);

  std::cout << "Total time is " << total_us << std::endl;
  std::cout << "Average time per packet: "
            << 1000.0 * double(total_us) / double(pl.get_total_packets())
            << " ns" << std::endl;
  std::cout << "Total Packest handled: " << cnt << " miss " << miss_cnt
            << std::endl;
  teardown();
  return 0;
}
