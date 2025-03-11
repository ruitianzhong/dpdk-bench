#include <iostream>
#include <unordered_map>
#include "util/common.hpp"
#include <sys/unistd.h>
#include <sys/time.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <string.h>
#include <cassert>

struct SNATContext
{
    uint32_t src_ip;
    uint16_t src_port;
    int count;
};

struct DNATContext
{
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
uint16_t current_port = MIN_PORT_NUM;

void process_packet(Packet *packet)
{
    if (nullptr == packet)
    {
        throw "Null pointer to Packet";
    }

    if (packet->len > 1500 || packet->len < 54)
    {
        std::cout << "Malformed packet" << std::endl;
        return;
    }
    // assume this is a eth/ip/udp packet, so do not handle error for now
    udp *udp_p = packet->get_udp_hdr();
    ipv4 *ip_p = packet->get_ipv4_hdr();
    eth *eth_p = packet->get_eth_hdr();

    NetworkTuple tu;
    // network order
    tu.src_ip = ntohl(ip_p->ip_src);
    tu.dst_ip = ntohl(ip_p->ip_dst);
    tu.dst_port = ntohs(udp_p->dport);
    tu.src_port = ntohs(udp_p->sport);
    SNATContext *ctx = nullptr;
    // Miss
    if (snat_map.find(tu) == snat_map.end())
    {
        if (current_port == MAX_PORT_NUM)
        {
            throw "No port is available"; // FIXME in the future
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
    }

    if (!ctx)
    {
        ctx = snat_map[tu];
    }

    ip_p->ip_src = htonl(ctx->src_ip);
    udp_p->sport = htons(ctx->src_port);

    // TODO: handle MAC address heree
    uint8_t ethaddr[ETHADDR_LEN];
    memcpy(ethaddr, eth_p->shost, ETHADDR_LEN);
    memcpy(eth_p->shost, eth_p->dhost, ETHADDR_LEN);
    memcpy(eth_p->dhost, ethaddr, ETHADDR_LEN);
}
// TODO: Free all allocated resource
void teardown()
{
    for (auto kv : snat_map)
    {
        assert(kv.second != nullptr);
        delete kv.second;
    }

    for (auto kv : dnat_map)
    {
        assert(kv.second != nullptr);
        delete kv.second;
    }
}

int main(int argc, char const *argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: ./nat <pcap file path>" << std::endl;
    }
    struct timeval start_time, end_time;
    uint64_t total_us = 0;

    std::cout << "NAT processing start" << std::endl;
    gettimeofday(&start_time, NULL);
    int x = 0;
    // the killer microsecond
    std::cout << "The killer microsecond" << std::endl;

    PacketsLoader pl = PacketsLoader(std::string(argv[1]));
    Packet *p = nullptr;
    while ((p = pl.get_next_packet()) != nullptr)
    {
        process_packet(p);
    }

    gettimeofday(&end_time, NULL);
    std::cout << "NAT processing end";

    total_us = (end_time.tv_sec - start_time.tv_sec) * 1000000 + (end_time.tv_usec - start_time.tv_usec);

    std::cout << "Total time is " << total_us << std::endl;
    teardown();
    return 0;
}
