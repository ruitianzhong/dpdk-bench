#ifndef _NF_COMMON_H
#define _NF_COMMON_H
#include <cstdint>
#include <arpa/inet.h>
#include <string>

// hash table key
struct NetworkTuple
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    bool operator==(const NetworkTuple &tuple) const
    {
        return (src_ip == tuple.src_ip && dst_ip == tuple.dst_ip && src_port == tuple.src_port && dst_port == tuple.dst_port);
    }
};

class TupleHasher
{

public:
    size_t operator()(const NetworkTuple &tuple) const
    {
        size_t src_ip_low_16, dst_ip_low_16, src_port, dst_port;
        src_ip_low_16 = size_t(tuple.src_ip & ~(0xffff));
        dst_ip_low_16 = size_t(tuple.dst_ip & ~(0xffff));
        src_port = size_t(tuple.src_port);
        dst_port = size_t(tuple.dst_port);

        return (src_ip_low_16) | (dst_ip_low_16 << 16) | (dst_port << 32) | (src_port << 48);
    }
};

/// Note: struct definition is obtained from xv6 src code
#define ETHADDR_LEN 6
struct eth
{
    uint8_t dhost[ETHADDR_LEN];
    uint8_t shost[ETHADDR_LEN];
    uint16_t type;
} __attribute__((packed));

#define ETHTYPE_IP 0x0800  // Internet protocol
#define ETHTYPE_ARP 0x0806 // Address resolution protocol

// an IP packet header (comes after an Ethernet header).
struct ipv4
{
    uint8_t ip_vhl;  // version << 4 | header length >> 2
    uint8_t ip_tos;  // type of service
    uint16_t ip_len; // total length
    uint16_t ip_id;  // identification
    uint16_t ip_off; // fragment offset field
    uint8_t ip_ttl;  // time to live
    uint8_t ip_p;    // protocol
    uint16_t ip_sum; // checksum
    uint32_t ip_src, ip_dst;
};

#define NF_IPPROTO_ICMP 1 // Control message protocol
#define NF_IPPROTO_TCP 6  // Transmission control protocol
#define NF_IPPROTO_UDP 17 // User datagram protocol

#define MAKE_IP_ADDR(a, b, c, d)                 \
    (((uint32_t)a << 24) | ((uint32_t)b << 16) | \
     ((uint32_t)c << 8) | (uint32_t)d)

// a UDP packet header (comes after an IP header).

struct udp
{
    uint16_t sport; // source port
    uint16_t dport; // destination port
    uint16_t ulen;  // length, including udp header, not including IP header
    uint16_t sum;   // checksum
};

// end of header definiton

struct Packet
{
    uint8_t *data;
    size_t len;
    // ethernet layer
    struct eth *get_eth_hdr();

    struct ipv4 *get_ipv4_hdr();

    struct udp *get_udp_hdr();

    Packet(uint8_t *_data, size_t _len) : data(_data), len(_len) {}
};

extern struct Packet **p;

constexpr int MAX_PACKETS_NUM = 10000000;

class PacketsLoader
{
private:
    Packet *_packets[MAX_PACKETS_NUM];
    uint64_t _total_packets;
    uint64_t _cur_idx;
    uint64_t _total_bytes_count;
    /* data */
public:
    explicit PacketsLoader(std::string &&filepath);

    PacketsLoader(PacketsLoader &) = delete;
    // return nullptr if there is no more packet
    Packet *get_next_packet();
};
// #define NF_DEBUG
#endif