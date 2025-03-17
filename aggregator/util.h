#ifndef _AGGREGATOR_UTIL
#define _AGGREGATOR_UTIL
#include <stdint.h>
#include <stddef.h>


struct packet
{
    uint8_t *data;
    size_t len;
    struct rte_mbuf *mbuf;
    TAILQ_ENTRY(packet)
    tailq;
};

struct __rte_packed_begin ipv4_5tuple
{
    uint32_t ip_dst;
    uint32_t ip_src;
    uint16_t port_dst;
    uint16_t port_src;
    uint8_t proto;
} __rte_packed_end;
#endif