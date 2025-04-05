#ifndef _AGGREGATOR_UTIL
#define _AGGREGATOR_UTIL
#include <stdint.h>
#include <stddef.h>

struct packet
{
    uint8_t *data;
    size_t len;
};

struct __attribute__((packed)) ipv4_5tuple {
  uint8_t proto;
  uint32_t ip_dst;
  uint32_t ip_src;
  uint16_t port_dst;
  uint16_t port_src;
};
inline static bool tuple_equal(struct ipv4_5tuple *t1, struct ipv4_5tuple *t2) {
  return t1->ip_dst == t2->ip_dst && t1->ip_src == t2->ip_src &&
         t1->port_dst == t2->port_dst && t1->port_src == t2->port_src &&
         t1->proto == t2->proto;
}
#endif