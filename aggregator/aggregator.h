#ifndef _AGGREGATOR_H
#define _AGGREGATOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include "util.h"
#define MAX_PKT_BURST 64
#define MAX_FLOW_PER_CORE 4096
#define MAX_AGGREGATE_PER_FLOW 16
#define READY_QUEUE_RESERVED 4096

TAILQ_HEAD(packet_head, packet);
TAILQ_HEAD(flow_entry_head, flow_entry);
struct flow_entry
{
    uint64_t created_tsc;
    int total_byte_count;

    int pkt_cnt;
    struct packet *pkts[MAX_AGGREGATE_PER_FLOW];
    int nb_max_per_flow_batch_size;
    struct packet_head head;
    TAILQ_ENTRY(flow_entry)
    tailq;
};

struct aggregator
{
    /* data */

    struct rte_hash *cucko_hashtable;

    struct flow_entry *entries;

    struct packet_head ready_queue;

    struct flow_entry_head flow_list;

    int flow_burst_max;

    uint64_t buffer_time_us;
};

#endif


