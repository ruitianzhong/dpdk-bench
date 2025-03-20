#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_lcore_var.h>
#include <rte_spinlock.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>

#define DEFAULT_HASH_FUNC rte_hash_crc
#define HASH_ENTRIES 2048
#include "aggregator.h"
#include <rte_memory.h>
#include "../util.h"

#include <stdio.h>
#include <stddef.h>
#include <rte_malloc.h>
#include <rte_acl.h>
// ACL reference https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html
#define MAX_ACL_RULES 20000

enum
{
    FIREWALL_ALLOW
};


// To achieve zero-copy in the data path here
struct rte_acl_field_def ipv4_defs[5] = {
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof(uint8_t),
        .field_index = 0,
        .input_index = 0,
        .offset = 0,
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = 1,
        .input_index = 2,
        .offset = offsetof(struct rte_ipv4_hdr, src_addr) - offsetof(struct rte_ipv4_hdr, next_proto_id),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = 2,
        .input_index = 3,
        .offset = offsetof(struct rte_ipv4_hdr, dst_addr) - offsetof(struct rte_ipv4_hdr, next_proto_id),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = 3,
        .input_index = 4,
        .offset = sizeof(struct rte_ipv4_hdr) - offsetof(struct rte_ipv4_hdr, next_proto_id),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = 4,
        .input_index = 4,
        .offset = sizeof(struct rte_ipv4_hdr) - offsetof(struct rte_ipv4_hdr, next_proto_id) + sizeof(uint16_t),
    }

};

RTE_ACL_RULE_DEF(acl_ipv4_rule, RTE_DIM(ipv4_defs));

struct firewall
{
    struct rte_acl_ctx *acl_ctx;

    // used for rte_acl_
    uint32_t num_ipv4;
    uint32_t num_rule;

    uint8_t types[MAX_PKT_BURST];

    const uint8_t *data_ipv4[MAX_PKT_BURST];
    uint32_t res_ipv4[MAX_PKT_BURST];
};

int read_acl_from_file(char *filename, size_t len)
{
}

struct firewall *firewall_create()
{
    struct firewall *fw;

    fw = rte_zmalloc("firewall_ctx", sizeof(struct firewall), 0);

    if (NULL == fw)
    {
        rte_exit(EXIT_FAILURE, "failed to allocate firewall");
    }
    struct rte_acl_ctx *acx;
    struct rte_acl_config cfg;
    int ret;

    struct rte_acl_param param = {
        .name = "firewall_acl",
        .socket_id = SOCKET_ID_ANY,
        .rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs)),
        .max_rule_num = 8,
    };
    struct acl_ipv4_rule acl_rules[] = {
        {
            .data = {.userdata = 1, .category_mask = 1, .priority = 1},
            .field[2] = {
                .value.u32 = RTE_IPV4(192, 168, 0, 0),
                .mask_range.u32 = 16,
            },
            .field[3] = {
                .value.u16 = 0,
                .mask_range.u16 = 0xffff,
            },
            .field[4] = {
                .value.u16 = 0,
                .mask_range.u16 = 0xffff,
            },
        }};
    if ((acx = rte_acl_create(&param)) == NULL)
    {
        rte_exit(EXIT_FAILURE, "failed to create acl context");
    }

    ret = rte_acl_add_rules(acx, acl_rules, RTE_DIM(acl_rules));
    if (ret != 0)
    {
        rte_exit(EXIT_FAILURE, "failed to add rules");
    }

    cfg.num_categories = 1;
    cfg.num_fields = RTE_DIM(ipv4_defs);

    memcpy(cfg.defs, ipv4_defs, sizeof(ipv4_defs));

    ret = rte_acl_build(acx, &cfg);

    if (ret != 0)
    {
        rte_exit(EXIT_FAILURE, "fail to build acl");
    }
    rte_acl_dump(acx);
    fw->acl_ctx = acx;

    // rte_acl_classify(acx, data, results, 1, 4);
    return fw;
}
// From my perspective, category is similar to `namespace`

void firewall_free(struct firewall *fw)
{
    if (NULL==fw){
        return;
    }

    rte_acl_free(fw->acl_ctx);

    rte_free(fw);
}

static int process_packet(struct firewall * fw,uint16_t *data, size_t length)
{
}
