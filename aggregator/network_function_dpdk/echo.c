// server echo back what the client send

#include "../aggregator.h"

static void echo_sender(thread_context_t *ctx) {}

static void echo_receiver(thread_context_t *ctx) {}

struct dpdk_app echo_app = {
    .receive = echo_receiver,
    .send = echo_sender,
};