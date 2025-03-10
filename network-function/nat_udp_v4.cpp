#include <iostream>
#include <unordered_map>
#include "util/common.hpp"
#include <sys/unistd.h>
#include <sys/time.h>
#include <inttypes.h>
struct nat_context
{
    int count;
    NetworkTuple tuple;
};


// std::unordered_map<network_five_tuple, nat_context *> snat_map, dnat_map;
// we do not use the reserved port here though
constexpr int MIN_PORT_NUM = 1024;
constexpr int MAX_PORT_NUM = 65535;

// void process_packet(Packet *packet)
// {

// }

int main(int argc, char const *argv[])
{
    int current_port = MIN_PORT_NUM;
    struct timeval start_time, end_time;
    uint64_t total_us = 0;

    std::cout << "NAT processing start" << std::endl;
    gettimeofday(&start_time, NULL);
    int x = 0;
    // the killer microsecond
    std::cout << "The killer microsecond" << std::endl;

    gettimeofday(&end_time, NULL);
    std::cout << "NAT processing end";

    total_us = (end_time.tv_sec - start_time.tv_sec) * 1000000 + (end_time.tv_usec - start_time.tv_usec);

    std::cout << "Total time is " << total_us << std::endl;

    return 0;
}
