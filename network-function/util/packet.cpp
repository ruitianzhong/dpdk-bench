#include "common.hpp"
#include <cassert>
#include <string>

// It just works
udp *Packet::get_udp_hdr()
{
    assert(len >= sizeof(ipv4) + sizeof(eth) + sizeof(udp));
    return (udp *)(data + sizeof(ipv4) + sizeof(eth));
}

ipv4 *Packet::get_ipv4_hdr()
{
    assert(len >= (sizeof(ipv4) + sizeof(eth)));
    return (ipv4 *)(data + sizeof(eth));
}

eth *Packet::get_eth_hdr()
{
    assert(len >= sizeof(eth));
    return (eth *)data;
}

PacketsLoader::PacketsLoader(std::string &filepath)
    : _cur_idx(0), _total_packets(0), _total_bytes_count(0)
{
    
}

bool PacketsLoader::have_next()
{
    return _cur_idx < _total_packets;
}
