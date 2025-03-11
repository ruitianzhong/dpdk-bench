#include "common.hpp"
#include <cassert>
#include <cstdio>
#include <string>
#include <pcap/pcap.h>
#include <iostream>
#include <cstring>

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
// We use pcap because it's easy to read the packet through tools like Wireshark
PacketsLoader::PacketsLoader(std::string &&filepath)
    : _cur_idx(0), _total_packets(0), _total_bytes_count(0)
{
    const char *path = filepath.c_str();
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(path, ebuf);
    if (!p)
    {
        std::string s = "pcap_open_offline " + std::string(ebuf);
        throw s;
    }

    pcap_pkthdr pkthdr;
    const u_char *pkt = nullptr;

    while (!(pkt = pcap_next(p, &pkthdr)))
    {
        std::cout << "header length: " << pkthdr.len << std::endl;
        uint8_t *buf = (uint8_t *)malloc(pkthdr.len);
        if (!buf)
        {

            std::cout << "failed to allocate function @" << __func__ << std::endl;
            throw "failed to load data";
        }

        std::memcpy(buf, pkt, pkthdr.len);
        Packet *packet = new Packet(buf, pkthdr.len);
        _total_bytes_count += pkthdr.len;
        _packets[_total_packets++] = packet;
        _total_packets += 1;

        // pkt may become invalid after pcap_next, according to man page
        // It's the callee's duty to free  pkt, not the caller
    }
    pcap_close(p);
}

Packet *PacketsLoader::get_next_packet()
{
    if(_cur_idx < _total_packets){
        return this->_packets[_cur_idx++];
    }
    return nullptr;
}
