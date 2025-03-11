CXXFLAGS := -g -O3
CXX := g++

.PHONY: clean

nat: nat_udp_v4 util
	${CXX} ${CXXFLAGS} -o nat  nat_ipv4.o packet.o -lpcap


nat_udp_v4: nat_ipv4.cpp
	${CXX} -c ${CXXFLAGS} nat_ipv4.cpp


util: util/packet.cpp util/common.hpp
	${CXX} -c ${CXXFLAGS} util/packet.cpp

clean:
	rm -f ./*.o util/*.o nat ./scripts/*.pcap

