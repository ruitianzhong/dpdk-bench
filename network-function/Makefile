CXXFLAGS := -g -O3
CXX := g++

.PHONY: clean

nat: nat_udp_v4 util
	${CXX} ${CXXFLAGS} -o nat  nat_udp_v4.o packet.o


nat_udp_v4: nat_udp_v4.cpp
	${CXX} -c ${CFLAGS} nat_udp_v4.cpp


util: util/packet.cpp util/common.hpp
	${CXX} -c ${CFLAGS} util/packet.cpp

clean:
	rm -f ./*.o util/*.o 

