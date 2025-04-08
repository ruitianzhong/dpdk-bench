CXXFLAGS := -g -O3 -Werror
CXX := g++

.PHONY: clean

all: nat
nat: nat_ipv4.o packet.o
	${CXX} ${CXXFLAGS} -o nat  nat_ipv4.o packet.o -lpcap

nat_ipv4.o: nat_ipv4.cpp Makefile
	${CXX} -c ${CXXFLAGS} nat_ipv4.cpp

packet.o: util/packet.cpp util/common.hpp Makefile
	${CXX} -c ${CXXFLAGS} util/packet.cpp

clean:
	rm -f ./*.o util/*.o nat

