# binary name
AGGREGATOR_TEST_NAME = aggregator_test
FIREWALL_TEST_NAME = firewall_test

# all source are stored in SRCS-y
SRCS-y :=  ../aggregator.c ../network_function_dpdk/pkt_gen.c ../config.c ../network_function_dpdk/common.c
SRCS-fw :=  firewall_test.c $(SRCS-y) ../network_function_dpdk/firewall.c
SRCS-agg := aggregator_test.c $(SRCS-y)
HEADERS := ../aggregator.h ../dpdk_app.h
PKGCONF ?= pkg-config

$(echo $(SRCS-fw))

# Build using pkg-config variables if possible
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

all: agg_shared fw_shared
.PHONY: agg_shared agg_static fw_shared fw_static
agg_shared: build/$(AGGREGATOR_TEST_NAME)-shared
	ln -sf $(AGGREGATOR_TEST_NAME)-shared build/$(AGGREGATOR_TEST_NAME)
agg_static: build/$(AGGREGATOR_TEST_NAME)-static
	ln -sf $(AGGREGATOR_TEST_NAME)-static build/$(AGGREGATOR_TEST_NAME)

fw_shared: build/$(FIREWALL_TEST_NAME)-shared
	ln -sf $(FIREWALL_TEST_NAME)-shared build/$(FIREWALL_TEST_NAME)
fw_static: build/$(FIREWALL_TEST_NAME)-static
	ln -sf $(FIREWALL_TEST_NAME)-static build/$(FIREWALL_TEST_NAME)

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk)

ifeq ($(MAKECMDGOALS),static)
# check for broken pkg-config
ifeq ($(shell echo $(LDFLAGS_STATIC) | grep 'whole-archive.*l:lib.*no-whole-archive'),)
$(warning "pkg-config output list does not contain drivers between 'whole-archive'/'no-whole-archive' flags.")
$(error "Cannot generate statically-linked binaries with this version of pkg-config")
endif
endif

CFLAGS += -DALLOW_EXPERIMENTAL_API -g

build/$(AGGREGATOR_TEST_NAME)-shared: $(SRCS-agg) Makefile $(PC_FILE) $(HEADERS) | build
	$(CC) $(CFLAGS) $(SRCS-agg) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED) -lpcap

build/$(AGGREGATOR_TEST_NAME)-static: $(SRCS-agg) Makefile $(PC_FILE) $(HEADERS) | build
	$(CC) $(CFLAGS) $(SRCS-agg) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC) -lpcap

build/$(FIREWALL_TEST_NAME)-shared: $(SRCS-fw) Makefile $(PC_FILE) $(HEADERS) | build
	$(CC) $(CFLAGS) $(SRCS-fw) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED) -lpcap

build/$(FIREWALL_TEST_NAME)-static: $(SRCS-fw) Makefile $(PC_FILE) $(HEADERS) | build
	$(CC) $(CFLAGS) $(SRCS-fw) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC) -lpcap

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(AGGREGATOR_TEST_NAME) build/$(AGGREGATOR_TEST_NAME)-static build/$(AGGREGATOR_TEST_NAME)-shared \
	build/$(FIREWALL_TEST_NAME) build/$(FIREWALL_TEST_NAME)-static build/$(FIREWALL_TEST_NAME)-shared

	test -d build && rmdir -p build || true
