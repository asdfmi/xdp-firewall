BPF_CLANG ?= clang
BPF_ARCH ?= x86

CC ?= gcc
CXX ?= g++

CFLAGS ?= -g -O2 -Wall -Wextra -std=c11
CXXFLAGS ?= -g -O2 -Wall -Wextra -std=c++17
CPPFLAGS ?=

CPPFLAGS += -I. -Ixdp/include -Ibuild -Ixdt -Iagent -Icommon -Icommon/cli

LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LDLIBS ?= $(shell pkg-config --libs libbpf 2>/dev/null)
LIBXDP_CFLAGS ?= $(shell pkg-config --cflags libxdp 2>/dev/null)
LIBXDP_LDLIBS ?= $(shell pkg-config --libs libxdp 2>/dev/null)
ifeq ($(strip $(LIBBPF_CFLAGS)),)
LIBBPF_CFLAGS :=
endif

ifeq ($(strip $(LIBBPF_LDLIBS)),)
LIBBPF_LDLIBS := -lbpf -lelf -lz
endif

ifeq ($(strip $(LIBXDP_CFLAGS)),)
LIBXDP_CFLAGS :=
endif

ifeq ($(strip $(LIBXDP_LDLIBS)),)
LIBXDP_LDLIBS := -lxdp
endif

THREAD_LDLIBS ?= -pthread

BPFTARGET := build/xdp.bpf.o
BPF_SRC := xdp/bpf/xdp.bpf.c

COMMON_CLI_SOURCES := \
	common/cli/params.c

CLI_SOURCES := \
	xdt/cmd/add.c \
	xdt/cmd/attach.c \
	xdt/cmd/detach.c \
	xdt/cmd/help.c \
	xdt/cmd/list.c \
	xdt/cmd/log.c \
	xdt/xdt.c

LIB_SOURCES := \
	xdp/lib/xdp_telemetry.c

AGENT_C_SOURCES := \
	agent/xdt-agent.c \
	agent/telemetry_client.c

TELEMETRY_C_SOURCES := \
	common/telemetry/telemetry.c

CENTRAL_SOURCES := \
    central/main.c \
    central/http_server.c \
    central/store.c

SERVICE_SOURCES := \
	service/health-server.c

TEST_SOURCES := $(wildcard xdp/tests/integration/*.c)

OBJDIR := build/obj

COMMON_CLI_OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(COMMON_CLI_SOURCES))

CLI_OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(CLI_SOURCES)) \
	$(COMMON_CLI_OBJS)
LIB_OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(LIB_SOURCES))
TELEMETRY_OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(TELEMETRY_C_SOURCES))

AGENT_OBJS := \
	$(patsubst %.c,$(OBJDIR)/%.o,$(AGENT_C_SOURCES)) \
	$(COMMON_CLI_OBJS) \
	$(TELEMETRY_OBJS)
CENTRAL_OBJS := \
	$(patsubst %.c,$(OBJDIR)/%.o,$(CENTRAL_SOURCES)) \
	$(TELEMETRY_OBJS)
SERVICE_OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(SERVICE_SOURCES))

TEST_BINS := $(patsubst xdp/tests/integration/%.c,build/tests/integration/%,$(TEST_SOURCES))

XDT_BIN := build/xdt
AGENT_BIN := build/xdt-agent
CENTRAL_BIN := build/central
SERVICE_BIN := build/service-health

SYS_INCLUDES := /usr/include /usr/include/$(shell uname -m)-linux-gnu

.PHONY: all
all: $(XDT_BIN) $(AGENT_BIN) $(CENTRAL_BIN) $(SERVICE_BIN)

build:
	@mkdir -p build

build/tests:
	@mkdir -p build/tests

build/tests/integration: | build/tests
	@mkdir -p $@

$(OBJDIR):
	@mkdir -p $(OBJDIR)

build/vmlinux.h: | build
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPFTARGET): $(BPF_SRC) xdp/include/label_meta.h xdp/include/rule.h build/vmlinux.h | build
	$(BPF_CLANG) -g -O2 -target bpf \
		-D__TARGET_ARCH_$(BPF_ARCH) \
		-Ibuild -Ixdp/include -I. \
		$(addprefix -isystem ,$(SYS_INCLUDES)) \
		-c $< -o $@

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LIBBPF_CFLAGS) $(LIBXDP_CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: %.cc | $(OBJDIR)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LIBBPF_CFLAGS) $(LIBXDP_CFLAGS) -c $< -o $@

$(XDT_BIN): $(CLI_OBJS) $(LIB_OBJS) $(BPFTARGET) | build
	$(CC) $(CFLAGS) $(CLI_OBJS) $(LIB_OBJS) -o $@ \
		$(LIBBPF_LDLIBS) $(LIBXDP_LDLIBS)


$(AGENT_BIN): $(AGENT_OBJS) $(LIB_OBJS) $(BPFTARGET) | build
	$(CC) $(CFLAGS) $(AGENT_OBJS) $(LIB_OBJS) -o $@ \
		$(LIBBPF_LDLIBS) $(LIBXDP_LDLIBS)

$(CENTRAL_BIN): $(CENTRAL_OBJS) | build
	$(CC) $(CFLAGS) $(CENTRAL_OBJS) -o $@ $(THREAD_LDLIBS)

$(SERVICE_BIN): $(SERVICE_OBJS) | build
	$(CC) $(CFLAGS) $(SERVICE_OBJS) -o $@ $(THREAD_LDLIBS)

build/tests/integration/%: xdp/tests/integration/%.c $(LIB_OBJS) $(BPFTARGET) | build/tests/integration
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LIBBPF_CFLAGS) $(LIBXDP_CFLAGS) $< $(LIB_OBJS) -o $@ \
		$(LIBBPF_LDLIBS) $(LIBXDP_LDLIBS)

.PHONY: test
test: $(XDT_BIN) $(TEST_BINS)
	@failed=0; \
	for t in $(TEST_BINS); do \
		"$$t"; \
		status=$$?; \
		if [ $$status -eq 0 ]; then \
			echo "$$t PASS"; \
		elif [ $$status -eq 77 ]; then \
			echo "$$t SKIP"; \
		else \
			echo "$$t FAIL"; \
			failed=1; \
		fi; \
	done; \
	exit $$failed

.PHONY: clean
clean:
	rm -rf build

.PHONY: cleanup
cleanup:
	@$(MAKE) clean
	@$(MAKE) all
