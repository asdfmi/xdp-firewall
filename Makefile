BPF_CLANG ?= clang
BPF_ARCH ?= x86
BPFTARGET := build/xdp_labeler.bpf.o
XDPBLE_BIN := build/xdp-labeling
BPF_SRC := bpf/xdp_labeler.bpf.c

BPFOBJECTS := $(BPFTARGET)

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

LIBBPF_CFLAGS += -Ibuild -Iheaders

all: $(XDPBLE_BIN) $(AGENT_BIN)

build:
	@mkdir -p build

SYS_INCLUDES := /usr/include /usr/include/$(shell uname -m)-linux-gnu

build/vmlinux.h: | build
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPFTARGET): $(BPF_SRC) headers/label_meta.h headers/rule.h build/vmlinux.h | build
	$(BPF_CLANG) -g -O2 -target bpf \
		-D__TARGET_ARCH_$(BPF_ARCH) \
		-Ibuild -Iheaders -I. \
		$(addprefix -isystem ,$(SYS_INCLUDES)) \
		-c $< -o $@

CLI_DIR := cli
LIB_DIR := lib

CLI_SOURCES := $(CLI_DIR)/params.c \
	$(CLI_DIR)/cmd/add.c \
	$(CLI_DIR)/cmd/attach.c \
	$(CLI_DIR)/cmd/detach.c \
	$(CLI_DIR)/cmd/help.c \
	$(CLI_DIR)/cmd/list.c \
	$(CLI_DIR)/cmd/log.c \
	$(CLI_DIR)/xdp-labeling.c

LIB_SOURCES := $(LIB_DIR)/xdp_labeling.c

CLI_CPPFLAGS := -Iheaders -I$(CLI_DIR)
AGENT_DIR := agent
AGENT_SOURCES := $(AGENT_DIR)/xdp-agent.c \
	$(AGENT_DIR)/options.c
AGENT_CPPFLAGS := -Iheaders -I$(AGENT_DIR)
AGENT_BIN := build/xdp-agent

TEST_DIR := tests
TEST_SOURCES := $(wildcard $(TEST_DIR)/integration/*.c)
TEST_BINS := $(patsubst $(TEST_DIR)/integration/%.c, build/tests/integration/%, $(TEST_SOURCES))
TEST_CPPFLAGS := -Iheaders

$(XDPBLE_BIN): $(CLI_SOURCES) $(LIB_SOURCES) $(BPFTARGET) | build
	$(CC) -g -O2 -Wall -Wextra -std=c11 \
		$(LIBBPF_CFLAGS) \
		$(LIBXDP_CFLAGS) \
		$(CLI_CPPFLAGS) \
	$(CLI_SOURCES) \
	$(LIB_SOURCES) \
	-o $@ \
	$(LIBBPF_LDLIBS) $(LIBXDP_LDLIBS)

$(AGENT_BIN): $(AGENT_SOURCES) $(LIB_SOURCES) $(BPFTARGET) | build
	$(CC) -g -O2 -Wall -Wextra -std=c11 \
		$(LIBBPF_CFLAGS) \
		$(LIBXDP_CFLAGS) \
		$(AGENT_CPPFLAGS) \
		$(AGENT_SOURCES) \
		$(LIB_SOURCES) \
		-o $@ \
		$(LIBBPF_LDLIBS) $(LIBXDP_LDLIBS)

build/tests/integration: | build
	@mkdir -p $@

build/tests/integration/%: $(TEST_DIR)/integration/%.c $(LIB_SOURCES) $(BPFTARGET) | build/tests/integration
	$(CC) -g -O2 -Wall -Wextra -std=c11 \
		$(LIBBPF_CFLAGS) \
		$(LIBXDP_CFLAGS) \
		$(TEST_CPPFLAGS) \
		$< \
		$(LIB_SOURCES) \
		-o $@ \
		$(LIBBPF_LDLIBS) $(LIBXDP_LDLIBS)

.PHONY: test
test: $(XDPBLE_BIN) $(TEST_BINS)
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
