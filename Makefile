BPF_CLANG ?= clang
BPF_ARCH ?= x86
BPFTARGET := build/xdp_firewall.bpf.o
SKEL_HEADER := src/xdp_firewall.skel.h
XDPFW_BIN := build/xdpfw

BPFOBJECTS := $(BPFTARGET)

LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LDLIBS ?= $(shell pkg-config --libs libbpf 2>/dev/null)

ifeq ($(strip $(LIBBPF_CFLAGS)),)
LIBBPF_CFLAGS :=
endif

ifeq ($(strip $(LIBBPF_LDLIBS)),)
LIBBPF_LDLIBS := -lbpf -lelf -lz
endif

LIBBPF_CFLAGS += -Iinclude

all: $(XDPFW_BIN)

build:
	@mkdir -p build

SYS_INCLUDES := /usr/include /usr/include/$(shell uname -m)-linux-gnu

$(BPFTARGET): src/xdp_firewall.bpf.c include/log_event.h vmlinux.h | build
	$(BPF_CLANG) -g -O2 -target bpf \
		-D__TARGET_ARCH_$(BPF_ARCH) \
		-Iinclude -I. \
		$(addprefix -isystem ,$(SYS_INCLUDES)) \
		-c $< -o $@

$(SKEL_HEADER): $(BPFTARGET)
	bpftool gen skeleton $< > $@

$(XDPFW_BIN): src/xdpfw.c $(SKEL_HEADER) | build
	$(CC) -g -O2 -Wall -Wextra -std=c11 \
		-Iinclude \
		$(LIBBPF_CFLAGS) \
		src/xdpfw.c \
		-o $@ \
		$(LIBBPF_LDLIBS)

.PHONY: clean
clean:
	rm -rf build
	rm -f $(SKEL_HEADER)
