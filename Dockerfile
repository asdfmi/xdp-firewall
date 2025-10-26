# syntax=docker/dockerfile:1.4

##
## Builder stage
##
FROM ubuntu:22.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        make clang llvm gcc pkg-config \
        libelf-dev zlib1g-dev \
        libbpf-dev \
        ca-certificates git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY . .

# Generate vmlinux.h when it is not already present in the source tree.
# This step assumes BuildKit is used so we can temporarily bind-mount the
# host's BTF metadata into the build context.
RUN if [ ! -f build/vmlinux.h ]; then \
        echo "build/vmlinux.h is missing – generate it before building images (e.g. via 'bpftool btf dump ... > build/vmlinux.h')." >&2; \
        exit 1; \
    fi

RUN make LIBXDP_CFLAGS= LIBXDP_LDLIBS=

##
## Runtime base
##
FROM ubuntu:22.04 AS runtime-base

ARG DEBIAN_FRONTEND=noninteractive

# Runtime images need libbpf shared objects; copy them
# from the builder stage where they were installed alongside headers.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libelf1 \
        zlib1g && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/lib/x86_64-linux-gnu/libbpf.so.* /usr/lib/x86_64-linux-gnu/

WORKDIR /opt/xdt
RUN mkdir -p build central/ui/static

##
## Agent runtime image
##
FROM runtime-base AS agent

COPY --from=builder /src/build/xdt-agent /usr/local/bin/xdt-agent
COPY --from=builder /src/build/xdt /usr/local/bin/xdt
COPY --from=builder /src/build/xdp.bpf.o /opt/xdt/build/xdp.bpf.o

ENTRYPOINT ["/usr/local/bin/xdt-agent"]

##
## Central runtime image
##
FROM runtime-base AS central

COPY --from=builder /src/build/central /usr/local/bin/central
COPY --from=builder /src/central/ui/static /opt/xdt/central/ui/static

ENTRYPOINT ["/usr/local/bin/central"]

##
## Service runtime image
##
FROM runtime-base AS service

COPY --from=builder /src/build/service-health /usr/local/bin/service-health

ENTRYPOINT ["/usr/local/bin/service-health"]

##
## CLI utility image
##
FROM runtime-base AS xdt

COPY --from=builder /src/build/xdt /usr/local/bin/xdt
COPY --from=builder /src/build/xdp.bpf.o /opt/xdt/build/xdp.bpf.o

ENTRYPOINT ["/usr/local/bin/xdt"]
