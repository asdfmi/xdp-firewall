# syntax=docker/dockerfile:1.4

##
## Builder stage
##
FROM ubuntu:24.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        make clang llvm gcc pkg-config \
        libelf-dev zlib1g-dev \
        libbpf-dev libxdp-dev \
        ca-certificates git curl \
        iproute2 jq && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY . .

# Generate vmlinux.h when it is not already present in the source tree.
# This step assumes BuildKit is used so we can temporarily bind-mount the
# host's BTF metadata into the build context.
RUN if [ -d build ]; then \
        find build -mindepth 1 -maxdepth 1 -exec rm -rf {} +; \
    fi
RUN if [ ! -f xdp/include/vmlinux.h ]; then \
        echo "xdp/include/vmlinux.h is missing – generate it before building images (e.g. via 'bpftool btf dump ... > xdp/include/vmlinux.h')." >&2; \
        exit 1; \
    fi

RUN make

# Install crictl in the image for runtime agent (used to resolve service pod PID)
ARG CRICTL_VERSION=v1.28.0
RUN set -e; \
    arch=$(dpkg --print-architecture); \
    case "$arch" in \
      amd64) arch2=amd64 ;; \
      arm64) arch2=arm64 ;; \
      *) arch2=amd64 ;; \
    esac; \
    url="https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-${arch2}.tar.gz"; \
    echo "Fetching crictl from $url"; \
    curl -fsSL "$url" -o /tmp/crictl.tgz; \
    tar -C /usr/local/bin -xzvf /tmp/crictl.tgz >/dev/null; \
    rm -f /tmp/crictl.tgz; \
    /usr/local/bin/crictl --version || true

##
## Runtime base
##
FROM builder AS runtime-base

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
COPY --from=builder /usr/sbin/ip /usr/sbin/ip

ENTRYPOINT ["/usr/local/bin/central"]

##
## Service runtime image
##
FROM runtime-base AS service

COPY --from=builder /src/build/service-health /usr/local/bin/service-health
COPY --from=builder /usr/sbin/ip /usr/sbin/ip

ENTRYPOINT ["/usr/local/bin/service-health"]

##
## CLI utility image
##
FROM runtime-base AS xdt

COPY --from=builder /src/build/xdt /usr/local/bin/xdt
COPY --from=builder /src/build/xdp.bpf.o /opt/xdt/build/xdp.bpf.o

ENTRYPOINT ["/usr/local/bin/xdt"]
