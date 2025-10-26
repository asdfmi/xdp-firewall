# XDP Telemetry (PoC)

This repository contains a monorepo PoC that applies XDP/eBPF to label packets, forwards traffic back to the service path using `AF_XDP` zero-copy rings, and streams metadata to a central telemetry server with a lightweight UI. The project is organised as modular components so it can later be split into separate services if needed.

## Components

- **xdp/** — eBPF program (`xdp/bpf/xdp.bpf.c`) and user-space helpers (`xdp/lib/xdp_telemetry.c`, headers under `xdp/include/`).
- **agent/** — `xdt-agent` binary. Attaches to the pinned maps, receives events via `AF_XDP`, reinjects packets, and streams telemetry records over a length-prefixed TCP channel to the central server. Command-line options are parsed inline with the shared params helper.
- **central/** — Telemetry server. Accepts the length-prefixed telemetry frames, keeps in-memory statistics per agent, exposes `/metrics.json`, and serves the dashboard UI under `central/ui/static/`.
- **service/** — Minimal HTTP health server that listens on `/healthz`; acts as a placeholder for the protected business application.
- **xdt/** — `xdt` CLI tool for attach/detach, rule management, and debugging (uses the shared library under `xdp/`).
- **common/** — Shared telemetry encoder/decoder (`common/telemetry`) and command-line parser (`common/cli`), used by agent and CLI.
- **k8s/** — Sample Kubernetes manifests (DaemonSet for the agent, Deployments/Services for central and the sample service).

## Build

Dependencies: `clang`, `bpftool`, `libbpf`, standard POSIX toolchain.

```bash
make
```

Artifacts are placed in `build/`:

- `build/xdt` — CLI
- `build/xdt-agent` — agent daemon
- `build/central` — telemetry + UI server
- `build/service-health` — sample service
- `build/xdp.bpf.o` — compiled eBPF program

## Kubernetes Sample (kind)

Sample manifests live in `k8s/`. You can exercise them locally with a kind cluster:

1. Install [kind](https://kind.sigs.k8s.io/) and create a cluster (requires Docker):
   ```bash
   kind create cluster --name xdt --config k8s/cluster/kind-config.yaml
   export DOCKER_BUILDKIT=1
   make docker-images DOCKER_IMAGE_PREFIX=xdt
   kind load docker-image xdt-agent:latest xdt-central:latest xdt-service:latest xdt-xdt:latest --name xdt
   ```
2. Update the interface if needed (`k8s/daemonset-xdt-agent.yaml` defaults to `eth0` inside kind nodes).
3. Apply the manifests:
   ```bash
   kubectl apply -f k8s/
   ```
4. Verify the rollout:
   - `kubectl get pods -n default -o wide`
   - `kubectl get svc central xdt-service`
   - `kubectl port-forward svc/central 8080:8080` and browse `http://localhost:8080/`.
   - `kubectl run curl-test --rm -it --image=curlimages/curl -- curl -s http://xdt-service:8081/`
5. Tear down when finished:
   ```bash
   kind delete cluster --name xdt
   ```

## Telemetry UI

- `/metrics.json` returns `{ total_events, nodes: [ { agent_id, total_events, label_counts[], recent_events[] } ] }`.
- The UI (served at `/`) fetches JSON every second, renders per-agent bar charts (label distribution), a timeline chart (payload size vs timestamp), and a table of recent events.
