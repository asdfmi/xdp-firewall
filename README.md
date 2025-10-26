# XDP Telemetry (PoC)

This repository contains a monorepo PoC that applies XDP/eBPF to label packets, forwards traffic back to the service path using `AF_XDP` zero-copy rings, and streams metadata to a central telemetry server with a lightweight UI. The project is organised as modular components so it can later be split into separate services if needed.

## Components

- **xdp/** — eBPF program (`xdp/bpf/xdp_labeler.bpf.c`) and user-space helpers (`xdp/lib/xdt_telemetry.c`, headers under `xdp/include/`).
- **agent/** — `xdt-agent` binary. Attaches to the pinned maps, receives events via `AF_XDP`, reinjects packets, and streams telemetry records to the central server. Command-line options are parsed in `agent/options.c`.
- **central/** — Telemetry server. Receives binary telemetry streams, keeps in-memory statistics per agent, exposes `/metrics.json`, and serves the dashboard UI under `central/ui/static/`.
- **service/** — Minimal HTTP health server that listens on `/healthz`; acts as a placeholder for the protected business application.
- **cli/** — `xdt` CLI tool for attach/detach, rule management, and debugging (uses the shared library under `xdp/`).
- **common/** — Shared telemetry encoder/decoder (`common/telemetry`), used by both agent and central.
- **k8s/** — Sample Kubernetes manifests (DaemonSet for the agent, Deployments/Services for central and the sample service).

## Build

Dependencies: `clang`, `bpftool`, `libbpf`, `libxdp`, standard POSIX toolchain.

```bash
make
```

Artifacts are placed in `build/`:

- `build/xdt` — CLI
- `build/xdt-agent` — agent daemon
- `build/central` — telemetry + UI server
- `build/service-health` — sample service
- `build/xdp_labeler.bpf.o` — compiled eBPF program

## Local PoC Walkthrough

1. Attach the XDP program and pin maps using the CLI:
   ```bash
   sudo build/xdt attach --interface <ifname>
   ```
2. Insert IPv4 rules as needed (e.g. `build/xdt add ...`).
3. Start the telemetry server:
   ```bash
   ./build/central 50051 8080   # telemetry port, HTTP UI port
   ```
4. Start the agent (requires root, interface, central endpoint, optional agent id):
   ```bash
   sudo ./build/xdt-agent \
     --interface <ifname> \
     --central 127.0.0.1:50051 \
     --agent-id $(hostname)
   ```
5. Run the demo service:
   ```bash
   ./build/service-health 8081
   ```
6. Generate some traffic to the service (`curl http://localhost:8081/healthz`).
7. Open the dashboard: `http://localhost:8080/` to see per-agent charts and recent events.

Detach when finished:
```bash
sudo build/xdt detach --interface <ifname>
```

## Kubernetes Sample

Sample manifests are provided in the `k8s/` directory:

- `daemonset-xdt-agent.yaml` — deploys `xdt-agent` as a privileged DaemonSet. The init container runs `xdt attach`, and a `preStop` hook detaches the program.
- `central-deployment.yaml` — deploys the telemetry server and exposes telemetry (`50051`) and UI (`8080`).
- `service-deployment.yaml` — deploys the sample health-check service on port `8081`.

Before applying, adapt the following to your cluster:

1. Build and push container images for `xdt-agent`, `xdt` (CLI for attach/detach), `central`, and `service-health` to your registry (`image:` fields are placeholders).
2. Set the interface name used on worker nodes (`INTERFACE_NAME` env var / args). For heterogeneous environments you may need node labels and per-node configuration.
3. Ensure nodes run with kernel/driver support for the XDP mode you intend to use. The DaemonSet requires `privileged` pods, host networking, and access to `/sys/fs/bpf` (mounted via `hostPath`).
4. Apply manifests:
   ```bash
   kubectl apply -f k8s/
   ```
5. Verify:
   - `kubectl get pods -l app=xdt-agent` (one per node)
   - `kubectl get svc central` (telemetry/UI service)
   - `kubectl port-forward svc/central 8080:8080` and open `http://localhost:8080/` to inspect the dashboard.

## Telemetry UI

- `/metrics.json` returns `{ total_events, nodes: [ { agent_id, total_events, label_counts[], recent_events[] } ] }`.
- The UI (served at `/`) fetches JSON every second, renders per-agent bar charts (label distribution), a timeline chart (payload size vs timestamp), and a table of recent events.
