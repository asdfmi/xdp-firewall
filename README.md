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

Dependencies: `clang`, `bpftool`, `libbpf`, `libxdp`, standard POSIX toolchain.

```bash
make
```

Artifacts are placed in `build/`:

- `build/xdt` — CLI
- `build/xdt-agent` — agent daemon
- `build/central` — telemetry + UI server
- `build/service-health` — sample service
- `build/xdp.bpf.o` — compiled eBPF program

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

## Kubernetes Sample (kind)

Sample manifests live in `k8s/`. You can exercise them locally with a kind cluster:

1. Install [kind](https://kind.sigs.k8s.io/) and create a cluster (requires Docker):
   ```bash
   kind create cluster --name xdt
   kind load docker-image <your-registry>/xdt-agent:latest
   kind load docker-image <your-registry>/xdt:latest
   kind load docker-image <your-registry>/central:latest
   kind load docker-image <your-registry>/service-health:latest
   ```
2. Update the manifests with your image names and the interface to attach on each node (kind nodes typically expose `eth0` inside the container).
3. Apply the manifests:
   ```bash
   kubectl apply -f k8s/
   ```
4. Verify the rollout:
   - `kubectl get pods -n default -l app=xdt-agent`
   - `kubectl get svc central`
   - `kubectl port-forward svc/central 8080:8080` and browse `http://localhost:8080/`.
5. Tear down when finished:
   ```bash
   kind delete cluster --name xdt
   ```

## Telemetry UI

- `/metrics.json` returns `{ total_events, nodes: [ { agent_id, total_events, label_counts[], recent_events[] } ] }`.
- The UI (served at `/`) fetches JSON every second, renders per-agent bar charts (label distribution), a timeline chart (payload size vs timestamp), and a table of recent events.
