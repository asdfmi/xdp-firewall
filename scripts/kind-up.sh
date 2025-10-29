#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)

KIND_CLUSTER_NAME=xdt
AGENT_INTERFACE=eth0
UI_NODE_PORT=30080
SERVICE_NODE_PORT=30081
UI_HOST_PORT=8090
SERVICE_HOST_PORT=8091
CENTRAL_TELEMETRY_PORT=50051
CENTRAL_HTTP_PORT=8080
SERVICE_PORT=8081

if kind get clusters 2>/dev/null | grep -qx "${KIND_CLUSTER_NAME}"; then
  echo "error: kind cluster '${KIND_CLUSTER_NAME}' already exists" >&2
  exit 1
fi

echo "Creating kind cluster '${KIND_CLUSTER_NAME}'"
tmp_config=$(mktemp)
trap 'rm -f "${tmp_config}"' EXIT
cat >"${tmp_config}" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: ${UI_NODE_PORT}
        hostPort: ${UI_HOST_PORT}
        protocol: TCP
      - containerPort: ${SERVICE_NODE_PORT}
        hostPort: ${SERVICE_HOST_PORT}
        protocol: TCP
  - role: worker
  - role: worker
EOF
kind create cluster --name "${KIND_CLUSTER_NAME}" --config "${tmp_config}"

echo "Waiting for Kubernetes API to become available"
for attempt in {1..60}; do
  if kubectl get nodes >/dev/null 2>&1; then
    break
  fi
  if [[ ${attempt} -eq 60 ]]; then
    echo "error: kubectl could not reach the cluster API" >&2
    exit 1
  fi
  sleep 2
done

echo "Waiting for nodes to report Ready"
kubectl wait --for=condition=Ready node --all --timeout=180s >/dev/null

echo "Labeling worker nodes for telemetry scheduling"
kubectl label node xdt-worker xdt-worker2 xdt-telemetry=true --overwrite >/dev/null

echo "Building and loading container images into kind"
make -C "${REPO_ROOT}" KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME}" kind-docker-load

echo "Applying Kubernetes resources"
cat <<EOF | kubectl apply -f -
---
apiVersion: v1
kind: Pod
metadata:
  name: xdt-cli
  labels:
    app: xdt-cli
spec:
  hostNetwork: true
  hostPID: true
  dnsPolicy: ClusterFirstWithHostNet
  nodeSelector:
    kubernetes.io/hostname: xdt-worker
  initContainers:
    - name: mount-bpffs
      image: alpine:3.19
      securityContext:
        privileged: true
      command:
        - sh
        - -c
        - |
          set -e
          apk add --no-cache util-linux >/dev/null
          nsenter --target 1 --mount -- mkdir -p /sys/fs/bpf || true
          nsenter --target 1 --mount -- mkdir -p /sys/fs/bpf/xdp-telemetry || true
          if ! nsenter --target 1 --mount -- mount | grep -q " /sys/fs/bpf "; then
            nsenter --target 1 --mount -- mount -t bpf bpf /sys/fs/bpf
          fi
  containers:
    - name: xdt-cli
      image: xdt-xdt:latest
      imagePullPolicy: IfNotPresent
      securityContext:
        privileged: true
      command: ["/bin/sh"]
      args: ["-c", "sleep infinity"]
      volumeMounts:
        - name: bpffs
          mountPath: /sys/fs/bpf
          mountPropagation: HostToContainer
        - name: modules
          mountPath: /lib/modules
          readOnly: true
        - name: debugfs
          mountPath: /sys/kernel/debug
          readOnly: true
        - name: btf
          mountPath: /sys/kernel/btf
          readOnly: true
  terminationGracePeriodSeconds: 5
  volumes:
    - name: bpffs
      hostPath:
        path: /sys/fs/bpf
        type: DirectoryOrCreate
    - name: modules
      hostPath:
        path: /lib/modules
        type: Directory
    - name: debugfs
      hostPath:
        path: /sys/kernel/debug
        type: Directory
    - name: btf
      hostPath:
        path: /sys/kernel/btf
        type: Directory
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: xdt-agent
  labels:
    app: xdt-agent
spec:
  selector:
    matchLabels:
      app: xdt-agent
  template:
    metadata:
      labels:
        app: xdt-agent
    spec:
      nodeSelector:
        xdt-telemetry: "true"
      hostNetwork: true
      hostPID: true
      dnsPolicy: ClusterFirstWithHostNet
      securityContext:
        runAsUser: 0
      initContainers:
        - name: mount-bpffs
          image: alpine:3.19
          securityContext:
            privileged: true
          command:
            - sh
            - -c
            - |
              set -e
              apk add --no-cache util-linux >/dev/null
              nsenter --target 1 --mount -- mkdir -p /sys/fs/bpf || true
              if ! nsenter --target 1 --mount -- mount | grep -q " /sys/fs/bpf "; then
                nsenter --target 1 --mount -- mount -t bpf bpf /sys/fs/bpf
              fi
      containers:
        - name: xdt-agent
          image: xdt-agent:latest
          imagePullPolicy: IfNotPresent
          securityContext:
            privileged: true
          command:
            - sh
            - -c
          args:
            - |
              set -e
              # Find service pod sandbox PID via crictl (containerd), with timeout
              CRI_SOCK=/run/containerd/containerd.sock
              for i in \$(seq 1 60); do
                POD_ID=\$(crictl -r "\$CRI_SOCK" pods -o json | jq -r '.items[] | select(.metadata.namespace=="default" and (.metadata.name|startswith("xdt-service-"))) | .id' | head -n1)
                if [ -n "\$POD_ID" ]; then break; fi
                echo "waiting for xdt-service pod..." >&2; sleep 1
              done
              if [ -z "\$POD_ID" ]; then echo "error: service pod not found" >&2; exit 1; fi
              PID=\$(crictl -r "\$CRI_SOCK" inspectp "\$POD_ID" | jq -r '.info.pid')
              if [ -z "\$PID" ] || [ "\$PID" = "null" ]; then echo "error: pid not found" >&2; exit 1; fi
              exec /usr/local/bin/xdt-agent \
                --interface eth0 \
                --netns-pid "\$PID" \
                --central central:${CENTRAL_TELEMETRY_PORT} \
                --agent-id "\$NODE_NAME"
          env:
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          volumeMounts:
            - name: bpffs
              mountPath: /sys/fs/bpf
            - name: containerd-sock
              mountPath: /run/containerd/containerd.sock
              readOnly: true
      terminationGracePeriodSeconds: 30
      tolerations:
        - operator: Exists
      volumes:
        - name: bpffs
          hostPath:
            path: /sys/fs/bpf
            type: Directory
        - name: containerd-sock
          hostPath:
            path: /run/containerd/containerd.sock
            type: Socket
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: xdt-central
  labels:
    app: xdt-central
spec:
  replicas: 1
  selector:
    matchLabels:
      app: xdt-central
  template:
    metadata:
      labels:
        app: xdt-central
    spec:
      nodeSelector:
        kubernetes.io/hostname: xdt-control-plane
      tolerations:
        - key: "node-role.kubernetes.io/master"
          operator: Exists
          effect: NoSchedule
        - key: "node-role.kubernetes.io/control-plane"
          operator: Exists
          effect: NoSchedule
      containers:
        - name: central
          image: xdt-central:latest
          imagePullPolicy: IfNotPresent
          command: ["/usr/local/bin/central"]
          args:
            - "${CENTRAL_TELEMETRY_PORT}"
            - "${CENTRAL_HTTP_PORT}"
          ports:
            - containerPort: ${CENTRAL_TELEMETRY_PORT}
              name: telemetry
            - containerPort: ${CENTRAL_HTTP_PORT}
              name: http
      terminationGracePeriodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: central
  labels:
    app: xdt-central
spec:
  selector:
    app: xdt-central
  ports:
    - name: telemetry
      port: ${CENTRAL_TELEMETRY_PORT}
      targetPort: ${CENTRAL_TELEMETRY_PORT}
    - name: http
      port: ${CENTRAL_HTTP_PORT}
      targetPort: ${CENTRAL_HTTP_PORT}
      nodePort: ${UI_NODE_PORT}
  type: NodePort
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: xdt-service
  labels:
    app: xdt-service
spec:
  replicas: 2
  selector:
    matchLabels:
      app: xdt-service
  template:
    metadata:
      labels:
        app: xdt-service
    spec:
      nodeSelector:
        xdt-telemetry: "true"
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchExpressions:
                  - key: app
                    operator: In
                    values:
                      - xdt-service
              topologyKey: kubernetes.io/hostname
      containers:
        - name: service-health
          image: xdt-service:latest
          imagePullPolicy: IfNotPresent
          command: ["/usr/local/bin/service-health"]
          args:
            - "${SERVICE_PORT}"
          ports:
            - containerPort: ${SERVICE_PORT}
              name: http
      terminationGracePeriodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: xdt-service
  labels:
    app: xdt-service
spec:
  selector:
    app: xdt-service
  ports:
    - name: http
      port: ${SERVICE_PORT}
      targetPort: ${SERVICE_PORT}
      nodePort: ${SERVICE_NODE_PORT}
  type: NodePort
EOF

echo "Waiting for xdt-cli pod to become Ready"
kubectl wait --for=condition=Ready pod/xdt-cli --timeout=180s

echo "Waiting for xdt-agent daemonset rollout"
kubectl rollout status daemonset/xdt-agent --timeout=180s

echo "Waiting for xdt-central deployment rollout"
kubectl rollout status deployment/xdt-central --timeout=180s

echo "Waiting for xdt-service deployment rollout"
kubectl rollout status deployment/xdt-service --timeout=180s

echo "kind environment ready"
