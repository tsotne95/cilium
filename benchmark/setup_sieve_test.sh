#!/bin/bash
set -e

CLUSTER_NAME="cilium-sieve-test"
KIND_CONFIG="benchmark/kind-config.yaml"
# Reuse image from previous steps or default
IMAGE="quay.io/cilium/cilium-dev:benchmark"

echo "=== Setting up Sieve Test Environment ==="

# 1. Create Cluster
if kind get clusters | grep -q "${CLUSTER_NAME}"; then
    echo "Deleting existing cluster '${CLUSTER_NAME}'..."
    kind delete cluster --name "${CLUSTER_NAME}"
fi

echo "Creating Kind cluster '${CLUSTER_NAME}'..."
kind create cluster --name "${CLUSTER_NAME}" --config "${KIND_CONFIG}"
echo "Loading image..."
kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"

# 2. Install Cilium (LEGACY MODE to trigger Map Full errors)
echo "Installing Cilium (Legacy Mode)..."
# Using cilium-cli instead of helm locally to avoid permission issues
# bpf.policyMapMax=4096 (small enough to fail with World explosion)
cilium install \
   --namespace kube-system \
   --set image.repository=quay.io/cilium/cilium-dev \
   --set image.tag=benchmark \
   --set image.useDigest=false \
   --set operator.replicas=1 \
   --set policySharedMap.enabled=false \
   --set bpf.policyMapMax=4096 \
   --set operator.unmanagedPodWatcher.restart=false \
   --wait

echo "Installing CRDs explicitly..."
# Apply CRDs explicitly to ensure they exist before we wait for them
if [ -d "pkg/k8s/apis/cilium.io/client/crds/v2" ]; then
    kubectl apply -f pkg/k8s/apis/cilium.io/client/crds/v2/
elif [ -f "examples/crds.yaml" ]; then
    kubectl apply -f examples/crds.yaml
else
    echo "Warning: No local CRD file found, hoping cilium-cli installed them..."
fi

echo "Waiting for CNP CRD..."
kubectl wait --for=condition=established crd/ciliumnetworkpolicies.cilium.io --timeout=60s

# 3. Apply Workload
echo "Applying World Repro Workload..."
python3 benchmark/repro_world_manifests.py --output benchmark/sieve_repro.yaml
kubectl apply -f benchmark/sieve_repro.yaml

echo "Waiting for pods..."
kubectl wait --for=condition=ready pod -l app=victim -n world-repro --timeout=300s || true

echo "=== Environment Ready ==="
echo "You can now run benchmark/test_sieve_logic.sh"
