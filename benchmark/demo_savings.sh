#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}   Cilium Shared Policy Map: Memory Savings Demo (World Repro)   ${NC}"
echo -e "${BLUE}================================================================${NC}"
echo "This demo will run a workload that typically causes BPF map explosion"
echo "and show how Shared Policy Map solves it."
echo ""

# Configuration
CLUSTER_NAME="cilium-demo"
KIND_CONFIG="benchmark/kind-config.yaml"
IMAGE="quay.io/cilium/cilium-dev:benchmark"

# 1. Setup Cluster
echo -e "${GREEN}[1/4] Setting up Kind Cluster '${CLUSTER_NAME}'...${NC}"
kind delete cluster --name "${CLUSTER_NAME}" > /dev/null 2>&1 || true
kind create cluster --name "${CLUSTER_NAME}" --config "${KIND_CONFIG}" > /dev/null 2>&1

echo -e "${GREEN}[2/4] Loading Images...${NC}"
kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}" > /dev/null 2>&1

# Function to run test
run_mode() {
    MODE=$1
    echo -e "${GREEN}[3/4] Running in ${MODE} Mode...${NC}" >&2
    
    # Install Cilium
    HELM_FLAGS="--set image.repository=quay.io/cilium/cilium-dev --set image.tag=benchmark --set image.useDigest=false"
    HELM_FLAGS+=" --set bpf.policyMapMax=8192" # Ensure enough space for legacy to explode
    HELM_FLAGS+=" --set operator.unmanagedPodWatcher.restart=false" # Fix operator crash
    
    if [ "$MODE" == "shared" ]; then
        HELM_FLAGS+=" --set policySharedMap.enabled=true --set policySharedMap.mode=shared"
    else
        HELM_FLAGS+=" --set policySharedMap.enabled=false"
    fi

    # Uninstall previous
    cilium uninstall > /dev/null 2>&1 || true
    
    # Install
    cilium install $HELM_FLAGS > /dev/null 2>&1
    cilium status --wait > /dev/null 2>&1

    # Apply Workload
    echo "    Applying 'World Explosion' Workload (20 pods, 0.0.0.0/0 policy)..." >&2
    python3 benchmark/repro_world_manifests.py --output benchmark/demo_manifest.yaml
    kubectl apply -f benchmark/demo_manifest.yaml > /dev/null 2>&1
    
    # Wait for pods
    kubectl wait --for=condition=ready pod -l app=victim -n world-repro --timeout=300s > /dev/null 2>&1
    
    echo "    Collecting Metrics..." >&2
    # Sleep to allow policy propagation
    sleep 10
    
    # Count entries
    CILIUM_POD=$(kubectl -n kube-system get pods -l k8s-app=cilium -o jsonpath='{.items[0].metadata.name}')
    
    # Get IDs of victims
    IDS=$(kubectl exec -n kube-system $CILIUM_POD -- cilium-dbg endpoint list -o json | jq -r '[.[] | select(.status.identity.labels[]? | contains("app=victim")) | .id] | join(" ")')
    
    TOTAL_ENTRIES=0
    for ID in $IDS; do
        # Count Policy Map entries (Legacy)
        COUNT=$(kubectl exec -n kube-system $CILIUM_POD -- cilium-dbg bpf policy get $ID | grep -c -E 'Allow|Deny' || true)
        TOTAL_ENTRIES=$((TOTAL_ENTRIES + COUNT))
    done
    
    echo $TOTAL_ENTRIES
}

echo -e "${BLUE}=== Starting Comparisons ===${NC}"

# Run Legacy
echo ">>> Testing Legacy Mode (Expect Explosion)..."
LEGACY_COUNT=$(run_mode "legacy")
echo -e "${RED}Legacy Mode Total Entries: ${LEGACY_COUNT}${NC}"

# Run Shared
echo ">>> Testing Shared Mode (Expect Savings)..."
SHARED_COUNT=$(run_mode "shared")
echo -e "${GREEN}Shared Mode Total Entries: ${SHARED_COUNT}${NC}"

# Summary
echo ""
echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}                     DEMO RESULTS                               ${NC}"
echo -e "${BLUE}================================================================${NC}"
echo -e "Scenario: 20 Pods, Egress to 0.0.0.0/0 (World)"
echo -e "Legacy Mode Entries: ${RED}${LEGACY_COUNT}${NC}"
echo -e "Shared Mode Entries: ${GREEN}${SHARED_COUNT}${NC} (Legacy Map Usage)"

SAVINGS=$((LEGACY_COUNT - SHARED_COUNT))
PERCENT=$((SAVINGS * 100 / LEGACY_COUNT))

echo -e "Memory Savings:      ${GREEN}${PERCENT}%${NC} reduction!"
echo -e "${BLUE}================================================================${NC}"

# Cleanup
rm benchmark/demo_manifest.yaml
