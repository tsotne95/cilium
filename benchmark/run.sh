#!/bin/bash
set -e

CLUSTER_NAME="cilium-benchmark"
IMAGE_TAG="benchmark"
# Makefile produces quay.io/cilium/cilium-dev:benchmark by default
IMAGE_NAME="quay.io/cilium/cilium-dev:$IMAGE_TAG"
KIND_CONFIG="benchmark/kind-config.yaml"

function log() {
    echo "[$(date +'%H:%M:%S')] $1"
}

function prepare_image() {
    log "Building Cilium Docker Image..."
    make dev-docker-image DOCKER_IMAGE_TAG=$IMAGE_TAG
}

function setup_cluster() {
    log "Cleaning up old cluster..."
    kind delete cluster --name $CLUSTER_NAME 2>/dev/null || true
    log "Creating Kind Cluster '$CLUSTER_NAME'..."
    kind create cluster --name $CLUSTER_NAME --config $KIND_CONFIG
}

function load_image() {
    log "Loading Image into Kind..."
    kind load docker-image $IMAGE_NAME --name $CLUSTER_NAME
}

function generate_manifests() {
    log "Generating Manifests (World Repro)..."
    python3 benchmark/repro_world_manifests.py --output benchmark/manifests/all.yaml
}

function install_cilium() {
    local mode=$1
    log "Installing Cilium (Mode: $mode)..."

    local flags=(
        "--version" "v1.16.0" # Dummy version to force usage of local image
        "--set" "image.repository=quay.io/cilium/cilium-dev"
        "--set" "image.tag=$IMAGE_TAG"
        "--set" "image.pullPolicy=Never"
        "--set" "bpf.policyMapMax=4096" # Increased to hold 0.0.0.0/0 explosion
        "--set" "operator.unmanagedPodWatcher.restart=false" # Fix config invalid duration error
        "--wait"
    )

    if [ "$mode" == "shared" ]; then
        flags+=("--set" "policySharedMap.enabled=true")
        flags+=("--set" "policySharedMap.mode=shared")
        flags+=("--set" "policySharedMap.ruleSetPoolSize=1000") # Small pool to verify config
    else
        flags+=("--set" "policySharedMap.enabled=false")
    fi

    # Assuming we are in root of repo and can use helm or cilium cli
    # We use 'cilium install' with helm flags if possible, or just helm install if cilium cli is tricky with local charts
    # Let's try cilium install with --helm-set
    
    cilium install \
        --chart-directory ./install/kubernetes/cilium \
        "${flags[@]}"
}

function run_measurement() {
    local mode=$1
    log "Waiting for CRDs..."
    # Explicitly install CRDs to ensure they exist
    kubectl apply -f pkg/k8s/apis/cilium.io/client/crds/v2/ciliumnetworkpolicies.yaml || true
    
    # Wait for CRD to exist
    for i in {1..60}; do
        if kubectl get crd ciliumnetworkpolicies.cilium.io >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    kubectl wait --for condition=established --timeout=60s crd/ciliumnetworkpolicies.cilium.io || true
    
    local namespace="world-repro"
    
    log "Applying Workload..."
    kubectl apply -f benchmark/manifests/all.yaml
    kubectl -n $namespace wait --for=condition=available --timeout=300s deployment/victim
    
    log "Waiting for policy propagation..."
    sleep 10
    
    log "Collecting Metrics..."
    local cilium_pod=$(kubectl -n kube-system get pods -l k8s-app=cilium -o jsonpath='{.items[0].metadata.name}')
    
    log "Executing commands in $cilium_pod..."
    
    echo "=== Mode: $mode ===" >> benchmark/results.txt
    
    # 1. Total BPF Policy Map Entries (Legacy Map)
    local legacy_count=0
    # List all endpoints using jq
    local eps_json=$(kubectl -n kube-system exec $cilium_pod -- cilium-dbg endpoint list -o json)
    local eps=$(echo "$eps_json" | jq -r '.[].id')
    
    for ep in $eps; do
        if [ "$ep" != "null" ] && [ "$ep" != "" ]; then
            # Count lines in policy get (excluding headers)
            local count=$(kubectl -n kube-system exec $cilium_pod -- cilium-dbg bpf policy get $ep --numeric 2>/dev/null | grep -v "POLICY" | wc -l)
            legacy_count=$((legacy_count + count))
        fi
    done
    echo "Total Legacy Map Entries: $legacy_count" >> benchmark/results.txt
    
    # 2. Shared Map Entries (via bpftool)
    local shared_count=0
    if [ "$mode" == "shared" ]; then
        # Check for cilium_policy_shared map
        shared_count=$(kubectl -n kube-system exec $cilium_pod -- bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_policy_shared 2>/dev/null | grep "value" | wc -l)
    fi
    echo "Total Shared Map Entries: $shared_count" >> benchmark/results.txt
    
    # 3. Memory Usage (RSS of cilium-agent)
    # Attempt to find PID of cilium-agent
    local mem_usage_kb=$(kubectl -n kube-system exec $cilium_pod -- sh -c 'ps -o rss= -p $(pgrep cilium-agent | head -n 1)' 2>/dev/null)
    if [ -z "$mem_usage_kb" ]; then
         mem_usage_kb=0
    fi
    local mem_usage_bytes=$((mem_usage_kb * 1024))
    echo "Agent Memory Usage: $mem_usage_bytes bytes" >> benchmark/results.txt
    
    log "Measurement Complete."
}

function cleanup() {
    log "Cleaning up..."
    # kind delete cluster --name $CLUSTER_NAME
    log "Cleanup skipped for debugging."
}

# --- Main ---

# cleanup || true # Clean start
mkdir -p benchmark/manifests
echo " Benchmark Results " > benchmark/results.txt

generate_manifests
prepare_image
setup_cluster
load_image

# Test 1: Legacy
install_cilium "legacy"
run_measurement "legacy"
cilium uninstall --wait

# Test 2: Shared
install_cilium "shared"
run_measurement "shared"

log "Benchmark Finished. Results:"
cat benchmark/results.txt
