#!/bin/bash
set -e

# Config
IMAGE_TAG="${IMAGE_TAG:-benchmark-clean}"
CLUSTER_NAME="${CLUSTER_NAME:-kind}"

echo "=== Yahoo Benchmark Runner ==="
echo "Cluster: $CLUSTER_NAME"
echo "Image:   $IMAGE_TAG"

# Check dependencies
if ! command -v kind &> /dev/null; then
    echo "Error: kind is not installed."
    exit 1
fi

if ! command -v cilium &> /dev/null; then
    echo "Error: cilium-cli is not installed."
    exit 1
fi

# Check Cluster
if ! kind get clusters | grep -q "^$CLUSTER_NAME$"; then
    echo "Cluster '$CLUSTER_NAME' not found. Creating..."
    kind create cluster --name "$CLUSTER_NAME"
fi

# Load Image
# Load Image
if [ "$IMAGE_TAG" == "local" ]; then
    FULL_IMAGE="localhost:5000/cilium/cilium-dev:local"
else
    FULL_IMAGE="quay.io/cilium/cilium-dev:$IMAGE_TAG"
fi
echo "Loading image '$FULL_IMAGE' into Kind cluster '$CLUSTER_NAME'..."
kind load docker-image "$FULL_IMAGE" --name "$CLUSTER_NAME"

function setup_cilium() {
    local mode=$1
    echo "Deploying Cilium in $mode mode..."
    
    local shared_enabled="false"
    local shared_mode="legacy"
    
    if [ "$mode" == "shared" ]; then
        shared_enabled="true"
        shared_mode="shared"
    fi

    # Determine if we need install or upgrade
    local cmd="install"
    if cilium status --wait=false >/dev/null 2>&1; then
        cmd="upgrade"
        echo "Cilium detected. Using 'cilium upgrade'..."
    else
        echo "Cilium not found. Using 'cilium install'..."
    fi

    local image_repo="quay.io/cilium/cilium-dev"
    if [ "$IMAGE_TAG" == "local" ]; then
        image_repo="localhost:5000/cilium/cilium-dev"
    fi

    cilium $cmd \
        --chart-directory ./install/kubernetes/cilium \
        --namespace kube-system \
        --set image.repository=$image_repo \
        --set image.tag=$IMAGE_TAG \
        --set image.pullPolicy=Never \
        --set bpf.policyMapMax=16384 \
        --set policySharedMap.enabled=$shared_enabled \
        --set policySharedMap.mode=$shared_mode \
        --set policySharedMap.maxSharedRefs=32 \
        --set policySharedMap.maxSharedRefs=32 \
        --set-string extraConfig.enable-policy-shared-map-arena=true \
        --wait

    echo "Restarting Cilium DaemonSet to ensure config takes effect..."
    kubectl -n kube-system rollout restart ds/cilium
    kubectl -n kube-system rollout status ds/cilium --timeout=5m
        
    echo "Cilium deployed in $mode mode."
}

function measure() {
    local mode=$1
    echo "Measuring $mode mode..."
    
    # Wait for victim pods to be ready (ensure policy is enforced)
    echo "Waiting for victim pods..."
    kubectl -n yahoo-repro wait --for=condition=ready pod -l app=victim --timeout=2m || true
    
    # Wait a bit for policy propagation
    sleep 10
    
    local cilium_pod=$(kubectl -n kube-system get pods -l k8s-app=cilium -o jsonpath="{.items[0].metadata.name}")
    echo "Inspecting Cilium Pod: $cilium_pod"
    
    # Count total legacy entries (cilium_policy_XXXX maps)
    echo "Counting legacy map entries..."
    # We find all map IDs for cilium_policy_*, excluding shared/events
    local map_ids=$(kubectl exec -n kube-system $cilium_pod -- bpftool map show | grep "cilium_policy_" | grep -v "shared" | grep -v "events" | awk '{print $1}' | tr -d ':')
    
    local total_legacy=0
    for id in $map_ids; do
        # Dump map and count lines containing "key:"
        local count=$(kubectl exec -n kube-system $cilium_pod -- bpftool map dump id $id 2>/dev/null | grep "key:" | wc -l)
        total_legacy=$((total_legacy + count))
    done
    
    local total_shared=0
    local total_global_rules=0
    local total_list_nodes=0
    if [ "$mode" == "shared" ]; then
         echo "Counting shared map entries..."
         # Count entries in cilium_policy_shared (pinned map)
         total_shared=$(kubectl exec -n kube-system $cilium_pod -- bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_policy_shared 2>/dev/null | grep "value" | wc -l)
         
         # Count entries in Phase 3 maps (non-zero entries)
         # Using grep -v "00 00 00 00 00 00 00 00" to filter out empty entries in Array Map
         total_global_rules=$(kubectl exec -n kube-system $cilium_pod -- bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_policy_g 2>/dev/null | grep "value:" | grep -v "00 00 00 00 00 00 00 00" | wc -l)
         total_list_nodes=$(kubectl exec -n kube-system $cilium_pod -- bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_policy_l 2>/dev/null | grep "value:" | grep -v "00 00 00 00 00 00 00 00" | wc -l)
         
         # Check Arena (Name might be truncated to cilium_policy_a)
         if kubectl exec -n kube-system $cilium_pod -- bpftool map show | grep -q "cilium_policy_a"; then
             arena_status="Active"
         else
             arena_status="Not Found"
         fi
    fi
    
    echo "=== Results for $mode ==="
    echo "Total Legacy Entries: $total_legacy"
    echo "Total Shared Entries (Phase 2): $total_shared"
    echo "Total Global Rules (Phase 3): $total_global_rules"
    echo "Total List Nodes (Phase 3): $total_list_nodes"
    if [ "$mode" == "shared" ]; then
        echo "BPF Arena Status: $arena_status"
        echo "Estimated Arena Rules (Mirrored): $total_global_rules"
    fi
}

# 1. Generate Manifests
echo "Generating Yahoo Repro manifests..."
python3 benchmark/repro_yahoo_manifests.py --output yahoo_repro.yaml

TEST_MODE="${TEST_MODE:-all}"

if [[ "$TEST_MODE" == "all" || "$TEST_MODE" == "legacy" ]]; then
    # 2. Test Legacy
    setup_cilium "legacy"

    echo "Manually applying all CRDs..."
    kubectl apply -f pkg/k8s/apis/cilium.io/client/crds/v2/ || true

    echo "Waiting for CNP CRD..."
    kubectl wait --for=condition=established crd/ciliumnetworkpolicies.cilium.io --timeout=60s || true

    echo "Applying manifests..."
    kubectl create ns yahoo-repro --dry-run=client -o yaml | kubectl apply -f -
    kubectl apply -f yahoo_repro.yaml

    measure "legacy"

    echo "Uninstalling Legacy Cilium..."
    cilium uninstall --wait
fi

if [[ "$TEST_MODE" == "all" || "$TEST_MODE" == "shared" ]]; then
    # 4. Test Shared
    if [ "$SKIP_SETUP" != "true" ]; then
        echo "Cleaning up stale BPF maps..."
        nodes=$(kind get nodes --name "$CLUSTER_NAME")
        for node in $nodes; do
            echo "Cleaning maps on $node..."
            docker exec "$node" rm -f /sys/fs/bpf/tc/globals/cilium_policy_shared 2>/dev/null || true
            docker exec "$node" rm -f /sys/fs/bpf/tc/globals/cilium_policy_a 2>/dev/null || true
            docker exec "$node" rm -f /sys/fs/bpf/tc/globals/cilium_policy_g 2>/dev/null || true
            docker exec "$node" rm -f /sys/fs/bpf/tc/globals/cilium_policy_l 2>/dev/null || true
            docker exec "$node" rm -f /sys/fs/bpf/tc/globals/cilium_policy_overlay 2>/dev/null || true
        done

        setup_cilium "shared"
    fi

    # Check if manifests need to be applied (e.g. if we skipped legacy or setup)
    if [[ "$TEST_MODE" == "shared" ]]; then
         echo "Applying manifests for Shared mode..."
         kubectl apply -f pkg/k8s/apis/cilium.io/client/crds/v2/ || true
         kubectl create ns yahoo-repro --dry-run=client -o yaml | kubectl apply -f -
         kubectl apply -f yahoo_repro.yaml
    fi

    echo "Restarting victims to ensure they are managed..."
    kubectl -n yahoo-repro rollout restart deploy/victim
    kubectl -n yahoo-repro rollout status deploy/victim --timeout=120s
    measure "shared"
fi

echo "Yahoo Repro Complete."
