#!/bin/bash
set -e
echo "=== Verifying Persistence ==="
# Wait for pods to be ready first (in case benchmark just finished)
kubectl -n kube-system rollout status ds/cilium --timeout=2m || true

POD=$(kubectl -n kube-system get pods -l k8s-app=cilium -o jsonpath="{.items[0].metadata.name}")
echo "Current Cilium Pod: $POD"

# Check if Arena Map is active
if kubectl exec -n kube-system $POD -- ls /sys/fs/bpf/tc/globals/cilium_policy_a >/dev/null 2>&1; then
    echo "SUCCESS: Map pinned at /sys/fs/bpf/tc/globals/cilium_policy_a"
elif ! kubectl exec -n kube-system $POD -- bpftool map show | grep -q "cilium_policy_a"; then
    echo "Error: cilium_policy_a map not found (neither file nor bpftool)!"
    exit 1
fi

# Trigger Restart
echo "Restarting Cilium Agent..."
kubectl -n kube-system rollout restart ds/cilium
kubectl -n kube-system rollout status ds/cilium --timeout=5m

# Check Logs for Recovery
# We sleep a bit to let logs flush
sleep 5
NEW_POD=$(kubectl -n kube-system get pods -l k8s-app=cilium -o jsonpath="{.items[0].metadata.name}")
echo "New Cilium Pod: $NEW_POD"

echo "Checking logs for recovery message..."
if kubectl -n kube-system logs $NEW_POD --tail=-1 | grep -q "Recovered Arena Allocator state"; then
    echo "SUCCESS: Found 'Recovered Arena Allocator state' in logs."
    echo "Persistence Verified."
else
    echo "FAILURE: Recovery message NOT found in logs."
    echo "Dumping recent logs:"
    kubectl -n kube-system logs $NEW_POD --tail=50
    exit 1
fi
