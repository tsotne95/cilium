#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Testing Sieve Logic Locally ===${NC}"
echo "Verifying if the current cluster would be 'caught' by our Sieve queries."
echo ""

# 1. Map Exhaustion Sieve (Log Check)
echo -e "${BLUE}[Sieve 1] Map Exhaustion Scanner${NC}"
# In a real Sieve, this checks Cloud Logging. Here we check Pod Logs.
CILIUM_PODS=$(kubectl -n kube-system get pods -l k8s-app=cilium -o name)
ERRORS=$(kubectl -n kube-system logs -l k8s-app=cilium --tail=5000 2>/dev/null | grep -E "Failed to add PolicyMap key|Map limit reached" | wc -l)

if [ "$ERRORS" -gt 0 ]; then
    echo -e "${RED}[MATCH] Found $ERRORS 'Map Full' errors.${NC}"
else
    echo -e "${GREEN}[NO MATCH] No recent 'Map Full' errors found.${NC}"
fi
echo ""

# 2. High Density Sieve (Node Capacity)
echo -e "${BLUE}[Sieve 2] High Density Scanner${NC}"
NODES=$(kubectl get nodes -o name)
for node in $NODES; do
    POD_COUNT=$(kubectl get pods --all-namespaces --field-selector spec.nodeName=${node##*/} --no-headers | wc -l)
    if [ "$POD_COUNT" -gt 50 ]; then
        echo -e "${RED}[MATCH] Node ${node} has $POD_COUNT pods (>50).${NC}"
    else
        echo -e "${GREEN}[NO MATCH] Node ${node} has $POD_COUNT pods (<=50).${NC}"
    fi
done
echo ""

# 3. World Policy Sieve (0.0.0.0/0 Egress)
echo -e "${BLUE}[Sieve 3] World Policy Scanner${NC}"
# Use JQ to parse all NetworkPolicies for 0.0.0.0/0 in egress
WORLD_POLICIES=$(kubectl get cnp -A -o json | jq -r '.items[] | select(.spec.egress[].toCIDR[]? | contains("0.0.0.0/0")) | "\(.metadata.namespace)/\(.metadata.name)"')

if [ ! -z "$WORLD_POLICIES" ]; then
    echo -e "${RED}[MATCH] Found World Policies:${NC}"
    echo "$WORLD_POLICIES"
else
    echo -e "${GREEN}[NO MATCH] No policies with 0.0.0.0/0 egress found.${NC}"
fi
echo ""

# 4. Identity Duplication Sieve
echo -e "${BLUE}[Sieve 4] Identity Duplication Scanner${NC}"
# Requires cilium-cli to get endpoints or parsing CiliumEndpoint CRD
# We look for >5 endpoints with same Identity ID on the same node.

# Get all CEPs: Node, IdentityID
DUPLICATIONS=$(kubectl get cep -A -o json | jq -r '
    .items[] | 
    {node: .status.networking.node, id: .status.identity.id}
' | jq -s '
    group_by(.node)[] | 
    {node: .[0].node, identities: (map(.id) | group_by(.) | map(select(length > 5)))} | 
    select(.identities | length > 0)
')

if [ ! -z "$DUPLICATIONS" ]; then
    echo -e "${RED}[MATCH] Found High Duplication on Nodes:${NC}"
    echo "$DUPLICATIONS" | jq -c '.'
else
    echo -e "${GREEN}[NO MATCH] No Identity Duplication > 5 found.${NC}"
fi
echo ""

# 5. Policy Churn Sieve (Regeneration Rate)
echo -e "${BLUE}[Sieve 5] Policy Churn Scanner${NC}"

# Check Metrics for "cilium_endpoint_regenerations_total"
# Sieve 5: Metric-based detection of churn.
# Get one cilium pod
CILIUM_POD=$(kubectl -n kube-system get pods -l k8s-app=cilium -o jsonpath="{.items[0].metadata.name}")

get_regen_count() {
    kubectl -n kube-system exec "$CILIUM_POD" -- cilium metrics list -o json | jq -r '[.[] | select(.name == "cilium_endpoint_regenerations_total") | .value | tonumber] | add'
}

START_OPS=$(get_regen_count)
echo "Initial Regeneration Count: $START_OPS"

# SIMULATION: Generate fake churn
echo "Simulating Policy Churn (Apply/Delete 20 times)..."
cat <<EOF > dummy-churn-policy.yaml
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: dummy-churn
  namespace: world-repro
spec:
  endpointSelector:
    matchLabels:
      k8s-app: victim-world
  egress:
  - toEntities:
    - world
EOF

for i in {1..20}; do
  kubectl apply -f dummy-churn-policy.yaml
  sleep 1
  kubectl delete -f dummy-churn-policy.yaml
  sleep 1
done
rm dummy-churn-policy.yaml
sleep 5 # Wait for metrics to update

END_OPS=$(get_regen_count)
echo "Final Regeneration Count: $END_OPS"

DELTA=$((END_OPS - START_OPS))
echo "Regeneration Delta: $DELTA"

if [ "$DELTA" -gt 10 ]; then
    echo -e "${RED}[MATCH] High Policy Churn Detected ($DELTA events).${NC}"
else
    echo -e "${GREEN}[NO MATCH] Churn is low ($DELTA events).${NC}"
fi
echo ""

echo -e "${BLUE}=== Sieve Verification Complete ===${NC}"
