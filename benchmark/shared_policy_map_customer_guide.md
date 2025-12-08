# Shared Policy Map: Customer Enabling Guide

## Overview
The **Shared Policy Map** is a new memory-optimization feature in Cilium. It significantly reduces the BPF map memory footprint by deduplicating identical network policy rules across multiple pods.

## Why use it?
Legacy Cilium stores a complete copy of network policy rules for *every endpoint*. If you have 100 pods running the same application, Cilium stores 100 copies of the same rules.

**Shared Policy Map** solves this by storing unique rules once in a global map and having endpoints reference them.

### Benefits at a Glance
| Scenario | Legacy Memory (Entries) | Shared Memory (Entries) | Savings |
| :--- | :--- | :--- | :--- |
| **Yahoo/Typical (20 pods, 50 rules)** | 1000+ entries | ~525 entries | **~48%** |
| **World/Egress 0.0.0.0/0 (20 pods)** | 5000+ entries | ~500 entries | **~90%** |
| **Massive Scale (DaemonSets)** | Linear Growth (N * Rules) | Constant (Rules) | **>95%** |

## How it Works (Technical Deep Dive)
Traditionally, Cilium compiles network policies into a per-endpoint BPF map (`cilium_policy_v2_<ID>`). If 100 pods share the same policy, the same rules are compiled and written 100 times.

**Shared Policy Map** introduces a two-layer look-up:
1.  **Global Shared Map (`cilium_policy_shared`)**: Stores unique Policy Rules (e.g., "Allow Ingress from 10.0.0.1/32"). Each unique set of rules is assigned a **RuleSetID**.
2.  **Endpoint Overlay Map**: The per-endpoint map now only stores a reference: "Apply RuleSetID 1234".

### Architecture Diagram
1.  **Policy Repository**: Calculates unique sets of rules (`RuleSet`).
2.  **RuleSetAllocator**: Assigns a unique, reusable `RuleSetID` (e.g., 42) to that set of rules using a hash-based mechanism.
3.  **Endpoint Regeneration**: Instead of writing 50 rules to the endpoint's map, the Agent writes 1 entry: `Call SharedMap(42)`.
4.  **Dataplane (BPF)**: When a packet arrives, the BPF program looks up the Endpoint Map, finds the `SharedMap(42)` instruction, and tails-calls or loops into the Shared Map to evaluate the actual rules.

### Use Case: The "World" Explosion
A policy allowing egress to `0.0.0.0/0` expands to allow all cluster identities + the "World" identity. In legacy mode, this inserts ~250 entries per pod.
-   **Legacy**: 20 pods * 250 entries = **5,000 entries**.
-   **Shared**: 1 RuleSet (250 entries) + 20 pointers = **270 entries**.
**Savings: ~95%.**

## When to Enable?
Enable this feature if you meet **ANY** of the following criteria:

- [ ] **High Pod Density**: You run >50 pods per node.
- [ ] **DaemonSets**: You use DaemonSets with Network Policies (duplication is 100%).
- [ ] **World Policies**: You use Egress allows to `0.0.0.0/0` or large CIDRs.
- [ ] **Map Exhaustion**: You see `BPF map full` or `Map limit reached` errors in `cilium-agent` logs.

## Troubleshooting
If you suspect issues with Shared Policy Map:
1.  **Verify State**:
    ```bash
    cilium-dbg bpf policy get --all
    # Look for "SharedHandles: [...]" in output
    ```
2.  **Check Maps**:
    ```bash
    cilium-dbg map get cilium_policy_shared
    ```
3.  **Disable if unstable**: Set `policySharedMap.enabled=false` and restart agents.

## Configuration
To enable Shared Policy Map, update your Helm configuration:

```yaml
policySharedMap:
  enabled: true
  mode: "shared"
  # Optional Tuning
  maxSharedRefs: 16 (default)
  maxPrivateOverrides: 8 (default)
```

**Helm Command:**
```bash
helm upgrade cilium cilium/cilium \
   --namespace kube-system \
   --set policySharedMap.enabled=true \
   --set policySharedMap.mode=shared
```

## Performance & Trade-offs
-   **Memory**: Massive savings in BPF (Kernel) memory.
-   **CPU**: Slight increase in Control Plane CPU (Agent) to calculate deduplication.
-   **Agent Memory**: Slight increase (~50-100MB RSS) in Userspace memory to track rule sets.

**Recommendation:** The BPF memory savings (preventing packet drops and node instability) far outweigh the slight Agent RSS increase.
