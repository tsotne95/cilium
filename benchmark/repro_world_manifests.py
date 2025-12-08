
import argparse
import yaml

def generate_manifests(output_file, num_cidrs=250, num_replicas=20):
    manifests = []

    # 1. Namespace
    manifests.append({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": "world-repro"}
    })

    # 2. Victim Deployment (simulates pods with 0.0.0.0/0 egress)
    manifests.append({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "victim",
            "namespace": "world-repro",
            "labels": {"app": "victim"}
        },
        "spec": {
            "replicas": num_replicas,
            "selector": {"matchLabels": {"app": "victim"}},
            "template": {
                "metadata": {"labels": {"app": "victim"}},
                "spec": {
                    "containers": [{
                        "name": "nginx",
                        "image": "nginx:alpine",
                        "ports": [{"containerPort": 80}]
                    }]
                }
            }
        }
    })

    # 3. Victim Policy (Egress to 0.0.0.0/0)
    manifests.append({
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "victim-world-egress",
            "namespace": "world-repro"
        },
        "spec": {
            "endpointSelector": {"matchLabels": {"app": "victim"}},
            "egress": [{
                "toCIDR": ["0.0.0.0/0"]
            }]
        }
    })

    # 4. Noise Job/Pods (Just to justify the existence of IDs, but strictly we just need the IDs)
    # We create a dummy policy that references MANY CIDRs.
    # This forces Cilium to allocate Identities for these CIDRs.
    # Because 'victim' allows 0.0.0.0/0 (World), and these CIDRs are World, 
    # they *should* be added to victim's policy map if the issue manifests.

    cidrs = []
    for i in range(num_cidrs):
        # Generate 11.x.x.x IPs
        octet2 = (i // 255) % 255
        octet3 = i % 255
        cidrs.append(f"11.{octet2}.{octet3}.1/32")

    manifests.append({
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "noise-policy-cidr-allocator",
            "namespace": "world-repro"
        },
        "spec": {
            "endpointSelector": {"matchLabels": {"app": "noise"}}, # Matches nothing or we create a dummy
            "egress": [{
                "toCIDR": cidrs
            }]
        }
    })

    # Dummy noise pod to make policy active? 
    # Cilium allocates CIDR identities even if no endpoint selects them? 
    # Actually, usually they are allocated when referenced by a rule that is *selected* by an endpoint?
    # Or just existence of CNP is enough?
    # To be safe, let's create a noise pod.
    manifests.append({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "noise-pod",
            "namespace": "world-repro",
            "labels": {"app": "noise"}
        },
        "spec": {
            "containers": [{
                "name": "pause",
                "image": "k8s.gcr.io/pause:3.1"
            }]
        }
    })

    with open(output_file, "w") as f:
        yaml.dump_all(manifests, f)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="world_repro.yaml")
    args = parser.parse_args()
    generate_manifests(args.output)
