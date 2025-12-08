
import argparse
import yaml

def generate_manifests(output_file, num_rules=50, num_replicas=20):
    manifests = []

    # 1. Namespace
    manifests.append({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": "yahoo-repro"}
    })

    # 2. Victim Deployment (simulates multiple pods receiving the same policy)
    manifests.append({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "victim",
            "namespace": "yahoo-repro",
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

    # 3. Heavy Policy
    # Allows ingress from 'num_rules' distinct labels.
    # In Legacy mode, this puts 'num_rules' entries into EACH of the 'num_replicas' pod maps.
    # In Shared mode, these 'num_rules' are stored ONCE in the shared map.
    ingress_rules = []
    for i in range(num_rules):
        # Generate distinct IPs: 10.0.0.0/32 ... 10.0.0.199/32
        ip_octet = i % 255
        ingress_rules.append({
            "fromCIDR": [
                f"10.100.{i // 255}.{ip_octet}/32"
            ]
        })

    manifests.append({
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "yahoo-heavy-policy",
            "namespace": "yahoo-repro"
        },
        "spec": {
            "endpointSelector": {"matchLabels": {"app": "victim"}},
            "ingress": ingress_rules
        }
    })

    with open(output_file, "w") as f:
        yaml.dump_all(manifests, f)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="yahoo_repro.yaml")
    args = parser.parse_args()
    generate_manifests(args.output)
