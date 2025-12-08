#!/usr/bin/env python3
import sys

# Configuration
NUM_POLICIES = 100
SHARED_LABEL = "role=monitoring"
SHARED_LABEL_KEY = "role"
SHARED_LABEL_VAL = "monitoring"

def generate_workload():
    return """apiVersion: apps/v1
kind: Deployment
metadata:
  name: victim
  labels:
    app: victim
spec:
  replicas: 1
  selector:
    matchLabels:
      app: victim
  template:
    metadata:
      labels:
        app: victim
    spec:
      containers:
      - name: nginx
        image: nginx
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: victim
spec:
  selector:
    app: victim
  ports:
  - port: 80
    targetPort: 80
"""

def generate_policy(i):
    # Each policy allows a unique CIDR
    return f"""---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: policy-{i}
spec:
  podSelector:
    matchLabels:
      app: victim
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock:
        cidr: 10.10.{i // 256}.{i % 256}/32
"""

def main():
    print(generate_workload())
    for i in range(NUM_POLICIES):
        print(generate_policy(i))

if __name__ == "__main__":
    main()
