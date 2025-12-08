#!/bin/bash
set -e

echo ">>> Compiling BPF..."
make -C bpf/

echo ">>> Running Arena Allocator Tests (Privileged)..."
# We strictly filter for TestArenaAllocator to avoid running other tests that might fail or take too long
go test -v ./pkg/maps/policymap -run TestArenaAllocator

echo ">>> Verification Complete!"
