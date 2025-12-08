// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestOverlayClamp(t *testing.T) {
	overlay := OverlayEntry{
		SharedHandles: []uint32{1, 2, 3, 4, 5},
		Private: []OverlayPrivateEntry{
			{Entry: PolicyEntry{ProxyPortNetwork: byteorder.HostToNetwork16(1)}},
			{Entry: PolicyEntry{ProxyPortNetwork: byteorder.HostToNetwork16(2)}},
			{Entry: PolicyEntry{ProxyPortNetwork: byteorder.HostToNetwork16(3)}},
			{Entry: PolicyEntry{ProxyPortNetwork: byteorder.HostToNetwork16(4)}},
		},
	}

	clamped := overlay.ClampWith(3, 2)
	if got, want := int(clamped.SharedRefCount), 3; got != want {
		t.Fatalf("unexpected shared ref count: %d want %d", got, want)
	}
	if clamped.SharedRefs[0] != 1 || clamped.SharedRefs[2] != 3 {
		t.Fatalf("unexpected shared refs: %+v", clamped.SharedRefs)
	}

	if got, want := int(clamped.PrivateCount), 2; got != want {
		t.Fatalf("unexpected private count: %d want %d", got, want)
	}
	if clamped.PrivateOverrides[0].Entry.GetProxyPort() != 1 || clamped.PrivateOverrides[1].Entry.GetProxyPort() != 2 {
		t.Fatalf("unexpected private overrides: %+v", clamped.PrivateOverrides)
	}
}

func TestSharedStoreLifecycle(t *testing.T) {
	store := NewSharedStore()
	now := time.Now()

	key := SharedPolicyKey{
		EndpointGroupPrefix: 42,
		Identity:            identity.NumericIdentity(1234),
		Direction:           trafficdirection.Egress,
		Nexthdr:             u8proto.TCP,
		DestPortNetwork:     80,
	}

	handle, meta := store.Reference(key, 10, now)
	if handle == 0 {
		t.Fatal("expected handle to be allocated")
	}
	if meta.RefCount != 1 {
		t.Fatalf("unexpected refcount: %d", meta.RefCount)
	}

	againHandle, meta := store.Reference(key, 11, now.Add(time.Second))
	if againHandle != handle {
		t.Fatalf("expected deduplication: %d vs %d", handle, againHandle)
	}
	if meta.RefCount != 2 {
		t.Fatalf("unexpected refcount after second reference: %d", meta.RefCount)
	}
	if _, ok := meta.OwnerEps[10]; !ok {
		t.Fatalf("missing owner 10")
	}
	if _, ok := meta.OwnerEps[11]; !ok {
		t.Fatalf("missing owner 11")
	}

	if ref, deleted, _ := store.Dereference(handle, 10); ref != 1 || deleted {
		t.Fatalf("unexpected deref result ref=%d deleted=%v", ref, deleted)
	}

	cutoff := now.Add(2 * time.Second)
	deleted := store.GarbageCollect(cutoff)
	if len(deleted) != 0 {
		t.Fatalf("expected no GC while refcount positive, got %v", deleted)
	}

	// Dereference returns true (ref count 0) but deferred deletion means it is NOT removed from map.
	if ref, zero, _ := store.Dereference(handle, 11); ref != 0 || !zero {
		t.Fatalf("expected zero ref on last deref, got ref=%d zero=%v", ref, zero)
	}

	deleted = store.GarbageCollect(cutoff)
	if len(deleted) != 1 {
		t.Fatalf("expected stale handle to be removed by GC, got %v", deleted)
	}
}

func TestSharedStoreGarbageCollectsStale(t *testing.T) {
	store := NewSharedStore()
	now := time.Now()

	key := SharedPolicyKey{EndpointGroupPrefix: 1}
	handle, _ := store.Reference(key, 1, now.Add(-time.Hour))
	store.Dereference(handle, 1)

	deleted := store.GarbageCollect(time.Now())
	if len(deleted) != 1 || deleted[0] != handle {
		t.Fatalf("expected stale handle to be removed, got %v", deleted)
	}
}

func TestSharedPolicyPrefixBits(t *testing.T) {
	if got, want := SharedPolicyPrefixBits(), uint32(unsafe.Sizeof(SharedPolicyKey{})*8); got != want {
		t.Fatalf("unexpected prefix bits: %d want %d", got, want)
	}
}
