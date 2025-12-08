// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

// SharedPolicyKey identifies entries in the node-scoped shared policy map.
//
// The EndpointGroupPrefix currently mirrors the endpoint ID, but is preserved
// as a prefix field to allow future grouping strategies without changing the
// datapath key layout.
//
// Must be kept in sync with struct shared_policy_key in the datapath once the
// map is wired up.
type SharedPolicyKey struct {
	EndpointGroupPrefix uint32
	Identity            identity.NumericIdentity
	Direction           trafficdirection.TrafficDirection
	Nexthdr             u8proto.U8proto
	DestPortNetwork     uint16
}

// SharedPolicyEntry reuses the existing PolicyEntry layout to avoid duplicating
// datapath definitions.
type SharedPolicyEntry = PolicyEntry

// OverlayEntry captures the per-endpoint overlay that augments the shared
// policy map. SharedHandles reference entries in the shared map, while Private
// contains endpoint-scoped overrides that should bypass sharing.
type OverlayEntry struct {
	SharedHandles []uint32
	Private       []PolicyEntry
}

// The maximum overlay dimensions are compiled into the BPF value layout. They
// are intentionally small defaults that can be tuned via build options once the
// datapath wiring is added.
const (
	DefaultMaxSharedRefs      = 16
	DefaultMaxPrivateOverride = 8
)

// OverlayEntryBPF mirrors struct overlay_entry in the datapath. The struct
// needs a fixed-size layout so the arrays are backed by constants rather than
// runtime configuration.
type OverlayEntryBPF struct {
	SharedRefCount   uint8
	PrivateCount     uint8
	SharedRefs       [DefaultMaxSharedRefs]uint32
	PrivateOverrides [DefaultMaxPrivateOverride]PolicyEntry
}

// Clamp converts the high-level OverlayEntry into the fixed-size BPF-friendly
// representation, truncating any entries that exceed the configured maximums.
func (o OverlayEntry) Clamp() OverlayEntryBPF {
	return o.ClampWith(DefaultMaxSharedRefs, DefaultMaxPrivateOverride)
}

// ClampWith converts to OverlayEntryBPF while honoring explicit limits. This
// helper is primarily used by tests to emulate kernels compiled with different
// bounds without rebuilding the entire daemon.
func (o OverlayEntry) ClampWith(maxShared, maxPrivate int) OverlayEntryBPF {
	var out OverlayEntryBPF

	shared := len(o.SharedHandles)
	if shared > maxShared {
		shared = maxShared
	}
	out.SharedRefCount = uint8(shared)
	for i := 0; i < shared; i++ {
		out.SharedRefs[i] = o.SharedHandles[i]
	}

	priv := len(o.Private)
	if priv > maxPrivate {
		priv = maxPrivate
	}
	out.PrivateCount = uint8(priv)
	for i := 0; i < priv; i++ {
		out.PrivateOverrides[i] = o.Private[i]
	}

	return out
}

// SharedMetadata tracks ownership of a single shared policy entry. The OwnerEps
// map is used to drive garbage collection and to attribute per-endpoint quotas
// during spillover handling.
type SharedMetadata struct {
	Key      SharedPolicyKey
	RefCount int
	OwnerEps map[uint16]struct{}
	LastUsed time.Time
}

// SharedStore maintains the mapping between policy keys and shared handles. The
// store is intentionally simple so it can be used by unit tests without
// requiring the datapath to be present.
type SharedStore struct {
	mu sync.Mutex

	nextHandle    uint32
	keyToHandle   map[SharedPolicyKey]uint32
	handleToEntry map[uint32]*SharedMetadata
}

// NewSharedStore creates an empty store with handle allocation starting at 1 to
// keep zero as a sentinel value.
func NewSharedStore() *SharedStore {
	return &SharedStore{
		nextHandle:    1,
		keyToHandle:   make(map[SharedPolicyKey]uint32),
		handleToEntry: make(map[uint32]*SharedMetadata),
	}
}

// Reference increments (or creates) a shared entry. It returns the handle that
// should be written into the overlay and the backing metadata record.
func (s *SharedStore) Reference(key SharedPolicyKey, owner uint16, now time.Time) (uint32, *SharedMetadata) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if h, ok := s.keyToHandle[key]; ok {
		meta := s.handleToEntry[h]
		meta.RefCount++
		if meta.OwnerEps == nil {
			meta.OwnerEps = make(map[uint16]struct{})
		}
		meta.OwnerEps[owner] = struct{}{}
		meta.LastUsed = now
		return h, meta
	}

	handle := s.nextHandle
	s.nextHandle++

	meta := &SharedMetadata{
		Key:      key,
		RefCount: 1,
		OwnerEps: map[uint16]struct{}{owner: {}},
		LastUsed: now,
	}
	s.keyToHandle[key] = handle
	s.handleToEntry[handle] = meta
	return handle, meta
}

// Dereference decreases the reference count for the given handle. It returns
// the resulting reference count and a boolean indicating whether the entry was
// removed.

func (s *SharedStore) Dereference(handle uint32, owner uint16) (int, bool, SharedPolicyKey) {
	s.mu.Lock()
	defer s.mu.Unlock()

	meta, ok := s.handleToEntry[handle]
	if !ok {
		return 0, false, SharedPolicyKey{}
	}

	if meta.RefCount > 0 {
		meta.RefCount--
	}
	delete(meta.OwnerEps, owner)
	if meta.RefCount > 0 {
		return meta.RefCount, false, meta.Key
	}

	delete(s.handleToEntry, handle)
	delete(s.keyToHandle, meta.Key)
	return 0, true, meta.Key
}

// GarbageCollect removes entries that have no owners or that were last used
// before the provided cutoff. The handles of the deleted entries are returned to
// allow caller-side cleanup.
func (s *SharedStore) GarbageCollect(cutoff time.Time) []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()

	var deleted []uint32
	for handle, meta := range s.handleToEntry {
		if meta.RefCount == 0 || meta.LastUsed.Before(cutoff) {
			deleted = append(deleted, handle)
			delete(s.handleToEntry, handle)
			delete(s.keyToHandle, meta.Key)
		}
	}
	return deleted
}

// HandleForKey returns the handle if the key is known. It is primarily useful
// for tests that need to assert deduplication.
func (s *SharedStore) HandleForKey(key SharedPolicyKey) (uint32, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	h, ok := s.keyToHandle[key]
	return h, ok
}

// Metadata returns the metadata record for a handle if present.
func (s *SharedStore) Metadata(handle uint32) (*SharedMetadata, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	meta, ok := s.handleToEntry[handle]
	return meta, ok
}
