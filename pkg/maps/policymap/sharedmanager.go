// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"iter"
	"sort"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/types"
)

type candidate struct {
	key         types.Key
	entry       types.MapStateEntry
	sharedKey   SharedPolicyKey
	sharedEntry PolicyEntry
	isPrivate   bool
}

// sharedManager is a lightweight controller that consumes the existing policy
// map state and mirrors it into in-memory shared metadata plus overlay records.
// This intentionally avoids any datapath wiring until the layered policy map
// datapath pieces are enabled, but keeps the control-plane flow exercised when
// the feature gate is on.
type sharedManager struct {
	store           *SharedStore
	overlays        map[uint16]OverlayEntryBPF
	spilloverCounts map[uint16]int    // Tracks spillover count per endpoint for metrics
	ruleSetIDs      map[uint16]uint32 // Tracks RuleSetID per endpoint
	allocator       *RuleSetAllocator
	maxShared       int
	maxPrivate      int

	mu sync.Mutex
}

var (
	sharedMgrOnce sync.Once
	sharedMgr     *sharedManager
)

// SharedManagerEnabled reports whether the layered shared policy map plumbing
// should be exercised based on the configured mode.
func SharedManagerEnabled() bool {
	if option.Config.EnablePolicySharedMapArena {
		return true
	}

	if !option.Config.PolicySharedMapEnabled {
		return false
	}

	switch option.Config.PolicySharedMapMode {
	case option.PolicySharedMapModeLegacy, option.PolicySharedMapModeOff:
		return false
	default:
		return true
	}
}

// getSharedManager returns a process-wide shared manager, initializing it from
// the current configuration on first use. Callers should gate invocations with
// SharedManagerEnabled() to avoid unnecessary work when the feature is disabled.
func getSharedManager() *sharedManager {
	sharedMgrOnce.Do(func() {
		sharedMgr = &sharedManager{
			store:           NewSharedStore(),
			overlays:        make(map[uint16]OverlayEntryBPF),
			spilloverCounts: make(map[uint16]int),
			ruleSetIDs:      make(map[uint16]uint32),
		}
		poolSize := option.Config.PolicySharedMapRuleSetPoolSize
		if poolSize <= 0 {
			poolSize = defaults.PolicySharedMapRuleSetPoolSize
		}
		// Initialize Allocators
		// Phase 3 Enablement

		// Initialize Allocators
		// Phase 3 Enablement
		// ArenaAllocator is the ONLY supported allocator now.

		var arenaAlloc *ArenaAllocator
		if option.Config.EnablePolicySharedMapArena {
			// Arena Map should be initialized by InitUniversalMaps
			m := ArenaMap()
			if m != nil {
				// Use Slog for Arena (new component)
				slogger := logging.DefaultSlogLogger.With(logfields.LogSubsys, "policymap-arena")
				alloc, err := NewArenaAllocator(slogger, m)
				if err != nil {
					logrus.WithError(err).Error("Failed to initialize Arena Allocator")
				} else {
					arenaAlloc = alloc
					logrus.Infof("Initialized Arena Allocator with max pages: %d", m.MaxEntries())
				}
			} else {
				logrus.Warn("EnableBPFArenaPolicy is true but Arena Map is not initialized (check InitUniversalMaps logic)")
			}
		}

		sharedMgr.allocator = NewRuleSetAllocator(poolSize, arenaAlloc)
		sharedMgr.maxShared = option.Config.PolicySharedMapMaxSharedRefs
		sharedMgr.maxPrivate = option.Config.PolicySharedMapMaxPrivateOverrides

		if sharedMgr.maxShared <= 0 {
			sharedMgr.maxShared = DefaultMaxSharedRefs
		}
		if sharedMgr.maxPrivate <= 0 {
			sharedMgr.maxPrivate = DefaultMaxPrivateOverride
		}
	})

	return sharedMgr
}

// SyncEndpointOverlay consumes an endpoint's desired policy map entries and
// produces an overlay entry plus shared metadata records. It returns a set of
// PolicyKeys that were successfully offloaded to the shared/overlay maps.
// Entries NOT in the returned set must be written to the legacy per-endpoint map.
func SyncEndpointOverlay(epID uint16, entries iter.Seq2[types.Key, types.MapStateEntry]) (map[types.Key]struct{}, error) {
	fmt.Printf("DEBUG SyncEndpointOverlay epID=%d Enabled=%v\n", epID, SharedManagerEnabled())
	if !SharedManagerEnabled() {
		return nil, nil
	}

	mgr := getSharedManager()

	// 1. Candidate selection: Identify all potential shared keys.
	// We intentionally do NOT limit this list by capacity yet, because we need
	// to select the *best* candidates (though currently we just take them all
	// in iteration order).
	//
	// TODO(shared-policy): Implement priority scoring to prefer sharing
	// frequently-used or high-value rules when caps are hit.

	var candidates []candidate

	entries(func(key types.Key, entry types.MapStateEntry) bool {
		sharedKey := SharedPolicyKey{
			EndpointGroupPrefix: uint32(epID),
			Identity:            key.Identity,
			Direction:           key.TrafficDirection(),
			Nexthdr:             key.Nexthdr,
			DestPortNetwork:     byteorder.HostToNetwork16(key.DestPort),
		}

		// Private override needed for Deny to ensure precedence
		isPrivate := entry.IsDeny()

		pk := NewKeyFromPolicyKey(key)
		pe := NewEntryFromPolicyEntry(pk, entry)

		candidates = append(candidates, candidate{
			key:         key,
			entry:       entry,
			sharedKey:   sharedKey,
			sharedEntry: pe,
			isPrivate:   isPrivate,
		})
		return true
	})

	// Sort candidates for deterministic hashing.
	// We need to sort if we want stable Rule Set Hashes.
	// Map iteration (iter.Seq2) is random?
	// The `entries` iterator comes from PolicyMap.MapChanges/Dump.
	// If it's a map iteration, it's random.
	// So tracking `candidates` slice is good, but we must sort it before hashing.

	// Sort key: Identity, then Direction, then Proto, then Port
	sortCandidates(candidates)
	fmt.Printf("DEBUG SyncEndpointOverlay epID=%d Candidates=%d\n", epID, len(candidates))

	// Calculate RuleSetHash from *SHARED* candidates only (exclude private for hash? or include?)
	// If private overrides are part of the "Intent", they should technically be part of the hash,
	// BUT private overrides are NOT shared.
	// The RuleSetID is used as a prefix for SHARED entries.
	// So two endpoints with same Shared rules but different Private rules
	// should probably share the same RuleSetID for the shared portion!
	// YES. The RuleSetID purely groups the shared entries.
	// So we filter for !isPrivate.

	var sharedCandidates []SharedPolicyKey
	for _, c := range candidates {
		if !c.isPrivate {
			sharedCandidates = append(sharedCandidates, c.sharedKey)
		}
	}

	// Update Phase 3 Call: Pass Keys, allocator calculates hash.
	groupID, _ := mgr.allocator.GetOrAllocate(sharedCandidates)
	fmt.Printf("DEBUG SyncEndpointOverlay epID=%d GroupID=%d SharedCandidates=%d\n", epID, groupID, len(sharedCandidates))

	// Update sharedKey prefixes with the new GroupID
	for i := range candidates {
		if !candidates[i].isPrivate {
			candidates[i].sharedKey.EndpointGroupPrefix = groupID
		}
	}
	// 2. Allocation & Clamping:
	// We use the GroupID (RuleSetID) as the SINGLE shared handle for this endpoint.
	// This enables us to share an unlimited number of rules under a single prefix.

	offloaded := make(map[types.Key]struct{}, len(candidates))

	// Private overrides are capped by MaxPrivateOverrides.
	var finalPrivateOverrides []OverlayPrivateEntry
	currentPrivateCount := 0
	currentSpilloverCount := 0

	for _, c := range candidates {
		if c.isPrivate {
			if currentPrivateCount < mgr.maxPrivate {
				pk := NewKeyFromPolicyKey(c.key)
				finalPrivateOverrides = append(finalPrivateOverrides, OverlayPrivateEntry{
					Key:   pk,
					Entry: c.sharedEntry,
				})
				currentPrivateCount++
			} else {
				currentSpilloverCount++
			}
		} else {
			// Shared entries are ALWAYS offloaded when using RuleSetID logic.
			// We assume the RuleSet ID fits in the BPF map logic (it acts as the prefix).
			// We just mark it offloaded.
			offloaded[c.key] = struct{}{}
		}
	}

	// The Overlay contains just the RuleSetID.
	// We put it in SharedHandles[0].
	// SharedRefCount = 1.
	var finalSharedHandles []uint32
	if groupID > 0 {
		finalSharedHandles = append(finalSharedHandles, groupID)
	}

	// NOTE: We bypass 'mgr.store' (SharedStore) usage here because it tracks individual
	// entry references which is O(N) and redundant when using RuleSetID O(1).
	// RefCounting for the RuleSetID is handled by 'mgr.allocator'.

	// 3. Construct Final Overlay
	overlay := OverlayEntry{
		SharedHandles: finalSharedHandles,
		Private:       finalPrivateOverrides,
	}

	// No need to Clamp() again because we built it to size.
	// Just convert to BPF format.
	clamped := overlay.ClampWith(mgr.maxShared, mgr.maxPrivate)

	mgr.mu.Lock()
	old, ok := mgr.overlays[epID]
	var oldPrivate int
	if ok {
		oldPrivate = int(old.PrivateCount)
	}
	newPrivate := int(clamped.PrivateCount)
	metrics.PolicySharedMapEntries.WithLabelValues(metrics.LabelSharedMapPriv).Add(float64(newPrivate - oldPrivate))

	oldSpill := mgr.spilloverCounts[epID]
	metrics.PolicySharedMapEntries.WithLabelValues(metrics.LabelSharedMapSpillover).Add(float64(currentSpilloverCount - oldSpill))
	mgr.spilloverCounts[epID] = currentSpilloverCount

	// Track RuleSetID changes
	oldGroupID, hadGroup := mgr.ruleSetIDs[epID]
	if hadGroup && oldGroupID != groupID {
		// Decrement old group ref
		mgr.allocator.ReleaseByID(oldGroupID)
	}
	mgr.ruleSetIDs[epID] = groupID

	mgr.overlays[epID] = clamped
	mgr.mu.Unlock()

	// 4. Update BPF Maps

	log := logrus.WithField(logfields.EndpointID, epID).WithField(logfields.LogSubsys, "policymap")

	// Optimization: Just update all candidates that are marked offloaded AND are shared
	for _, c := range candidates {
		if _, isOffloaded := offloaded[c.key]; isOffloaded && !c.isPrivate {
			// Phase 2 Logic (Populating cilium_policy_shared) REMOVED.
			// We ONLY use Arena/RuleSetID logic now.
			// The RuleSetID (groupID) was already allocated via mgr.allocator.GetOrAllocate.
			// The Global Rules were written to Arena inside GetOrAllocate.
			// So nothing to do here for shared entries.
		}
	}

	if err := updateOverlayPolicyEntry(epID, clamped); err != nil {
		log.WithError(err).Debug("failed to update overlay policy entry")
	}

	return offloaded, nil
}

// RemoveEndpointOverlay drops overlay metadata and dereferences shared handles
// for the given endpoint. This allows endpoint teardown paths to keep the shared
// store accurate even before datapath garbage collection is wired up.
func RemoveEndpointOverlay(epID uint16) {
	if !SharedManagerEnabled() {
		return
	}

	mgr := getSharedManager()
	mgr.mu.Lock()
	overlay, ok := mgr.overlays[epID]
	if ok {
		delete(mgr.overlays, epID)
		metrics.PolicySharedMapEntries.WithLabelValues(metrics.LabelSharedMapPriv).Sub(float64(overlay.PrivateCount))
	}
	oldSpill, spillOk := mgr.spilloverCounts[epID]
	if spillOk {
		delete(mgr.spilloverCounts, epID)
		metrics.PolicySharedMapEntries.WithLabelValues(metrics.LabelSharedMapSpillover).Sub(float64(oldSpill))
	}
	// Release RuleSetID
	if gid, ok := mgr.ruleSetIDs[epID]; ok {
		mgr.allocator.ReleaseByID(gid)
		delete(mgr.ruleSetIDs, epID)
	}
	mgr.mu.Unlock()

	if !ok {
		return
	}

	for i := 0; i < int(overlay.SharedRefCount); i++ {
		if count, removed, key := mgr.store.Dereference(overlay.SharedRefs[i], epID); removed || count == 0 {
			if err := deleteSharedPolicyKey(key); err != nil {
				logrus.WithField(logfields.LogSubsys, "policymap").WithError(err).Debug("failed to delete shared policy entry")
			}
		}
	}

	if err := deleteOverlayPolicyEntry(epID); err != nil {
		logrus.WithField(logfields.LogSubsys, "policymap").WithError(err).Debug("failed to delete overlay policy entry")
	}
}

// OverlaySnapshot returns a copy of the stored overlay entry for tests.
func OverlaySnapshot(epID uint16) (OverlayEntryBPF, bool) {
	mgr := getSharedManager()
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	overlay, ok := mgr.overlays[epID]
	return overlay, ok
}
func sortCandidates(c []candidate) {
	sort.Slice(c, func(i, j int) bool {
		ki, kj := c[i].key, c[j].key
		if ki.Identity != kj.Identity {
			return ki.Identity < kj.Identity
		}
		if ki.TrafficDirection() != kj.TrafficDirection() {
			return ki.TrafficDirection() < kj.TrafficDirection()
		}
		if ki.Nexthdr != kj.Nexthdr {
			return ki.Nexthdr < kj.Nexthdr
		}
		return ki.DestPort < kj.DestPort
	})
}
