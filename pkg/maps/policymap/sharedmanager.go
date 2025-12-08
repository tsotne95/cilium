// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"iter"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/types"
)

// sharedManager is a lightweight controller that consumes the existing policy
// map state and mirrors it into in-memory shared metadata plus overlay records.
// This intentionally avoids any datapath wiring until the layered policy map
// datapath pieces are enabled, but keeps the control-plane flow exercised when
// the feature gate is on.
type sharedManager struct {
	store      *SharedStore
	overlays   map[uint16]OverlayEntryBPF
	maxShared  int
	maxPrivate int

	mu sync.Mutex
}

var (
	sharedMgrOnce sync.Once
	sharedMgr     *sharedManager
)

// SharedManagerEnabled reports whether the layered shared policy map plumbing
// should be exercised based on the configured mode.
func SharedManagerEnabled() bool {
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
			store:      NewSharedStore(),
			overlays:   make(map[uint16]OverlayEntryBPF),
			maxShared:  option.Config.PolicySharedMapMaxSharedRefs,
			maxPrivate: option.Config.PolicySharedMapMaxPrivateOverrides,
		}
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
// produces an overlay entry plus shared metadata records. The resulting overlay
// is retained in-memory so unit tests and metrics can reason about deduplication
// without immediately wiring in datapath lookups.
func SyncEndpointOverlay(epID uint16, entries iter.Seq2[types.Key, types.MapStateEntry]) error {
	if !SharedManagerEnabled() {
		return nil
	}

	mgr := getSharedManager()
	now := time.Now()

	overlay := OverlayEntry{}
	var newShared []struct {
		key   SharedPolicyKey
		entry PolicyEntry
	}

	entries(func(key types.Key, entry types.MapStateEntry) bool {
		sharedKey := SharedPolicyKey{
			EndpointGroupPrefix: uint32(epID),
			Identity:            key.Identity,
			Direction:           key.TrafficDirection(),
			Nexthdr:             key.Nexthdr,
			DestPortNetwork:     byteorder.HostToNetwork16(key.DestPort),
		}

		handle, meta := mgr.store.Reference(sharedKey, epID, now)
		if meta.RefCount == 1 {
			pk := NewKeyFromPolicyKey(key)
			pe := NewEntryFromPolicyEntry(pk, entry)
			newShared = append(newShared, struct {
				key   SharedPolicyKey
				entry PolicyEntry
			}{key: sharedKey, entry: pe})
		}
		overlay.SharedHandles = append(overlay.SharedHandles, handle)

		// Preserve private overrides for denies to ensure precedence is kept
		// when overlays are consumed by the datapath.
		if entry.IsDeny() {
			pk := NewKeyFromPolicyKey(key)
			pe := NewEntryFromPolicyEntry(pk, entry)
			overlay.Private = append(overlay.Private, pe)
		}

		return true
	})

	clamped := overlay.ClampWith(mgr.maxShared, mgr.maxPrivate)
	mgr.mu.Lock()
	mgr.overlays[epID] = clamped
	mgr.mu.Unlock()

	// Best-effort map population; errors are logged but do not prevent policy
	// regeneration while the feature is in early rollout.
	log := logrus.WithField(logfields.EndpointID, epID).WithField(logfields.LogSubsys, "policymap")
	for _, upsert := range newShared {
		if err := updateSharedPolicyKey(upsert.key, upsert.entry); err != nil {
			log.WithError(err).Debug("failed to update shared policy map entry")
		}
	}
	if err := updateOverlayPolicyEntry(epID, clamped); err != nil {
		log.WithError(err).Debug("failed to update overlay policy entry")
	}

	return nil
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
