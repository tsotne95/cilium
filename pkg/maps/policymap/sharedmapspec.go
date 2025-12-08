// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	SharedPolicyMapName  = "cilium_policy_shared"
	PolicyOverlayMapName = "cilium_policy_overlay"
)

// sharedPolicyPrefixBits covers the entire SharedPolicyKey to ensure exact
// matches in the shared LPM trie until grouping semantics are expanded.
const sharedPolicyPrefixBits = uint32(unsafe.Sizeof(SharedPolicyKey{}) * 8)

// SharedPolicyLPMKey mirrors struct shared_policy_key on the datapath with a
// leading prefix length field required for LPM trie keys.
type SharedPolicyLPMKey struct {
	Prefixlen uint32
	Key       SharedPolicyKey
}

var (
	sharedPolicyMapOnce sync.Once
	sharedPolicyMap     *ebpf.Map
	sharedPolicyMapErr  error

	overlayPolicyMapOnce sync.Once
	overlayPolicyMap     *ebpf.Map
	overlayPolicyMapErr  error
)

func sharedPolicyLogger() *logging.Logger {
	return logging.DefaultLogger.WithField(logfields.LogSubsys, "policymap")
}

func newSharedLPMKey(key SharedPolicyKey) SharedPolicyLPMKey {
	return SharedPolicyLPMKey{Prefixlen: sharedPolicyPrefixBits, Key: key}
}

// SharedPolicyPrefixBits exposes the prefix length used for shared policy keys
// so tests can assert exact match semantics without relying on unsafe.Sizeof
// directly.
func SharedPolicyPrefixBits() uint32 {
	return sharedPolicyPrefixBits
}

// SharedPolicyMap returns the singleton shared policy map, creating it on first
// access. Errors are cached to avoid repeated map creation attempts.
func SharedPolicyMap() (*ebpf.Map, error) {
	sharedPolicyMapOnce.Do(func() {
		sharedPolicyMap = ebpf.NewMap(sharedPolicyLogger(), &ebpf.MapSpec{
			Name:       SharedPolicyMapName,
			Type:       ebpf.LPMTrie,
			KeySize:    uint32(unsafe.Sizeof(SharedPolicyLPMKey{})),
			ValueSize:  uint32(unsafe.Sizeof(PolicyEntry{})),
			MaxEntries: uint32(defaults.PolicyMapEntries),
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    ebpf.PinByName,
		})
		sharedPolicyMapErr = sharedPolicyMap.Err()
	})

	return sharedPolicyMap, sharedPolicyMapErr
}

// OverlayPolicyMap returns the overlay map keyed by endpoint ID.
func OverlayPolicyMap() (*ebpf.Map, error) {
	overlayPolicyMapOnce.Do(func() {
		overlayPolicyMap = ebpf.NewMap(sharedPolicyLogger(), &ebpf.MapSpec{
			Name:       PolicyOverlayMapName,
			Type:       ebpf.Hash,
			KeySize:    uint32(unsafe.Sizeof(uint32(0))),
			ValueSize:  uint32(unsafe.Sizeof(OverlayEntryBPF{})),
			MaxEntries: uint32(defaults.PolicyMapEntries),
			Pinning:    ebpf.PinByName,
		})
		overlayPolicyMapErr = overlayPolicyMap.Err()
	})

	return overlayPolicyMap, overlayPolicyMapErr
}

func deleteSharedPolicyKey(key SharedPolicyKey) error {
	m, err := SharedPolicyMap()
	if err != nil {
		return err
	}
	if m == nil {
		return fmt.Errorf("shared policy map unavailable")
	}
	lpmKey := newSharedLPMKey(key)
	return m.Delete(&lpmKey)
}

func updateSharedPolicyKey(key SharedPolicyKey, entry PolicyEntry) error {
	m, err := SharedPolicyMap()
	if err != nil {
		return err
	}
	if m == nil {
		return fmt.Errorf("shared policy map unavailable")
	}
	lpmKey := newSharedLPMKey(key)
	return m.Update(&lpmKey, &entry, 0)
}

func updateOverlayPolicyEntry(epID uint16, overlay OverlayEntryBPF) error {
	m, err := OverlayPolicyMap()
	if err != nil {
		return err
	}
	if m == nil {
		return fmt.Errorf("overlay policy map unavailable")
	}
	epKey := uint32(epID)
	return m.Update(&epKey, &overlay, 0)
}

func deleteOverlayPolicyEntry(epID uint16) error {
	m, err := OverlayPolicyMap()
	if err != nil {
		return err
	}
	if m == nil {
		return fmt.Errorf("overlay policy map unavailable")
	}
	epKey := uint32(epID)
	return m.Delete(&epKey)
}

// InitSharedPolicyMaps eagerly creates the shared and overlay policy maps when
// the layered policy pipeline is enabled. This avoids late map creation during
// endpoint regeneration and lets the agent fail fast if the kernel does not
// support the required map types.
func InitSharedPolicyMaps() error {
	if !SharedManagerEnabled() {
		return nil
	}

	shared, err := SharedPolicyMap()
	if err != nil {
		return err
	}
	if shared == nil {
		return fmt.Errorf("shared policy map unavailable")
	}
	if err := shared.OpenOrCreate(); err != nil {
		return fmt.Errorf("create %s: %w", SharedPolicyMapName, err)
	}

	overlay, err := OverlayPolicyMap()
	if err != nil {
		return err
	}
	if overlay == nil {
		return fmt.Errorf("overlay policy map unavailable")
	}
	if err := overlay.OpenOrCreate(); err != nil {
		return fmt.Errorf("create %s: %w", PolicyOverlayMapName, err)
	}

	return nil
}
