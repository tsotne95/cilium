// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"log/slog"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/spf13/viper"
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

func sharedPolicyLogger() *slog.Logger {
	return logging.DefaultSlogLogger.With(logfields.LogSubsys, "policymap")
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

// configuredPolicyMapMax is the configured maximum number of entries in the policy map.
// It is set by InitSharedPolicyMaps.
var configuredPolicyMapMax int

// SharedPolicyMap returns the singleton shared policy map, creating it on first
// access. Errors are cached to avoid repeated map creation attempts.
func SharedPolicyMap() (*ebpf.Map, error) {
	sharedPolicyMapOnce.Do(func() {
		maxEntries := configuredPolicyMapMax
		if maxEntries == 0 {
			maxEntries = viper.GetInt("bpf-policy-map-max")
		}
		if maxEntries == 0 {
			maxEntries = defaults.PolicyMapEntries
		}
		sharedPolicyMap = ebpf.NewMap(sharedPolicyLogger(), &ebpf.MapSpec{
			Name:       SharedPolicyMapName,
			Type:       ebpf.LPMTrie,
			KeySize:    uint32(unsafe.Sizeof(SharedPolicyLPMKey{})),
			ValueSize:  uint32(unsafe.Sizeof(PolicyEntry{})),
			MaxEntries: uint32(maxEntries),
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    ebpf.PinByName,
		})
	})

	return sharedPolicyMap, sharedPolicyMapErr
}

// OverlayPolicyMap returns the overlay map keyed by endpoint ID.
func OverlayPolicyMap() (*ebpf.Map, error) {
	overlayPolicyMapOnce.Do(func() {
		maxEntries := configuredPolicyMapMax
		if maxEntries == 0 {
			maxEntries = viper.GetInt("bpf-policy-map-max")
		}
		if maxEntries == 0 {
			maxEntries = defaults.PolicyMapEntries
		}
		overlayPolicyMap = ebpf.NewMap(sharedPolicyLogger(), &ebpf.MapSpec{
			Name:       PolicyOverlayMapName,
			Type:       ebpf.Hash,
			KeySize:    uint32(unsafe.Sizeof(uint32(0))),
			ValueSize:  uint32(unsafe.Sizeof(OverlayEntryBPF{})),
			MaxEntries: uint32(maxEntries),
			Pinning:    ebpf.PinByName,
		})
	})

	return overlayPolicyMap, overlayPolicyMapErr
}

var (
	deleteSharedPolicyKey = func(key SharedPolicyKey) error {
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

	updateSharedPolicyKey = func(key SharedPolicyKey, entry PolicyEntry) error {
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

	updateOverlayPolicyEntry = func(epID uint16, overlay OverlayEntryBPF) error {
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

	deleteOverlayPolicyEntry = func(epID uint16) error {
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
)

// InitSharedPolicyMaps eagerly creates the shared and overlay policy maps when
// the agent starts. This is done to ensure they are pinned and available even
// if no endpoints use them immediately.
func InitSharedPolicyMaps(maxEntries int) error {
	if !SharedManagerEnabled() {
		return nil
	}

	configuredPolicyMapMax = maxEntries

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
