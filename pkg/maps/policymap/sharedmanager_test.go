// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// resetSharedManagerForTest clears the singleton so each test starts from a
// clean slate.
func resetSharedManagerForTest() {
	sharedMgrOnce = sync.Once{}
	sharedMgr = nil
}

func TestSyncEndpointOverlayStoresOverrides(t *testing.T) {
	// 1. Setup options
	option.Config.PolicySharedMapEnabled = true
	option.Config.PolicySharedMapMode = option.PolicySharedMapModeShared
	option.Config.PolicySharedMapMaxSharedRefs = 4
	option.Config.PolicySharedMapMaxPrivateOverrides = 4
	option.Config.EnablePolicySharedMapArena = true

	// 2. Initialize Real Arena Map (Requires Root)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Logf("Failed to remove memlock rlimit: %v", err)
	}

	// Create ephemeral Arena map (No Pinning)
	// Use fmt.Sprintf for a unique name if needed, but unpinned maps don't need unique names globally, just FD.
	// But let's verify if 'Name' matters. Upstream ebpf might use it for /proc.
	m := ebpf.NewMap(logging.DefaultSlogLogger, &ciliumebpf.MapSpec{
		Name:       "cilium_test_ov",
		Type:       ciliumebpf.MapType(33), // BPF_MAP_TYPE_ARENA
		KeySize:    0,
		ValueSize:  0,
		MaxEntries: 512,
		Flags:      1 << 10, // BPF_F_MMAPABLE
	})
	if err := m.OpenOrCreate(); err != nil {
		t.Fatalf("Failed to create ephemeral arena map: %v", err)
	}
	arenaMap = m // Inject into global variable

	// Check cleanup
	t.Cleanup(func() {
		option.Config.PolicySharedMapEnabled = false
		option.Config.EnablePolicySharedMapArena = false
		resetSharedManagerForTest()
		if arenaMap != nil {
			arenaMap.Close()
			arenaMap = nil
		}
	})

	resetSharedManagerForTest()
	mgr := getSharedManager()

	seq := func(yield func(policyTypes.Key, policyTypes.MapStateEntry) bool) {
		key := policyTypes.KeyForDirection(trafficdirection.Ingress).WithPortProto(u8proto.TCP, 80)
		key.Identity = 128
		yield(key, policyTypes.AllowEntry())
		return
	}

	// Mock BPF map operations
	oldUpdateOverlay := updateOverlayPolicyEntry
	oldUpdateShared := updateSharedPolicyKey
	oldDeleteShared := deleteSharedPolicyKey
	oldDeleteOverlay := deleteOverlayPolicyEntry
	defer func() {
		updateOverlayPolicyEntry = oldUpdateOverlay
		updateSharedPolicyKey = oldUpdateShared
		deleteSharedPolicyKey = oldDeleteShared
		deleteOverlayPolicyEntry = oldDeleteOverlay
	}()

	updateOverlayPolicyEntry = func(epID uint16, overlay OverlayEntryBPF) error { return nil }
	updateSharedPolicyKey = func(key SharedPolicyKey, entry PolicyEntry) error { return nil }
	deleteSharedPolicyKey = func(key SharedPolicyKey) error { return nil }
	deleteOverlayPolicyEntry = func(epID uint16) error { return nil }

	_, err := SyncEndpointOverlay(10, seq)
	require.NoError(t, err)

	overlay, ok := OverlaySnapshot(10)
	require.True(t, ok)
	require.Equal(t, uint8(1), overlay.SharedRefCount)
	require.Equal(t, uint8(0), overlay.PrivateCount)

	mgr.allocator.mu.Lock()
	count, exists := mgr.allocator.refcount[overlay.SharedRefs[0]]
	mgr.allocator.mu.Unlock()
	require.True(t, exists)
	require.Equal(t, 1, count)

	RemoveEndpointOverlay(10)
	_, still := OverlaySnapshot(10)
	require.False(t, still)
}
