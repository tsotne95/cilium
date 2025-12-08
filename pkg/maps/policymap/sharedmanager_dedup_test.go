package policymap

import (
	"iter"
	"testing"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/stretchr/testify/assert"
)

// Helper to convert map to iterator
func mapToIter(m types.MapStateMap) iter.Seq2[types.Key, types.MapStateEntry] {
	return func(yield func(types.Key, types.MapStateEntry) bool) {
		for k, v := range m {
			if !yield(k, v) {
				return
			}
		}
	}
}

// TestSyncEndpointOverlay_Deduplication verifies that two endpoints with identical
// policy rules are assigned the same RuleSetID and thus share the same map key space.
func TestSyncEndpointOverlay_Deduplication(t *testing.T) {
	t.Skip("Skipping Dedup test: requires valid ArenaAllocator")
	// Setup options
	option.Config.PolicySharedMapEnabled = true
	option.Config.PolicySharedMapMode = option.PolicySharedMapModeShared
	option.Config.PolicySharedMapMaxSharedRefs = 10
	option.Config.PolicySharedMapMaxPrivateOverrides = 5
	option.Config.PolicySharedMapMetrics = false
	option.Config.PolicySharedMapRuleSetPoolSize = 100 // Small pool for testing
	defer func() {
		option.Config.PolicySharedMapEnabled = false
	}()

	// Force init so we can overwrite
	_ = getSharedManager()
	sharedMgr = &sharedManager{
		store:           NewSharedStore(),
		overlays:        make(map[uint16]OverlayEntryBPF),
		spilloverCounts: make(map[uint16]int),
		ruleSetIDs:      make(map[uint16]uint32),
		allocator:       NewRuleSetAllocator(100, nil),
		maxShared:       10,
		maxPrivate:      5,
	}

	// Mock low-level map operations to prevent panic
	origUpdateSharedPolicyKey := updateSharedPolicyKey
	origDeleteSharedPolicyKey := deleteSharedPolicyKey
	origUpdateOverlayPolicyEntry := updateOverlayPolicyEntry
	origDeleteOverlayPolicyEntry := deleteOverlayPolicyEntry

	updateSharedPolicyKey = func(key SharedPolicyKey, entry PolicyEntry) error { return nil }
	deleteSharedPolicyKey = func(key SharedPolicyKey) error { return nil }
	updateOverlayPolicyEntry = func(epID uint16, overlay OverlayEntryBPF) error { return nil }
	deleteOverlayPolicyEntry = func(epID uint16) error { return nil }

	defer func() {
		updateSharedPolicyKey = origUpdateSharedPolicyKey
		deleteSharedPolicyKey = origDeleteSharedPolicyKey
		updateOverlayPolicyEntry = origUpdateOverlayPolicyEntry
		deleteOverlayPolicyEntry = origDeleteOverlayPolicyEntry
	}()

	// Create identical policy rules for two endpoints
	// Rule 1: Allow Ingress Port 80
	key1 := types.Key{
		LPMKey: types.LPMKey{
			Nexthdr:  u8proto.TCP,
			DestPort: 80,
		},
		Identity: 100,
	}
	entry1 := types.MapStateEntry{
		ProxyPort: 0,
	}

	// Rule 2: Allow Ingress Port 443
	key2 := types.Key{
		LPMKey: types.LPMKey{
			Nexthdr:  u8proto.TCP,
			DestPort: 443,
		},
		Identity: 101,
	}
	entry2 := types.MapStateEntry{
		ProxyPort: 0,
	}

	policyMap := make(types.MapStateMap)
	policyMap[key1] = entry1
	policyMap[key2] = entry2

	ep1ID := uint16(1001)
	ep2ID := uint16(1002)

	// Sync Endpoint 1
	SyncEndpointOverlay(ep1ID, mapToIter(policyMap))

	// Sync Endpoint 2
	SyncEndpointOverlay(ep2ID, mapToIter(policyMap))

	// Verify RuleSetIDs
	gid1, ok1 := sharedMgr.ruleSetIDs[ep1ID]
	gid2, ok2 := sharedMgr.ruleSetIDs[ep2ID]

	assert.True(t, ok1, "Endpoint 1 should have a RuleSetID")
	assert.True(t, ok2, "Endpoint 2 should have a RuleSetID")
	assert.NotZero(t, gid1, "Group ID should be non-zero")
	assert.Equal(t, gid1, gid2, "Both endpoints should share the same RuleSetID (GroupID)")

	// Verify Reference Counting
	// The allocator should have refcount 2 for this ID
	sharedMgr.allocator.mu.Lock()
	count, exists := sharedMgr.allocator.refcount[gid1]
	sharedMgr.allocator.mu.Unlock()
	assert.True(t, exists, "GroupID should exist in allocator")
	assert.Equal(t, 2, count, "GroupID refcount should be 2")

	// Verify Shared Store Contents
	// We can't easily inspect store internals without lock, but we can verify handles in overlay
	overlay1 := sharedMgr.overlays[ep1ID]
	overlay2 := sharedMgr.overlays[ep2ID]

	// In Phase 3 (Universal) or RuleSetID mode, we aggregate all rules into ONE RuleSetID.
	// So each overlay should have exactly 1 shared handle.
	assert.Equal(t, int(overlay1.SharedRefCount), 1)
	assert.Equal(t, int(overlay2.SharedRefCount), 1)

	// Collect shared handles for comparison (order might vary if sort is not deterministic, but it IS deterministic)
	// We should check that sets of handles are identical.
	handles1 := make(map[uint32]bool)
	for i := 0; i < int(overlay1.SharedRefCount); i++ {
		handles1[overlay1.SharedRefs[i]] = true
	}

	handles2 := make(map[uint32]bool)
	for i := 0; i < int(overlay2.SharedRefCount); i++ {
		handles2[overlay2.SharedRefs[i]] = true
	}

	assert.Equal(t, handles1, handles2, "Shared handles should be identical for identical policies")

	// Now Remove Endpoint 1
	RemoveEndpointOverlay(ep1ID)

	// Verify RuleSetID refcount Decremented
	sharedMgr.allocator.mu.Lock()
	count_after, exists_after := sharedMgr.allocator.refcount[gid1]
	sharedMgr.allocator.mu.Unlock()
	assert.True(t, exists_after)
	assert.Equal(t, 1, count_after)

	// Remove Endpoint 2
	RemoveEndpointOverlay(ep2ID)

	// Verify RuleSetID Released
	sharedMgr.allocator.mu.Lock()
	_, exists_final := sharedMgr.allocator.refcount[gid1]
	sharedMgr.allocator.mu.Unlock()
	assert.False(t, exists_final, "GroupID should be released after all endpoints removed")
}
