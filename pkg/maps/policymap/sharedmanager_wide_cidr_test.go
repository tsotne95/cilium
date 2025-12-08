package policymap

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestSharedManager_WideCIDRDedup(t *testing.T) {
	// 1. Setup
	option.Config.PolicySharedMapEnabled = true
	option.Config.PolicySharedMapMode = option.PolicySharedMapModeShared
	option.Config.EnablePolicySharedMapArena = true

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Logf("Failed to remove memlock rlimit: %v", err)
	}

	// Create ephemeral Arena map (No Pinning)
	m := ebpf.NewMap(logging.DefaultSlogLogger, &ciliumebpf.MapSpec{
		Name:       "cilium_test_wd",       // Unique name per test
		Type:       ciliumebpf.MapType(33), // BPF_MAP_TYPE_ARENA
		KeySize:    0,
		ValueSize:  0,
		MaxEntries: 512,
		Flags:      1 << 10, // BPF_F_MMAPABLE
	})
	if err := m.OpenOrCreate(); err != nil {
		t.Fatalf("Failed to create ephemeral arena map: %v", err)
	}
	arenaMap = m

	t.Cleanup(func() {
		option.Config.PolicySharedMapEnabled = false
		option.Config.EnablePolicySharedMapArena = false
		if arenaMap != nil {
			arenaMap.Close()
			arenaMap = nil
		}
	})
	oldUpdate := updateSharedPolicyKey
	oldDelete := deleteSharedPolicyKey
	oldUpdateOverlay := updateOverlayPolicyEntry
	defer func() {
		updateSharedPolicyKey = oldUpdate
		deleteSharedPolicyKey = oldDelete
		updateOverlayPolicyEntry = oldUpdateOverlay
	}()

	updateSharedPolicyKey = func(key SharedPolicyKey, entry PolicyEntry) error { return nil }
	deleteSharedPolicyKey = func(key SharedPolicyKey) error { return nil }
	updateOverlayPolicyEntry = func(epID uint16, overlay OverlayEntryBPF) error { return nil }

	// Reset singleton
	sharedMgrOnce = sync.Once{}
	sharedMgr = nil
	sharedMgr = getSharedManager()

	// 2. Simulate "Hot Tuple" Policy
	// A wide CIDR rule (e.g. 10.0.0.0/8) might allow traffic to many identities.
	// We simulate this by having the PolicyMap contain multiple allowed identities.
	// For "Ten endpoints share one", all 10 endpoints must have the SAME allowed identities.

	allowedIdentities := []identity.NumericIdentity{10, 11, 12, 13, 100, 200, 300} // simulating result of Wide CIDR

	policyMap := make(map[types.Key]types.MapStateEntry)
	for _, id := range allowedIdentities {
		key := types.KeyForDirection(trafficdirection.Ingress).
			WithProto(u8proto.TCP).
			WithPort(80).
			WithIdentity(id)
		entry := types.MapStateEntry{
			ProxyPort: 0,
		}
		policyMap[key] = entry
	}

	// 3. Sync 10 Endpoints with identical policy
	const numEndpoints = 10
	var ruleSetIDs []uint32

	for i := 0; i < numEndpoints; i++ {
		epID := uint16(1000 + i)
		_, err := SyncEndpointOverlay(epID, mapToIter(policyMap))
		assert.NoError(t, err)

		gid, ok := sharedMgr.ruleSetIDs[epID]
		assert.True(t, ok)
		ruleSetIDs = append(ruleSetIDs, gid)
	}

	// 4. Verification
	firstID := ruleSetIDs[0]
	assert.NotZero(t, firstID)

	// A. All endpoints must share the exact same ID
	for i, gid := range ruleSetIDs {
		assert.Equal(t, firstID, gid, fmt.Sprintf("Endpoint %d should share RuleSetID %d", 1000+i, firstID))
	}

	// B. RefCount must represent all 10 endpoints
	sharedMgr.allocator.mu.Lock()
	count, exists := sharedMgr.allocator.refcount[firstID]
	sharedMgr.allocator.mu.Unlock()

	assert.True(t, exists)
	assert.Equal(t, numEndpoints, count, "RefCount should equal number of endpoints using the rule set")

	// C. Verify Memory Savings
	// Legacy would store: 10 endpoints * 7 rules = 70 entries.
	// Shared stores:
	//   - Overlay: 10 endpoints * 1 pointer = 10 entries.
	//   - Shared:  1 RuleSet * 7 rules = 7 entries.
	//   - Total: 17 entries.
	// Savings: (70 - 17) / 70 = ~75% savings for this small case.
	// As N approaches infinity, savings approaches (Rules-1)/Rules => ~85% -> 99%.

	t.Logf("Verified Wide CIDR Dedup: %d Endpoints mapping to RuleSetID %d with RefCount %d", numEndpoints, firstID, count)
}
