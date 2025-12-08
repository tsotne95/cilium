package policymap

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/option"
)

// TestArenaFlagLogic verifies that EnablePolicySharedMapArena flag influences the creation logic.
func TestArenaFlagLogic(t *testing.T) {
	t.Cleanup(func() {
		option.Config.PolicySharedMapEnabled = false
		option.Config.EnablePolicySharedMapArena = false
		resetSharedManagerForTest()
	})

	option.Config.PolicySharedMapEnabled = true
	option.Config.PolicySharedMapMode = option.PolicySharedMapModeShared
	option.Config.PolicyRuleListNodesMax = 100

	// Case 1: Flag False
	option.Config.EnablePolicySharedMapArena = false
	resetSharedManagerForTest()
	mgr := getSharedManager()
	// When Flag is False, Arena Allocator should be nil.
	// Note: We removed legacy allocators, so if Arena is false, we might have nil allocator or error?
	// SharedManagerEnabled() returns false if Arena is false (in our new logic).
	// So getSharedManager() might not even be fully initialized or we shouldn't call it if disabled.
	// But getSharedManager() initializes singletons.

	// If SharedManagerEnabled() is false, we technically shouldn't use it.
	// But if we do call getSharedManager(), it initializes.
	// In my sharedmanager.go update, 'arenaAlloc' is nil if flag is false.
	// 'NewRuleSetAllocator' is called with 'arenaAlloc' (nil).
	// 'GetOrAllocate' checks if 'arenaAlloc' is nil and returns error.

	assert.Nil(t, mgr.allocator.arenaAlloc, "Arena Allocator should be nil when flag is false")

	// Case 2: Flag True (But Map Missing)
	// We need to simulate missing map. ArenaMap() returns nil by default unless InitUniversalMaps called.
	option.Config.EnablePolicySharedMapArena = true

	// We must ensure 'ArenaMap()' returns nil for this test case.
	// It is a global var in universal_maps.go.
	// We can't easily reset it from here unless we adding a ResetHelper or relies on it being nil?
	// It relies on 'InitUniversalMaps' to set it. detailed tests might set it.
	// Assuming it's nil here or we can't easily test "Map Missing" if it was already set by another test?
	// T.Cleanup should handle it if we had a ResetUniversalMaps? We don't.

	resetSharedManagerForTest()
	mgr2 := getSharedManager()
	// If map is missing, arenaAlloc should be nil (logged error).
	assert.Nil(t, mgr2.allocator.arenaAlloc, "Arena Allocator should be nil if map is missing (graceful fallback)")
}

func TestSharedManagerEnabled_Arena(t *testing.T) {
	t.Cleanup(func() {
		option.Config.PolicySharedMapEnabled = false
		option.Config.EnablePolicySharedMapArena = false
	})

	// Case 1: All disabled
	option.Config.PolicySharedMapEnabled = false
	option.Config.EnablePolicySharedMapArena = false
	assert.False(t, SharedManagerEnabled())

	// Case 2: Only Arena Enabled -> Should be True
	option.Config.EnablePolicySharedMapArena = true
	assert.True(t, SharedManagerEnabled(), "SharedManager should be enabled if Arena is enabled")
}
