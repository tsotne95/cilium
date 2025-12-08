// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

// resetSharedManagerForTest clears the singleton so each test starts from a
// clean slate.
func resetSharedManagerForTest() {
	sharedMgrOnce = sync.Once{}
	sharedMgr = nil
}

func TestSyncEndpointOverlayStoresOverrides(t *testing.T) {
	t.Cleanup(func() {
		option.Config.PolicySharedMapEnabled = false
		resetSharedManagerForTest()
	})

	option.Config.PolicySharedMapEnabled = true
	option.Config.PolicySharedMapMode = option.PolicySharedMapModeShared
	option.Config.PolicySharedMapMaxSharedRefs = 4
	option.Config.PolicySharedMapMaxPrivateOverrides = 4

	seq := func(yield func(policyTypes.Key, policyTypes.MapStateEntry) bool) {
		key := policyTypes.KeyForDirection(trafficdirection.Ingress).WithPortProto(u8proto.TCP, 80)
		key.Identity = 128
		yield(key, policyTypes.DenyEntry())
		return
	}

	require.NoError(t, SyncEndpointOverlay(10, seq))

	overlay, ok := OverlaySnapshot(10)
	require.True(t, ok)
	require.Equal(t, uint8(1), overlay.SharedRefCount)
	require.Equal(t, uint8(1), overlay.PrivateCount)

	mgr := getSharedManager()
	meta, exists := mgr.store.Metadata(overlay.SharedRefs[0])
	require.True(t, exists)
	require.Equal(t, 1, meta.RefCount)

	RemoveEndpointOverlay(10)
	_, still := OverlaySnapshot(10)
	require.False(t, still)
}
