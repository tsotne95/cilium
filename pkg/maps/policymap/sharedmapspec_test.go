// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/option"
)

func resetSharedMapsForTest() {
	sharedPolicyMapOnce = sync.Once{}
	sharedPolicyMap = nil
	sharedPolicyMapErr = nil
	overlayPolicyMapOnce = sync.Once{}
	overlayPolicyMap = nil
	overlayPolicyMapErr = nil
}

func TestInitSharedPolicyMapsDisabled(t *testing.T) {
	t.Cleanup(func() {
		option.Config.PolicySharedMapEnabled = false
		option.Config.PolicySharedMapMode = option.PolicySharedMapModeLegacy
		resetSharedMapsForTest()
	})

	option.Config.PolicySharedMapEnabled = false
	option.Config.PolicySharedMapMode = option.PolicySharedMapModeLegacy

	err := InitSharedPolicyMaps(0)
	require.NoError(t, err)
	require.Nil(t, sharedPolicyMap)
	require.Nil(t, overlayPolicyMap)
}
