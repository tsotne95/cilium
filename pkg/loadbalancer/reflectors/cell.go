// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflectors

import (
	"github.com/cilium/hive/cell"

	xdslb "github.com/cilium/cilium/pkg/loadbalancer/reflectors/xds"
)

var Cell = cell.Module(
	"loadbalancer-reflectors",
	"Reflects external state to load-balancing tables",

	// Reflects Kubernetes Services and Endpoint(Slices) to load-balancing tables
	K8sReflectorCell,

	// Reflects state to load-balancing tables from a local file specified with
	// '--lb-state-file'.
	FileReflectorCell,

	// Reflects load-balancing state from an external xDS control plane.
	xdslb.Cell,
)
