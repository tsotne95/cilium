package policymap

import (
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	ciliumebpf "github.com/cilium/ebpf"
)

const (
	ArenaMapName = "cilium_policy_a"
)

var (
	arenaMap *ebpf.Map
)

func universalPolicyLogger() *slog.Logger {
	return logging.DefaultSlogLogger.With(logfields.LogSubsys, "policymap-universal")
}

// PolicyRule is the on-the-wire BPF struct for a rule.
type PolicyRule struct {
	Identity        uint32 // NumericIdentity
	Direction       uint8  // TrafficDirection
	Nexthdr         uint8  // U8proto
	DestPortNetwork uint16
}

// RuleNode is the on-the-wire BPF struct for a list node.
type RuleNode struct {
	RuleID     uint32
	NextNodeID uint32
}

// InitUniversalMaps initializes the Phase 3 BPF Maps with the given limits.
func InitUniversalMaps() error {
	if !SharedManagerEnabled() {
		return nil
	}

	// Arena Map (if enabled)
	if option.Config.EnablePolicySharedMapArena {
		universalPolicyLogger().Info("Initializing BPF Arena Policy Map...")
		// Key/Value Size 0 is required for Arena.

		// Use 512 pages (2MB) to ensure huge page alignment support if needed.
		maxPages := 512

		arenaMap = ebpf.NewMap(universalPolicyLogger(), &ebpf.MapSpec{
			Name:       ArenaMapName,
			Type:       ciliumebpf.MapType(33), // BPF_MAP_TYPE_ARENA
			KeySize:    0,
			ValueSize:  0,
			MaxEntries: uint32(maxPages),
			Flags:      1 << 10, // BPF_F_MMAPABLE
			Pinning:    ebpf.PinByName,
		})
		if err := arenaMap.OpenOrCreate(); err != nil {
			return fmt.Errorf("failed to create arena map: %w", err)
		}
	}

	return nil
}

func ArenaMap() *ebpf.Map {
	return arenaMap
}
