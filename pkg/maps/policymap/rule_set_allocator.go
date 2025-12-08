// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/cilium/pkg/lock"
)

// ruleSetKey represents the hash of a set of rules.
type ruleSetKey string

// RuleSetAllocator manages the assignment of unique GroupIDs to sets of policy rules.
// In Phase 3: It acts as a dedup cache, returning HeadNodeIDs from ArenaAllocator.
type RuleSetAllocator struct {
	mu         lock.Mutex
	rulesets   map[ruleSetKey]uint32
	idToHash   map[uint32]ruleSetKey
	refcount   map[uint32]int
	arenaAlloc *ArenaAllocator // Phase 3 (Arena)
}

// NewRuleSetAllocator creates a new allocator.
// maxGroups: Hash Map Size constraint (not strictly used for limit in Phase 3 except for map/cache size).
func NewRuleSetAllocator(maxGroups int, arena *ArenaAllocator) *RuleSetAllocator {
	return &RuleSetAllocator{
		rulesets:   make(map[ruleSetKey]uint32),
		idToHash:   make(map[uint32]ruleSetKey),
		refcount:   make(map[uint32]int),
		arenaAlloc: arena,
	}
}

// GetOrAllocate returns the ID for the given rules.
func (a *RuleSetAllocator) GetOrAllocate(rules []SharedPolicyKey) (uint32, error) {
	// 1. Compute Hash (Universal)
	ruleSetHash := ComputeRuleSetHash(rules)

	a.mu.Lock()
	defer a.mu.Unlock()

	// 2. Check Cache
	if id, exists := a.rulesets[ruleSetHash]; exists {
		a.refcount[id]++
		return id, nil
	}

	// 3. Allocate New
	if a.arenaAlloc == nil {
		return 0, fmt.Errorf("arena allocator not initialized (legacy/phase2 support removed)")
	}

	// --- Phase 3: Arena V2 (Flat Array) ---

	// Max rules limited by uint16 (65535)
	if len(rules) > 65535 {
		return 0, fmt.Errorf("too many rules in set: %d (max 65535)", len(rules))
	}

	// Calculate size: Header (4B) + Rules
	// ruleSize is 8 bytes.
	const headerSize = 4
	const ruleSize = 8
	requiredSize := headerSize + len(rules)*ruleSize

	offset, allocSize, err := a.arenaAlloc.AllocateBlock(requiredSize)
	if err != nil {
		return 0, fmt.Errorf("arena block alloc failed: %w", err)
	}

	// Safety check bounds
	if offset+allocSize > uint64(len(a.arenaAlloc.data)) {
		// Should not happen if allocator is correct
		return 0, fmt.Errorf("allocated block out of bounds")
	}

	// Write Data
	ptr := a.arenaAlloc.data[offset : offset+allocSize]

	// Header: Count (u16), Capacity (u16)
	// Capacity = (allocSize - 4) / 8
	capacity := (allocSize - headerSize) / ruleSize
	if capacity > 65535 {
		capacity = 65535
	}

	binary.LittleEndian.PutUint16(ptr[0:], uint16(len(rules)))
	binary.LittleEndian.PutUint16(ptr[2:], uint16(capacity))

	// Write Rules (Sorted)
	// We sort 'rules' in ComputeRuleSetHash, but that logic used a copy.
	// We should sort the rules here nicely to ensure deterministic binary search in BPF?
	// BPF Binary Search REQUIRES sorted array.
	// We must sort 'rules' by relevant fields (Identity, Direction, etc.)
	// ComputeRuleSetHash already sorted a COPY.
	// We should duplicate that sort logic or just sort 'rules' here (assuming caller doesn't mind order change, or copy).
	// Let's copy and sort to be safe.
	sortedRules := make([]SharedPolicyKey, len(rules))
	copy(sortedRules, rules)
	sort.Slice(sortedRules, func(i, j int) bool {
		if sortedRules[i].Identity != sortedRules[j].Identity {
			return sortedRules[i].Identity < sortedRules[j].Identity
		}
		if sortedRules[i].Direction != sortedRules[j].Direction {
			return sortedRules[i].Direction < sortedRules[j].Direction
		}
		if sortedRules[i].Nexthdr != sortedRules[j].Nexthdr {
			return sortedRules[i].Nexthdr < sortedRules[j].Nexthdr
		}
		return sortedRules[i].DestPortNetwork < sortedRules[j].DestPortNetwork
	})

	for i, r := range sortedRules {
		// PolicyRule (8 bytes)
		// Identity (4), Direction (1), Nexthdr (1), DestPortNetwork (2)
		base := headerSize + i*ruleSize
		binary.LittleEndian.PutUint32(ptr[base:], uint32(r.Identity))
		ptr[base+4] = uint8(r.Direction)
		ptr[base+5] = uint8(r.Nexthdr)
		binary.LittleEndian.PutUint16(ptr[base+6:], r.DestPortNetwork)
	}

	id := uint32(offset)

	// 4. Update Cache
	a.rulesets[ruleSetHash] = id
	a.idToHash[id] = ruleSetHash
	a.refcount[id] = 1

	return id, nil
}

// ReleaseByID releases a reference to the rule set.
func (a *RuleSetAllocator) ReleaseByID(id uint32) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.refcount[id] == 0 {
		return false // Double free?
	}

	a.refcount[id]--
	if a.refcount[id] == 0 {
		// Garbage Collect
		if hash, exists := a.idToHash[id]; exists {
			delete(a.rulesets, hash)
			delete(a.idToHash, id)
		}
		delete(a.refcount, id)

		// Free the block in Arena
		// We need to know the size.
		// Read header from Arena.
		offset := uint64(id)
		if offset+4 <= uint64(len(a.arenaAlloc.data)) {
			// Read Count
			count := binary.LittleEndian.Uint16(a.arenaAlloc.data[offset:])

			// Re-calculate original requested size
			const headerSize = 4
			const ruleSize = 8
			requiredSize := headerSize + int(count)*ruleSize

			// FreeBlock will recalculate the power-of-two bucket
			if err := a.arenaAlloc.FreeBlock(offset, requiredSize); err != nil {
				// Ignore error
			}
		}

		return true
	}
	return false
}

// ComputeRuleSetHash calculates a deterministic hash for a set of rules.
func ComputeRuleSetHash(keys []SharedPolicyKey) ruleSetKey {
	var sb strings.Builder

	// Create a copy to sort
	sorted := make([]SharedPolicyKey, len(keys))
	copy(sorted, keys)

	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Identity != sorted[j].Identity {
			return sorted[i].Identity < sorted[j].Identity
		}
		if sorted[i].Direction != sorted[j].Direction {
			return sorted[i].Direction < sorted[j].Direction
		}
		if sorted[i].Nexthdr != sorted[j].Nexthdr {
			return sorted[i].Nexthdr < sorted[j].Nexthdr
		}
		if sorted[i].DestPortNetwork != sorted[j].DestPortNetwork {
			return sorted[i].DestPortNetwork < sorted[j].DestPortNetwork
		}
		return false
	})

	for _, k := range sorted {
		fmt.Fprintf(&sb, "%d:%d:%d:%d|", k.Identity, k.Direction, k.Nexthdr, k.DestPortNetwork)
	}

	hash := sha256.Sum256([]byte(sb.String()))
	return ruleSetKey(hex.EncodeToString(hash[:]))
}
