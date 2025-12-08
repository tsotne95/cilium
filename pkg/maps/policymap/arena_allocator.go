package policymap

import (
	"fmt"
	"log/slog"
	"math/bits"
	"os"
	"unsafe"

	"github.com/cilium/cilium/pkg/metrics"
	"golang.org/x/sys/unix"
)

// ArenaHeader resides at Offset 0 of the Arena memory.
// It persists the allocator state across agent restarts.
type ArenaHeader struct {
	Magic      uint64 // Magic number to check validity (0xDEADBEEFCAFEB222)
	FreeOffset uint64 // Pointer to the next free byte for bump allocation
	// FreeListHeads[i] points to the head of the free list for size class 2^i.
	// Index 0: 1 byte (unused, min alloc is 64B)
	// ...
	// Index 6: 64 bytes (min alloc)
	// ...
	// Index 31: 2GB
	FreeListHeads [32]uint64
}

const (
	ArenaMagic   = 0xDEADBEEFCAFEB222 // V2 Magic
	HeaderSize   = uint64(unsafe.Sizeof(ArenaHeader{}))
	MinBlockSize = 64
)

// ArenaMapBackend defines the interface required by ArenaAllocator.
type ArenaMapBackend interface {
	FD() int
	MaxEntries() uint32
}

// ArenaAllocator manages a BPF Arena map for storing variable-sized policy rule sets.
// It uses a Segregated Fit (Power-of-Two) allocator.
type ArenaAllocator struct {
	mapFD     int
	data      []byte
	size      int
	maxOffset uint64
	logger    *slog.Logger
	header    *ArenaHeader // Pointer to the memory-mapped header
}

// FreeBlockNode is the structure of a free block in the free list.
// It must fit within MinBlockSize.
type FreeBlockNode struct {
	NextOffset uint64
}

// NewArenaAllocator creates a new ArenaAllocator backed by the given map (or mock).
func NewArenaAllocator(logger *slog.Logger, m ArenaMapBackend) (*ArenaAllocator, error) {
	if m == nil {
		return nil, fmt.Errorf("arena map is nil")
	}

	fd := m.FD()
	pageSize := os.Getpagesize()
	maxPages := int(m.MaxEntries())
	size := maxPages * pageSize

	logger.Info("Attempting to mmap Arena V2",
		"fd", fd,
		"maxEntries", maxPages,
		"pageSize", pageSize,
		"totalSize", size,
	)

	// Mmap the arena memory
	b, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap arena: %w", err)
	}

	alloc := &ArenaAllocator{
		mapFD:     fd,
		data:      b,
		size:      size,
		maxOffset: uint64(size),
		logger:    logger,
		header:    (*ArenaHeader)(unsafe.Pointer(&b[0])),
	}

	// Check for Persistence / Initialization
	if alloc.header.Magic == ArenaMagic {
		logger.Info("Recovered Arena Allocator V2 state",
			"freeOffset", alloc.header.FreeOffset)
		// We trust the persisted state.
	} else {
		logger.Info("Initializing new Arena Allocator V2 header (Resetting)")
		// Initialize Header
		alloc.Reset()
	}

	alloc.updateMetrics()
	return alloc, nil
}

// AllocateBlock allocates a block of memory of at least the requested size.
// It rounds up to the next power of two (min 64 bytes).
// Returns offset and the actual allocated size.
func (a *ArenaAllocator) AllocateBlock(size int) (uint64, uint64, error) {
	if size <= 0 {
		return 0, 0, fmt.Errorf("invalid size: %d", size)
	}

	// 1. Calculate Power of 2 Size
	allocSize := uint64(size)
	if allocSize < MinBlockSize {
		allocSize = MinBlockSize
	}
	// Round up to next power of 2
	// If current is power of 2, it remains same.
	if bits.OnesCount64(allocSize) > 1 {
		lz := bits.LeadingZeros64(allocSize)
		allocSize = 1 << (64 - lz)
	}

	bucket := bits.TrailingZeros64(allocSize)
	if bucket >= len(a.header.FreeListHeads) {
		return 0, 0, fmt.Errorf("requested size too large: %d", size)
	}

	var offset uint64

	// 2. Try Free List
	if head := a.header.FreeListHeads[bucket]; head != 0 {
		offset = head

		// Unlink
		ptr := unsafe.Pointer(&a.data[offset])
		node := (*FreeBlockNode)(ptr)
		a.header.FreeListHeads[bucket] = node.NextOffset
		a.logger.Debug("Allocated block from Free List", "size", allocSize, "offset", offset)
	} else {
		// 3. Bump Pointer
		// Align FreeOffset to allocSize (Powers of 2 usually imply alignment, ensuring proper alignment helps cache)
		// Start at FreeOffset, aligned to allocSize
		start := (a.header.FreeOffset + allocSize - 1) &^ (allocSize - 1)

		if start < HeaderSize {
			start = (HeaderSize + allocSize - 1) &^ (allocSize - 1)
		}

		if start+allocSize > a.maxOffset {
			return 0, 0, fmt.Errorf("arena exhausted")
		}

		offset = start
		a.header.FreeOffset = start + allocSize
		a.logger.Debug("Allocated block from Bump Pointer", "size", allocSize, "offset", offset)
	}

	a.updateMetrics()
	return offset, allocSize, nil
}

// FreeBlock releases a block back to the Free List.
// The size MUST be the same (or same power-of-two class) as allocated.
func (a *ArenaAllocator) FreeBlock(offset uint64, size int) error {
	if offset == 0 || offset >= a.header.FreeOffset {
		return fmt.Errorf("invalid free offset: %d", offset)
	}

	allocSize := uint64(size)
	if allocSize < MinBlockSize {
		allocSize = MinBlockSize
	}
	if bits.OnesCount64(allocSize) > 1 {
		lz := bits.LeadingZeros64(allocSize)
		allocSize = 1 << (64 - lz)
	}

	bucket := bits.TrailingZeros64(allocSize)
	if bucket >= len(a.header.FreeListHeads) {
		return fmt.Errorf("invalid size class: %d", size)
	}

	// Push to Free List
	ptr := unsafe.Pointer(&a.data[offset])
	node := (*FreeBlockNode)(ptr)

	node.NextOffset = a.header.FreeListHeads[bucket]
	a.header.FreeListHeads[bucket] = offset

	a.logger.Debug("Freed block", "size", allocSize, "offset", offset)
	return nil
}

func (a *ArenaAllocator) updateMetrics() {
	pageSize := os.Getpagesize()
	usedPages := (int(a.header.FreeOffset) + pageSize - 1) / pageSize
	metrics.PolicySharedMapArenaPages.WithLabelValues("used").Set(float64(usedPages))
}

// Reset clears the allocator. Use cautiously!
func (a *ArenaAllocator) Reset() {
	a.header.Magic = ArenaMagic
	// Align to 64 bytes initially
	a.header.FreeOffset = (HeaderSize + 63) &^ 63
	for i := range a.header.FreeListHeads {
		a.header.FreeListHeads[i] = 0
	}
}

func (a *ArenaAllocator) Close() error {
	return unix.Munmap(a.data)
}
