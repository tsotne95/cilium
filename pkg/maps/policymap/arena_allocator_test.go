package policymap

import (
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/cilium/cilium/pkg/ebpf"
	upstream "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
)

func TestArenaAllocator_BlockAlloc(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	const MapTypeArena upstream.MapType = 33
	mapSpec := &upstream.MapSpec{
		Name:       "cilium_test_aa",
		Type:       MapTypeArena,
		KeySize:    0,
		ValueSize:  0,
		MaxEntries: 10,
		Flags:      1 << 10, // BPF_F_MMAPABLE
	}

	// We use cilium/pkg/ebpf wrapper to get the Map
	m := ebpf.NewMap(slog.New(slog.NewTextHandler(io.Discard, nil)), mapSpec)
	// But allow failure if kernel too old or no permissions
	if err := m.OpenOrCreate(); err != nil {
		t.Skipf("Skipping Arena test: %v", err)
	}
	defer m.Unpin()
	defer m.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	alloc, err := NewArenaAllocator(logger, m)
	if err != nil {
		t.Fatalf("failed to create allocator: %v", err)
	}
	defer alloc.Close()

	// 1. Alloc 64 bytes
	off1, size1, err := alloc.AllocateBlock(10)
	if err != nil {
		t.Fatal(err)
	}
	if size1 != 64 {
		t.Errorf("expected size 64, got %d", size1)
	}

	// 2. Alloc 100 bytes -> 128
	off2, size2, err := alloc.AllocateBlock(100)
	if err != nil {
		t.Fatal(err)
	}
	if size2 != 128 {
		t.Errorf("expected size 128, got %d", size2)
	}
	t.Logf("Allocated off2: %d", off2)

	// 3. Free off1 (64)
	if err := alloc.FreeBlock(off1, 64); err != nil {
		t.Fatal(err)
	}

	// 4. Alloc 50 bytes -> should reuse off1
	off3, size3, err := alloc.AllocateBlock(50)
	if err != nil {
		t.Fatal(err)
	}
	if size3 != 64 {
		t.Errorf("got %d", size3)
	}
	if off3 != off1 {
		t.Errorf("expected reuse of offset %d, got %d", off1, off3)
	}

	// 5. Alloc 200 bytes -> 256
	off4, size4, err := alloc.AllocateBlock(200)
	if err != nil {
		t.Fatal(err)
	}
	if size4 != 256 {
		t.Errorf("got %d", size4)
	}
	t.Logf("Allocated off4: %d", off4)
}

func TestArenaAllocator_Persistence_Block(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skip(err)
	}

	const MapTypeArena upstream.MapType = 33
	mapSpec := &upstream.MapSpec{
		Name:       "cilium_test_ap",
		Type:       MapTypeArena,
		KeySize:    0,
		ValueSize:  0,
		MaxEntries: 512, // 2MB
		Flags:      1 << 10,
	}
	// Use Stdout logger to see "Attempting to mmap" logs
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	m := ebpf.NewMap(logger, mapSpec)
	if err := m.OpenOrCreate(); err != nil {
		t.Skipf("Skipping: %v", err)
	}
	defer m.Close()

	alloc1, err := NewArenaAllocator(logger, m)
	require.NoError(t, err)

	// Alloc 128 bytes
	off1, _, err := alloc1.AllocateBlock(100)
	require.NoError(t, err)
	t.Logf("Alloc1 off: %d", off1)

	alloc1.Close()

	// Reopen
	alloc2, err := NewArenaAllocator(logger, m)
	if err != nil {
		t.Fatalf("Failed to reopen arena: %v", err)
	}
	defer alloc2.Close()

	// Check FreeOffset > off1
	off2, _, err := alloc2.AllocateBlock(100)
	require.NoError(t, err)
	require.Greater(t, off2, off1, "New allocation should be after persisted one")
}
