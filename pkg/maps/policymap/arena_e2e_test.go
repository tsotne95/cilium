package policymap

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestArenaE2E compiles and loads a BPF program using BPF_MAP_TYPE_ARENA.
// It verifies that the kernel accepts the map and program.
func TestArenaE2E(t *testing.T) {
	// 1. Compile BPF
	// Assume we are in pkg/maps/policymap
	repoRoot := "../../../"
	bpfSrc := filepath.Join(repoRoot, "bpf/arena_e2e.c")
	bpfObj := filepath.Join(repoRoot, "bpf/arena_e2e.o")

	// Clean up previous object
	os.Remove(bpfObj)
	defer os.Remove(bpfObj)

	clangCmd := exec.Command("clang",
		"-O2", "-target", "bpf",
		"-c", bpfSrc,
		"-o", bpfObj,
		"-I"+filepath.Join(repoRoot, "bpf"),
		"-I"+filepath.Join(repoRoot, "bpf/include"),
		"-I"+filepath.Join(repoRoot, "bpf/lib"),
	)

	if out, err := clangCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to compile BPF: %v\nOutput:\n%s", err, out)
	}
	t.Log("Successfully compiled BPF object")

	// 2. Check Root
	if os.Getuid() != 0 {
		t.Skip("Skipping Arena E2E test: Requires root privileges")
	}

	// 3. Remove Memlock
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("Failed to remove memlock: %v", err)
	}

	// 4. Load Collection
	spec, err := ebpf.LoadCollectionSpec(bpfObj)
	if err != nil {
		t.Fatalf("Failed to load collection spec: %v", err)
	}

	// 5. Create Map & Program
	// We instantiate the map manually if needed, or let ebpf do it.
	// Since we used SEC(".maps"), spec.Maps should have it.
	// Note: We need to ensure we don't have existing pinned maps conflicts.
	// The C code defines 'cilium_policy_a'.

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("Failed to create BPF collection: %v", err)
	}
	defer coll.Close()

	arenaMap := coll.Maps["cilium_policy_a"]
	if arenaMap == nil {
		t.Fatal("Map 'cilium_policy_a' not found in collection")
	}

	t.Logf("Successfully created Arena Map: %v", arenaMap)

	// 6. Verify Program Load
	prog := coll.Programs["test_arena_xdp"]
	if prog == nil {
		t.Fatal("Program 'test_arena_xdp' not found")
	}
	t.Logf("Successfully loaded XDP Program: %v", prog)

	// 7. Success!
	// If we got here, Kernel 6.16 successfully loaded a program referencing an Arena map.
}
