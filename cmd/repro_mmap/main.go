package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: inspector <pinned_path>")
		os.Exit(1)
	}
	pinnedPath := os.Args[1]

	// 1. Load Pinned Map
	m, err := ebpf.LoadPinnedMap(pinnedPath, nil)
	if err != nil {
		log.Fatalf("Failed to load pinned map: %v", err)
	}
	defer m.Close()

	info, err := m.Info()
	if err != nil {
		log.Fatalf("Failed to get map info: %v", err)
	}
	fmt.Printf("Map Loaded: %s Type: %s MaxEntries: %d Flags: %d\n",
		info.Name, info.Type, info.MaxEntries, info.Flags)

	// 2. Mmap
	// Arena map size = MaxEntries * PageSize (usually 4096)
	pageSize := os.Getpagesize()
	size := int(info.MaxEntries) * pageSize
	fmt.Printf("Mmapping %d bytes...\n", size)

	data, err := unix.Mmap(m.FD(), 0, size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		log.Fatalf("Mmap failed: %v", err)
	}
	defer unix.Munmap(data)

	// 3. Inspect Content
	fmt.Println("Successfully mmapped. Inspecting first 10 possible nodes (16 bytes each)...")

	nodeSize := 16
	for i := 0; i < 10; i++ {
		offset := i * nodeSize
		if offset+nodeSize > len(data) {
			break
		}

		// Read 16 bytes
		chunk := data[offset : offset+nodeSize]

		// Manual parse to avoid unsafe pointer casting issues in simple code
		// Little Endian assumptions
		identity := binary.LittleEndian.Uint32(chunk[0:4])
		direction := chunk[4]
		nexthdr := chunk[5]
		destPort := binary.LittleEndian.Uint16(chunk[6:8])
		nextOff := binary.LittleEndian.Uint64(chunk[8:16])

		if identity == 0 && direction == 0 && nexthdr == 0 && destPort == 0 && nextOff == 0 {
			if i == 0 {
				fmt.Printf("Node %d (Offset %d): [EMPTY]\n", i, offset)
			}
			continue
		}

		fmt.Printf("Node %d (Offset %d): Identity=%d Dir=%d Proto=%d Port=%d Next=%d\n",
			i, offset, identity, direction, nexthdr, destPort, nextOff)
	}

	// Scan for ANY non-zero byte if first few are empty
	fmt.Println("Scanning for any non-zero content...")
	nonZeroCount := 0
	for i := 0; i < len(data); i++ {
		if data[i] != 0 {
			nonZeroCount++
			if nonZeroCount <= 5 {
				fmt.Printf("Non-zero byte at offset %d: 0x%02x\n", i, data[i])
			}
		}
	}
	fmt.Printf("Total non-zero bytes: %d\n", nonZeroCount)
}
