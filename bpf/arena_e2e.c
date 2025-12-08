#include <linux/bpf.h>

// Minimal usage helpers
#ifndef __section
# define __section(NAME) __attribute__((section(NAME), used))
#endif

#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif

#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

#ifndef __array
#define __array(name, val) typeof(val) *name[]
#endif

// Define Arena Type
#ifndef BPF_MAP_TYPE_ARENA
#define BPF_MAP_TYPE_ARENA 33
#endif

#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U << 10)
#endif

// Map Definition
struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 100);
    __uint(key_size, 0);
    __uint(value_size, 0);
} cilium_policy_a __section(".maps");

// Head Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} arena_head_map __section(".maps");

// Struct matching Go
struct rule_node_arena {
    __u32 identity;
    __u8  direction;
    __u8  nexthdr;
    __be16 dport;
    __u64 next_offset;
} __attribute__((packed));

__section("xdp")
int test_arena_xdp(struct __sk_buff *ctx)
{
    // Minimal logic: Just Reference the map to ensure it is loaded.
    // If we can't look it up, preventing optimization away might be tricky without helpers.
    // usage of map in relocation.
    
    // We can't Call helpers without defining them.
    // But we don't need helpers to test LOADING.
    // Just referring to the map symbol might be enough for libbpf to try loading it?
    // Actually, if instructions don't use it, clang might optimize it out.
    // We need strict usage.
    
    // Fake usage:
    // "Load address of map"?
    // In eBPF, ld_map_fd.
    
    // Use an "asm" block to force reference?
    // Or just look up the HEAD map (Array) which is standard.
    // Verifying Arena loading depends on `cilium_arena` being in the ELF .maps section.
    // ebpf-go LoadCollectionSpec will verify it exists in ELF.
    // And LoadCollection will try to Create it.
    // So even if the Program doesn't use it, the Collection Load *will* try to create the map.
    
    return 0; // XDP_ABORTED
}

char __license[] __section("license") = "GPL";
