#pragma once
// ============================================================================
// μCore x86_64 Arch — Standalone Limine Boot Protocol Definitions (with SMP!)
// ============================================================================

#include "mucore/types.hpp"

namespace mucore::arch::x86_64::limine {

inline constexpr u64 COMMON_MAGIC_0   = 0xc7b1dd30df4c8b88ULL;
inline constexpr u64 COMMON_MAGIC_1   = 0x0a82e883a194f07bULL;
inline constexpr u64 SMP_FLAG_X2APIC  = 1ULL << 0;

struct HhdmResponse {
    u64 revision;
    u64 offset;
};

struct HhdmRequest {
    u64           id[4];
    u64           revision;
    HhdmResponse* response;
};

struct MemmapEntry {
    u64 base;
    u64 length;
    u64 type;
};

struct MemmapResponse {
    u64           revision;
    u64           entry_count;
    MemmapEntry** entries;
};

struct MemmapRequest {
    u64             id[4];
    u64             revision;
    MemmapResponse* response;
};

struct SmpInfo;
using GotoAddressFn = void (*)(SmpInfo*);

struct SmpInfo {
    u32           processor_id;
    u32           lapic_id;
    u64           reserved;
    GotoAddressFn goto_address;   // Atomically store AP entry function here to wake core!
    u64           extra_argument; // Kernel-assigned logical `CpuId`
};

struct SmpResponse {
    u64       revision;
    u32       flags;
    u32       bsp_lapic_id;
    u64       cpu_count;
    SmpInfo** cpus;
};

struct SmpRequest {
    u64          id[4];
    u64          revision;
    SmpResponse* response;
    u64          flags;
};

inline constexpr u64 MEMMAP_USABLE = 0ULL;

} // namespace mucore::arch::x86_64::limine
