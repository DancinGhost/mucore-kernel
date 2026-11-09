#pragma once
// ============================================================================
// μCore x86_64 Arch — Minimal Standalone Limine Boot Protocol Definitions
// ============================================================================
// Zero external header dependencies. Places Limine request tags in `.limine_requests`
// so a Limine-compliant bootloader enters `_start` directly in 64-bit Long Mode
// at higher-half `0xffffffff80000000` with HHDM & memory map populated.
// ============================================================================

#include "mucore/types.hpp"

namespace mucore::arch::x86_64::limine {

inline constexpr u64 COMMON_MAGIC_0 = 0xc7b1dd30df4c8b88ULL;
inline constexpr u64 COMMON_MAGIC_1 = 0x0a82e883a194f07bULL;

struct HhdmResponse {
    u64 revision;
    u64 offset; // Higher-Half Direct Map virtual base offset
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

inline constexpr u64 MEMMAP_USABLE = 0ULL;

} // namespace mucore::arch::x86_64::limine
