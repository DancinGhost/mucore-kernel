#pragma once
// ============================================================================
// μCore (mucore-kernel) — Explicit Freestanding Primitive & Domain Types
// ============================================================================
// Design Mandate: "No Hidden Mechanisms"
//   - Zero reliance on hosted C++ standard library runtime.
//   - Register-sized strong wrappers prevent accidental parameter transposition.
//   - All operations are constexpr, deterministic, and O(1).
// ============================================================================

#include <stddef.h>
#include <stdint.h>

namespace mucore {

using u8    = uint8_t;
using u16   = uint16_t;
using u32   = uint32_t;
using u64   = uint64_t;
using i8    = int8_t;
using i16   = int16_t;
using i32   = int32_t;
using i64   = int64_t;
using usize = size_t;
using uptr  = uintptr_t;

inline constexpr usize PAGE_SIZE_4K     = 4096ULL;
inline constexpr usize PAGE_SIZE_2M     = 2ULL * 1024ULL * 1024ULL;
inline constexpr usize CACHE_LINE_BYTES = 64ULL;
inline constexpr usize MAX_SMP_CPUS     = 8ULL;  // Per-CPU static shard array bound (<= 64)

// Empty value type for fallible void operations: Result<Unit, Error>
struct Unit {
    constexpr bool operator==(Unit const&) const noexcept = default;
};

// ----------------------------------------------------------------------------
// Strongly-Typed Kernel Identifiers (Register-Sized POD Wrappers)
// ----------------------------------------------------------------------------
struct CpuId {
    u16 raw{0};
    constexpr bool operator==(CpuId const&) const noexcept = default;
};

struct DomainId {
    u32 raw{0};
    constexpr bool operator==(DomainId const&) const noexcept = default;
    constexpr explicit operator bool() const noexcept { return raw != 0; }
};

struct ThreadId {
    u32 raw{0};
    constexpr bool operator==(ThreadId const&) const noexcept = default;
    constexpr explicit operator bool() const noexcept { return raw != 0; }
};

struct ConduitId {
    u32 raw{0};
    constexpr bool operator==(ConduitId const&) const noexcept = default;
    constexpr explicit operator bool() const noexcept { return raw != 0; }
};

struct PortId {
    u32 raw{0};
    constexpr bool operator==(PortId const&) const noexcept = default;
    constexpr explicit operator bool() const noexcept { return raw != 0; }
};

struct ArenaId {
    u32 raw{0};
    constexpr bool operator==(ArenaId const&) const noexcept = default;
    constexpr explicit operator bool() const noexcept { return raw != 0; }
};

struct KineticId {
    u32 raw{0};
    constexpr bool operator==(KineticId const&) const noexcept = default;
    constexpr explicit operator bool() const noexcept { return raw != 0; }
};

// Hardware Memory Protection Key (x86_64 PKRU / PKS 4-bit key 0..15)
struct PkeyId {
    u8 raw{0};
    constexpr bool operator==(PkeyId const&) const noexcept = default;
};

struct IoPacketId {
    u64 raw{0};
    constexpr bool operator==(IoPacketId const&) const noexcept = default;
    constexpr explicit operator bool() const noexcept { return raw != 0; }
};

struct IrqLine {
    u16 raw{0};
    constexpr bool operator==(IrqLine const&) const noexcept = default;
};

struct PhysAddr {
    u64 raw{0};
    constexpr bool operator==(PhysAddr const&) const noexcept = default;
    constexpr PhysAddr offset(u64 bytes) const noexcept { return PhysAddr{raw + bytes}; }
    constexpr bool is_page_aligned() const noexcept { return (raw & (PAGE_SIZE_4K - 1)) == 0; }
};

struct VirtAddr {
    u64 raw{0};
    constexpr bool operator==(VirtAddr const&) const noexcept = default;
    constexpr VirtAddr offset(u64 bytes) const noexcept { return VirtAddr{raw + bytes}; }
    constexpr bool is_page_aligned() const noexcept { return (raw & (PAGE_SIZE_4K - 1)) == 0; }
};

// Monotonic time in nanoseconds (explicit integer math; zero floating point in Ring 0)
struct TickNs {
    u64 raw{0};
    constexpr bool operator==(TickNs const&) const noexcept = default;
    constexpr bool operator<(TickNs const& o) const noexcept  { return raw < o.raw; }
    constexpr bool operator<=(TickNs const& o) const noexcept { return raw <= o.raw; }
    constexpr bool operator>(TickNs const& o) const noexcept  { return raw > o.raw; }
    constexpr bool operator>=(TickNs const& o) const noexcept { return raw >= o.raw; }
};

// Pure constexpr trailing-zeros bit scan (used for O(1) bitmaps in Port, Memory & SMP)
[[nodiscard]] constexpr u32 ctz64(u64 val) noexcept {
    u32 count = 0;
    while ((val & 1ULL) == 0ULL && count < 64u) {
        val >>= 1;
        ++count;
    }
    return count;
}

// Pure constexpr SWAR 64-bit population count (O(1) branchless ALU!)
[[nodiscard]] constexpr u32 popcount64(u64 x) noexcept {
    x = x - ((x >> 1) & 0x5555'5555'5555'5555ULL);
    x = (x & 0x3333'3333'3333'3333ULL) + ((x >> 2) & 0x3333'3333'3333'3333ULL);
    x = (x + (x >> 4)) & 0x0F0F'0F0F'0F0F'0F0FULL;
    return static_cast<u32>((x * 0x0101'0101'0101'0101ULL) >> 56);
}

// Branchless Spectre-v1 speculative index mask (exact for all 64-bit `idx`, zero branches):
// Produces `idx` when `idx < bound_pow2`, and `0` when `idx >= bound_pow2` using pure ALU shifts.
[[nodiscard]] constexpr u64 nospec_index_pow2(u64 idx, u64 bound_pow2) noexcept {
    u64 const mask = static_cast<u64>(
        static_cast<i64>(~(idx | (bound_pow2 - 1ULL - idx))) >> 63
    );
    return idx & (bound_pow2 - 1ULL) & mask;
}

// ----------------------------------------------------------------------------
// Explicit Kernel Error Taxonomy (Replaces C++ Exceptions Completely)
// ----------------------------------------------------------------------------
enum class Error : u8 {
    None = 0,
    InvalidArgument,
    InvalidCapability,
    RevokedCapability,
    InsufficientRights,
    DomainMismatch,
    TableFull,
    QuotaExceeded,
    AdmissionRejected,       // Real-Time CBS/EDF utilization bound exceeded
    VerificationFailed,      // Ring-0 Kineticlet static proof rejected program
    StepBudgetExceeded,      // Ring-0 Kineticlet fuel exhausted
    RingFull,
    RingEmpty,
    OutOfBounds,
    OutOfMemory,
    NotFound,
    InvalidState,
    ArenaSealed,             // Sender write blocked while GrantArena is sealed (anti-TOCTOU)
    DmaInFlightQuarantined,  // Physical frames quarantined until hardware/IOMMU DMA drains
    NamespaceNotFound,       // Plan-9 per-domain mount table lookup missed
    LoanActive,              // L4 MCS CBS scheduling context already loaned out
    RtReserveProtected,      // Non-RT thread hit per-core emergency RT frame watermark
    WxorXViolation,          // Attempted page-table mapping that is both Writable and Executable
    CrossCoreTargetRequired, // Target thread/domain lives on a remote CPU shard
};

[[nodiscard]] constexpr const char* error_name(Error err) noexcept {
    switch (err) {
        case Error::None:                    return "None";
        case Error::InvalidArgument:         return "InvalidArgument";
        case Error::InvalidCapability:       return "InvalidCapability";
        case Error::RevokedCapability:       return "RevokedCapability";
        case Error::InsufficientRights:      return "InsufficientRights";
        case Error::DomainMismatch:          return "DomainMismatch";
        case Error::TableFull:               return "TableFull";
        case Error::QuotaExceeded:           return "QuotaExceeded";
        case Error::AdmissionRejected:       return "AdmissionRejected";
        case Error::VerificationFailed:      return "VerificationFailed";
        case Error::StepBudgetExceeded:      return "StepBudgetExceeded";
        case Error::RingFull:                return "RingFull";
        case Error::RingEmpty:               return "RingEmpty";
        case Error::OutOfBounds:             return "OutOfBounds";
        case Error::OutOfMemory:             return "OutOfMemory";
        case Error::NotFound:                return "NotFound";
        case Error::InvalidState:            return "InvalidState";
        case Error::ArenaSealed:             return "ArenaSealed";
        case Error::DmaInFlightQuarantined:  return "DmaInFlightQuarantined";
        case Error::NamespaceNotFound:       return "NamespaceNotFound";
        case Error::LoanActive:              return "LoanActive";
        case Error::RtReserveProtected:      return "RtReserveProtected";
        case Error::WxorXViolation:          return "WxorXViolation";
        case Error::CrossCoreTargetRequired: return "CrossCoreTargetRequired";
    }
    return "UnknownError";
}

} // namespace mucore
