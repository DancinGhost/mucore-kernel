#pragma once
// ============================================================================
// μCore (mucore-kernel) — Explicit Freestanding Primitive & Domain Types
// ============================================================================
// Design Mandate: "No Hidden Mechanisms"
//   - Zero reliance on hosted C++ standard library runtime.
//   - Register-sized strong wrappers prevent accidental parameter transposition
//     (e.g., passing a ThreadId where a DomainId is expected is a type error).
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
inline constexpr usize CACHE_LINE_BYTES = 64ULL;

// Empty value type for fallible void operations: Result<Unit, Error>
struct Unit {
    constexpr bool operator==(Unit const&) const noexcept = default;
};

// ----------------------------------------------------------------------------
// Strongly-Typed Kernel Identifiers (Register-Sized POD Wrappers)
// ----------------------------------------------------------------------------
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
    AdmissionRejected,     // Real-Time CBS/EDF utilization bound exceeded
    VerificationFailed,    // Ring-0 Kineticlet static proof rejected program
    StepBudgetExceeded,    // Ring-0 Kineticlet fuel exhausted
    RingFull,
    RingEmpty,
    OutOfBounds,
    OutOfMemory,
    NotFound,
    InvalidState,
};

[[nodiscard]] constexpr const char* error_name(Error err) noexcept {
    switch (err) {
        case Error::None:               return "None";
        case Error::InvalidArgument:    return "InvalidArgument";
        case Error::InvalidCapability:  return "InvalidCapability";
        case Error::RevokedCapability:  return "RevokedCapability";
        case Error::InsufficientRights: return "InsufficientRights";
        case Error::DomainMismatch:     return "DomainMismatch";
        case Error::TableFull:          return "TableFull";
        case Error::QuotaExceeded:      return "QuotaExceeded";
        case Error::AdmissionRejected:  return "AdmissionRejected";
        case Error::VerificationFailed: return "VerificationFailed";
        case Error::StepBudgetExceeded: return "StepBudgetExceeded";
        case Error::RingFull:           return "RingFull";
        case Error::RingEmpty:          return "RingEmpty";
        case Error::OutOfBounds:        return "OutOfBounds";
        case Error::OutOfMemory:        return "OutOfMemory";
        case Error::NotFound:           return "NotFound";
        case Error::InvalidState:       return "InvalidState";
    }
    return "UnknownError";
}

} // namespace mucore
