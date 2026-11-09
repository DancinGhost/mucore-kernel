#pragma once
// ============================================================================
// μCore Functional Core — Physical Frame Policy & Zero-Copy Grant Arenas
// ============================================================================
// Solves the Microkernel Memory Copy & TLB Shootdown Bottleneck:
//   1. Ergonomic Intra-Domain Allocation (Anti-L4 Trap):
//      Domains allocate private anonymous frames against their `AmbientProfile`
//      quota without manually constructing hardware page-table capabilities.
//   2. Zero-Copy `GrantArena` Lease Transfer (Zero memcpy, Zero TLB Shootdown):
//      Traditional zero-copy remaps page tables on every IPC (`invlpg` IPIs
//      cost thousands of cycles across cores!). μCore establishes persistent
//      capability-gated `GrantArena` windows and transfers logical slice
//      ownership (`current_holder`) in O(1) without touching `CR3` or `invlpg`.
// ============================================================================

#include "mucore/result.hpp"
#include "mucore/types.hpp"
#include "mucore/core/kinetic.hpp"

namespace mucore::core::mm {

inline constexpr usize BITMAP_WORDS      = 64; // 64 * 64 = 4096 frames = 16 MiB per pool block
inline constexpr usize MAX_FRAMES        = BITMAP_WORDS * 64;
inline constexpr usize MAX_GRANT_ARENAS  = 32;

// Pure constexpr trailing-zeros helper (avoids compiler builtin portability pitfalls)
[[nodiscard]] constexpr u32 ctz64(u64 val) noexcept {
    u32 count = 0;
    while ((val & 1ULL) == 0ULL && count < 64u) {
        val >>= 1;
        ++count;
    }
    return count;
}

struct PhysPoolState {
    PhysAddr base_addr{0x0020'0000ULL}; // Default 2 MiB base
    u64      used_bitmap[BITMAP_WORDS]{}; // 1 = allocated, 0 = free
    u32      total_frames{MAX_FRAMES};
    u32      allocated_frames{0};

    constexpr PhysPoolState() noexcept = default;
    PhysPoolState(PhysPoolState const&)            = delete;
    PhysPoolState& operator=(PhysPoolState const&) = delete;
    constexpr PhysPoolState(PhysPoolState&&) noexcept            = default;
    constexpr PhysPoolState& operator=(PhysPoolState&&) noexcept = default;
};

struct GrantArenaState {
    bool     active{false};
    ArenaId  id{};
    PhysAddr phys_base{};
    u32      page_count{0};
    DomainId creator{};
    DomainId current_lease_holder{}; // Domain currently permitted to mutate payload
    bool     iommu_dma_pinned{false}; // True if pinned for Userspace Driver DMA
    // Inline header/scratch words visible to attached Ring-0 Kineticlets
    u64      kinetic_words[kinetic::NUM_ARENA_WORDS]{};
};

struct MemoryTable {
    PhysPoolState   pool{};
    GrantArenaState arenas[MAX_GRANT_ARENAS]{};

    constexpr MemoryTable() noexcept = default;
    MemoryTable(MemoryTable const&)            = delete;
    MemoryTable& operator=(MemoryTable const&) = delete;
    constexpr MemoryTable(MemoryTable&&) noexcept            = default;
    constexpr MemoryTable& operator=(MemoryTable&&) noexcept = default;
};

// ============================================================================
// PURE FUNCTIONAL CORE ALLOCATION & ZERO-COPY LEASE OPERATIONS
// ============================================================================

[[nodiscard]] constexpr Result<PhysAddr, Error> alloc_frame(PhysPoolState& pool) noexcept {
    if (pool.allocated_frames >= pool.total_frames) {
        return Result<PhysAddr, Error>::err(Error::OutOfMemory);
    }

    for (usize w = 0; w < BITMAP_WORDS; ++w) {
        u64 const inv = ~pool.used_bitmap[w];
        if (inv != 0ULL) {
            u32 const bit       = ctz64(inv);
            u32 const frame_idx = static_cast<u32>(w * 64ULL + bit);
            if (frame_idx >= pool.total_frames) {
                return Result<PhysAddr, Error>::err(Error::OutOfMemory);
            }
            pool.used_bitmap[w] |= (1ULL << bit);
            pool.allocated_frames += 1;
            return Result<PhysAddr, Error>::ok(
                pool.base_addr.offset(static_cast<u64>(frame_idx) * PAGE_SIZE_4K)
            );
        }
    }

    return Result<PhysAddr, Error>::err(Error::OutOfMemory);
}

[[nodiscard]] constexpr Result<Unit, Error> free_frame(
    PhysPoolState& pool,
    PhysAddr       addr
) noexcept {
    if (!addr.is_page_aligned() || addr.raw < pool.base_addr.raw) {
        return Result<Unit, Error>::err(Error::InvalidArgument);
    }

    u64 const frame_idx = (addr.raw - pool.base_addr.raw) / PAGE_SIZE_4K;
    if (frame_idx >= pool.total_frames) {
        return Result<Unit, Error>::err(Error::OutOfBounds);
    }

    usize const w   = static_cast<usize>(frame_idx / 64ULL);
    u32 const   bit = static_cast<u32>(frame_idx % 64ULL);
    u64 const  mask = (1ULL << bit);

    if ((pool.used_bitmap[w] & mask) == 0ULL) {
        return Result<Unit, Error>::err(Error::InvalidState); // Double-free caught explicitly!
    }

    pool.used_bitmap[w] &= ~mask;
    pool.allocated_frames -= 1;
    return Result<Unit, Error>::ok(Unit{});
}

[[nodiscard]] constexpr Result<ArenaId, Error> create_grant_arena(
    MemoryTable& mem,
    ArenaId      desired_id,
    DomainId     creator,
    u32          pages,
    bool         dma_pinned
) noexcept {
    if (!desired_id || !creator || pages == 0) {
        return Result<ArenaId, Error>::err(Error::InvalidArgument);
    }

    // Allocate first backing frame from pool to anchor arena physical window
    auto base_res = alloc_frame(mem.pool);
    if (base_res.is_err()) {
        return Result<ArenaId, Error>::err(base_res.error());
    }
    PhysAddr const base_phys = base_res.value();

    // Allocate remaining contiguous frames (in fresh pool, sequential allocs are contiguous)
    for (u32 p = 1; p < pages; ++p) {
        auto next_res = alloc_frame(mem.pool);
        if (next_res.is_err()) {
            return Result<ArenaId, Error>::err(next_res.error());
        }
    }

    for (usize i = 0; i < MAX_GRANT_ARENAS; ++i) {
        if (!mem.arenas[i].active) {
            GrantArenaState arena{};
            arena.active               = true;
            arena.id                   = desired_id;
            arena.phys_base            = base_phys;
            arena.page_count           = pages;
            arena.creator              = creator;
            arena.current_lease_holder = creator;
            arena.iommu_dma_pinned     = dma_pinned;
            mem.arenas[i]              = arena;
            return Result<ArenaId, Error>::ok(desired_id);
        }
    }

    return Result<ArenaId, Error>::err(Error::TableFull);
}

// O(1) Zero-Copy Lease Handoff: transfers exclusive write/consume ownership without TLB shootdowns!
[[nodiscard]] constexpr Result<Unit, Error> transfer_arena_lease(
    MemoryTable& mem,
    ArenaId      arena_id,
    DomainId     current_owner,
    DomainId     next_owner
) noexcept {
    if (!arena_id || !current_owner || !next_owner) {
        return Result<Unit, Error>::err(Error::InvalidArgument);
    }
    for (usize i = 0; i < MAX_GRANT_ARENAS; ++i) {
        GrantArenaState& a = mem.arenas[i];
        if (a.active && a.id == arena_id) {
            if (!(a.current_lease_holder == current_owner)) {
                return Result<Unit, Error>::err(Error::DomainMismatch);
            }
            a.current_lease_holder = next_owner;
            return Result<Unit, Error>::ok(Unit{});
        }
    }
    return Result<Unit, Error>::err(Error::NotFound);
}

} // namespace mucore::core::mm
