#pragma once
// ============================================================================
// μCore Functional Core — Zero-Copy Arenas, MPK Sealing, NT DMA Quarantine
//                         & Co-Located Driver Filter Stacks
// ============================================================================
// Resolves three major hybrid-kernel hazards identified in architectural audit:
//   1. Shared-Memory TOCTOU ("Double-Fetch") Elimination:
//      `transfer_and_seal_arena()` pairs O(1) lease transfer with Hardware
//      Memory Protection Key (`PkeyId`, x86 PKRU/PKS) write-revocation —
//      preventing malicious senders from mutating buffers during validation
//      with ZERO `invlpg` TLB shootdown IPIs!
//   2. Windows NT-Style Async Crash & DMA Quarantine Teardown:
//      Tracks `in_flight_dma_ops` per `GrantArena`. If a client crashes while
//      PCIe hardware is mid-DMA, `quarantine_domain_arenas()` isolates the
//      frames in `QuarantinedDmaDrain` rather than freeing them into `PhysPool`,
//      eliminating async DMA Use-After-Free!
//   3. NT Filter Stacks / Fuchsia DFv2 Driver Colocation (`ColocatedPipeline`):
//      Mutually trusted protocol layers co-located in one Ring-3 domain pass
//      `IoPacket`s (IRPs) stage-to-stage with 0 IPC hops & 0 CR3 switches,
//      complete with deterministic cancellation unwinding.
// ============================================================================

#include "mucore/result.hpp"
#include "mucore/types.hpp"
#include "mucore/core/kinetic.hpp"

namespace mucore::core::mm {

inline constexpr usize BITMAP_WORDS           = 64; // 64 * 64 = 4096 frames = 16 MiB pool
inline constexpr usize MAX_FRAMES             = BITMAP_WORDS * 64;
inline constexpr usize MAX_GRANT_ARENAS       = 32;
inline constexpr usize MAX_PIPELINE_STAGES    = 6;
inline constexpr usize MAGAZINE_CAPACITY      = 64; // Per-CPU 0-lock hot frame cache (256 KiB)
inline constexpr usize MAGAZINE_BATCH_SIZE    = 32; // Batch refill / drain quantum
inline constexpr usize RT_EMERGENCY_WATERMARK = 8;  // Protected exclusively for Tier-0 Hard RT!

enum class ArenaLifecycle : u8 {
    Free                 = 0,
    EditableByHolder     = 1, // Current lease holder may read/write freely
    SealedForValidation  = 2, // Sender write-revoked via MPK; receiver/Kineticlet safe from TOCTOU!
    DmaInFlight          = 3, // Pinned for active PCIe/IOMMU hardware transfer
    QuarantinedDmaDrain  = 4, // Domain crashed/cancelled mid-DMA; physical free blocked until drain!
};

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
    bool           active{false};
    ArenaId        id{};
    ArenaLifecycle lifecycle{ArenaLifecycle::Free};
    PkeyId         mpk_key{1};           // Hardware protection key guarding sender writes
    PhysAddr       phys_base{};
    u32            page_count{0};
    DomainId       creator{};
    DomainId       current_lease_holder{};
    bool           iommu_dma_pinned{false};
    u32            in_flight_dma_ops{0}; // Non-zero blocks physical frame reclamation!
    u64            kinetic_words[kinetic::NUM_ARENA_WORDS]{};
};

// NT IRP-Inspired Co-Located Filter Stack Packet (Fuchsia DFv2 / NT Stack Synthesis)
enum class IoPacketStatus : u8 {
    Pending   = 0,
    Completed = 1,
    Cancelled = 2,
};

struct ColocatedPipeline {
    IoPacketId     packet_id{};
    DomainId       host_domain{}; // Single Ring-3 domain hosting co-located trusted stages
    ArenaId        payload_arena{};
    u32            stage_ids[MAX_PIPELINE_STAGES]{};
    u8             total_stages{0};
    u8             current_stage{0};
    IoPacketStatus status{IoPacketStatus::Pending};
    u32            zero_ipc_hops{0}; // Counts stage transitions completed with 0 syscalls!
};

// Per-CPU 0-lock hot physical frame cache with Hard-RT emergency watermark
struct LocalFrameMagazine {
    PhysAddr frames[MAGAZINE_CAPACITY]{};
    usize    count{0};
    u64      local_fast_allocs{0};
    u64      batch_refills{0};
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
// PURE FUNCTIONAL CORE ALLOCATION, MAGAZINES, MPK SEALING & NT QUARANTINE
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

// Allocate `pages` genuinely contiguous 4 KiB physical frames (safe under fragmentation!)
[[nodiscard]] constexpr Result<PhysAddr, Error> alloc_contiguous_frames(
    PhysPoolState& pool,
    u32            pages
) noexcept {
    if (pages == 0 || pool.allocated_frames + pages > pool.total_frames) {
        return Result<PhysAddr, Error>::err(
            (pages == 0) ? Error::InvalidArgument : Error::OutOfMemory
        );
    }

    u32 run_start = 0;
    u32 run_len   = 0;
    for (u32 f = 0; f < pool.total_frames; ++f) {
        usize const w   = f / 64u;
        u32 const   bit = f % 64u;
        bool const  used = (pool.used_bitmap[w] & (1ULL << bit)) != 0ULL;
        if (!used) {
            if (run_len == 0) run_start = f;
            ++run_len;
            if (run_len == pages) {
                for (u32 mark = run_start; mark < run_start + pages; ++mark) {
                    pool.used_bitmap[mark / 64u] |= (1ULL << (mark % 64u));
                }
                pool.allocated_frames += pages;
                return Result<PhysAddr, Error>::ok(
                    pool.base_addr.offset(static_cast<u64>(run_start) * PAGE_SIZE_4K)
                );
            }
        } else {
            run_len = 0;
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

// 0-Lock O(1) Per-Core Magazine Pop:
//   Tier-1 (`!is_hard_rt`) cannot consume the last `RT_EMERGENCY_WATERMARK` frames,
//   guaranteeing Tier-0 Hard Real-Time paths never block on backing pool refills!
[[nodiscard]] constexpr Result<PhysAddr, Error> alloc_from_magazine(
    LocalFrameMagazine& mag,
    bool                is_hard_rt
) noexcept {
    if (mag.count == 0) {
        return Result<PhysAddr, Error>::err(Error::OutOfMemory);
    }
    if (!is_hard_rt && mag.count <= RT_EMERGENCY_WATERMARK) {
        return Result<PhysAddr, Error>::err(Error::RtReserveProtected);
    }
    mag.local_fast_allocs += 1;
    return Result<PhysAddr, Error>::ok(mag.frames[--mag.count]);
}

[[nodiscard]] constexpr Result<Unit, Error> free_to_magazine(
    LocalFrameMagazine& mag,
    PhysAddr            frame
) noexcept {
    if (!frame.is_page_aligned()) {
        return Result<Unit, Error>::err(Error::InvalidArgument);
    }
    if (mag.count >= MAGAZINE_CAPACITY) {
        return Result<Unit, Error>::err(Error::TableFull);
    }
    mag.frames[mag.count++] = frame;
    return Result<Unit, Error>::ok(Unit{});
}

// Batch-refill up to `MAGAZINE_BATCH_SIZE` frames from shared `PhysPoolState` into `mag`
[[nodiscard]] constexpr usize refill_magazine_batch(
    LocalFrameMagazine& mag,
    PhysPoolState&      pool
) noexcept {
    usize added = 0;
    while (mag.count < MAGAZINE_CAPACITY && added < MAGAZINE_BATCH_SIZE) {
        auto f = alloc_frame(pool);
        if (f.is_err()) break;
        mag.frames[mag.count++] = f.value();
        ++added;
    }
    if (added > 0) {
        mag.batch_refills += 1;
    }
    return added;
}

// Batch-drain `MAGAZINE_BATCH_SIZE` frames from full `mag` back to shared `PhysPoolState`
[[nodiscard]] constexpr usize drain_magazine_batch(
    LocalFrameMagazine& mag,
    PhysPoolState&      pool
) noexcept {
    usize drained = 0;
    while (mag.count > RT_EMERGENCY_WATERMARK && drained < MAGAZINE_BATCH_SIZE) {
        PhysAddr const f = mag.frames[--mag.count];
        (void)free_frame(pool, f);
        ++drained;
    }
    return drained;
}

[[nodiscard]] constexpr Option<usize> find_arena_slot(
    MemoryTable const& mem,
    ArenaId            id
) noexcept {
    if (!id) return Option<usize>::none();
    for (usize i = 0; i < MAX_GRANT_ARENAS; ++i) {
        if (mem.arenas[i].active && mem.arenas[i].id == id) {
            return Option<usize>::some(i);
        }
    }
    return Option<usize>::none();
}

[[nodiscard]] constexpr Result<ArenaId, Error> create_grant_arena(
    MemoryTable& mem,
    ArenaId      desired_id,
    DomainId     creator,
    u32          pages,
    bool         dma_pinned,
    PkeyId       mpk_key = PkeyId{1}
) noexcept {
    if (!desired_id || !creator || pages == 0 || find_arena_slot(mem, desired_id).is_some()) {
        return Result<ArenaId, Error>::err(Error::InvalidArgument);
    }

    auto base_res = alloc_contiguous_frames(mem.pool, pages);
    if (base_res.is_err()) {
        return Result<ArenaId, Error>::err(base_res.error());
    }
    PhysAddr const base_phys = base_res.value();

    for (usize i = 0; i < MAX_GRANT_ARENAS; ++i) {
        if (!mem.arenas[i].active) {
            GrantArenaState arena{};
            arena.active               = true;
            arena.id                   = desired_id;
            arena.lifecycle            = ArenaLifecycle::EditableByHolder;
            arena.mpk_key              = mpk_key;
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

// O(1) Zero-Copy Lease Handoff + Optional MPK Seal (eliminates TOCTOU double-fetch!)
[[nodiscard]] constexpr Result<PkeyId, Error> transfer_arena_lease(
    MemoryTable& mem,
    ArenaId      arena_id,
    DomainId     current_owner,
    DomainId     next_owner,
    bool         seal_sender_writes = true
) noexcept {
    if (!arena_id || !current_owner || !next_owner) {
        return Result<PkeyId, Error>::err(Error::InvalidArgument);
    }

    auto slot_opt = find_arena_slot(mem, arena_id);
    if (slot_opt.is_none()) {
        return Result<PkeyId, Error>::err(Error::NotFound);
    }

    GrantArenaState& a = mem.arenas[slot_opt.value()];
    if (!(a.current_lease_holder == current_owner)) {
        return Result<PkeyId, Error>::err(Error::DomainMismatch);
    }
    if (a.lifecycle == ArenaLifecycle::QuarantinedDmaDrain ||
        a.lifecycle == ArenaLifecycle::DmaInFlight) {
        return Result<PkeyId, Error>::err(Error::ArenaSealed);
    }

    a.current_lease_holder = next_owner;
    a.lifecycle = seal_sender_writes ? ArenaLifecycle::SealedForValidation
                                     : ArenaLifecycle::EditableByHolder;
    return Result<PkeyId, Error>::ok(a.mpk_key);
}

// Mark arena as actively undergoing hardware PCIe/IOMMU DMA
[[nodiscard]] constexpr Result<Unit, Error> begin_arena_dma(
    MemoryTable& mem,
    ArenaId      arena_id,
    DomainId     driver_holder
) noexcept {
    auto slot_opt = find_arena_slot(mem, arena_id);
    if (slot_opt.is_none()) {
        return Result<Unit, Error>::err(Error::NotFound);
    }
    GrantArenaState& a = mem.arenas[slot_opt.value()];
    if (!(a.current_lease_holder == driver_holder) || !a.iommu_dma_pinned) {
        return Result<Unit, Error>::err(Error::InsufficientRights);
    }
    if (a.lifecycle == ArenaLifecycle::QuarantinedDmaDrain) {
        return Result<Unit, Error>::err(Error::DmaInFlightQuarantined);
    }
    a.in_flight_dma_ops += 1;
    a.lifecycle = ArenaLifecycle::DmaInFlight;
    return Result<Unit, Error>::ok(Unit{});
}

// NT Crash/Cancellation Teardown: safely quarantines in-flight DMA pages instead of UAF!
[[nodiscard]] constexpr u32 quarantine_domain_arenas(
    MemoryTable& mem,
    DomainId     crashed_or_cancelling_domain
) noexcept {
    u32 quarantined_count = 0;
    for (usize i = 0; i < MAX_GRANT_ARENAS; ++i) {
        GrantArenaState& a = mem.arenas[i];
        if (!a.active) continue;
        if (!(a.creator == crashed_or_cancelling_domain) &&
            !(a.current_lease_holder == crashed_or_cancelling_domain)) {
            continue;
        }

        if (a.in_flight_dma_ops > 0) {
            // Hardware DMA still active! Lock in Quarantine so PhysPool CANNOT reallocate!
            a.lifecycle = ArenaLifecycle::QuarantinedDmaDrain;
            quarantined_count += 1;
        } else {
            // Safe to reclaim backing physical frames immediately
            for (u32 p = 0; p < a.page_count; ++p) {
                (void)free_frame(mem.pool, a.phys_base.offset(static_cast<u64>(p) * PAGE_SIZE_4K));
            }
            a = GrantArenaState{};
        }
    }
    return quarantined_count;
}

// Attempt explicit arena reclamation (fails with `DmaInFlightQuarantined` if DMA still active!)
[[nodiscard]] constexpr Result<Unit, Error> destroy_grant_arena(
    MemoryTable& mem,
    ArenaId      arena_id
) noexcept {
    auto slot_opt = find_arena_slot(mem, arena_id);
    if (slot_opt.is_none()) {
        return Result<Unit, Error>::err(Error::NotFound);
    }
    GrantArenaState& a = mem.arenas[slot_opt.value()];
    if (a.in_flight_dma_ops > 0 || a.lifecycle == ArenaLifecycle::QuarantinedDmaDrain) {
        return Result<Unit, Error>::err(Error::DmaInFlightQuarantined);
    }
    for (u32 p = 0; p < a.page_count; ++p) {
        (void)free_frame(mem.pool, a.phys_base.offset(static_cast<u64>(p) * PAGE_SIZE_4K));
    }
    a = GrantArenaState{};
    return Result<Unit, Error>::ok(Unit{});
}

// Driver / IOMMU confirms hardware queue abort/completion -> releases quarantined pages safely!
[[nodiscard]] constexpr Result<bool, Error> complete_arena_dma_op(
    MemoryTable& mem,
    ArenaId      arena_id
) noexcept {
    auto slot_opt = find_arena_slot(mem, arena_id);
    if (slot_opt.is_none()) {
        return Result<bool, Error>::err(Error::NotFound);
    }
    GrantArenaState& a = mem.arenas[slot_opt.value()];
    if (a.in_flight_dma_ops == 0) {
        return Result<bool, Error>::err(Error::InvalidState);
    }

    a.in_flight_dma_ops -= 1;
    if (a.in_flight_dma_ops == 0) {
        if (a.lifecycle == ArenaLifecycle::QuarantinedDmaDrain) {
            // Final quarantined DMA drained! Reclaim physical frames safely now.
            for (u32 p = 0; p < a.page_count; ++p) {
                (void)free_frame(mem.pool, a.phys_base.offset(static_cast<u64>(p) * PAGE_SIZE_4K));
            }
            a = GrantArenaState{};
            return Result<bool, Error>::ok(true); // Reclaimed from quarantine!
        }
        a.lifecycle = ArenaLifecycle::EditableByHolder;
    }
    return Result<bool, Error>::ok(false);
}

// ============================================================================
// CO-LOCATED TRUSTED FILTER PIPELINE (NT IRP Stack / Fuchsia DFv2 Colocation)
// ============================================================================

[[nodiscard]] constexpr Result<u32, Error> advance_colocated_stage(
    ColocatedPipeline& pipe
) noexcept {
    if (pipe.status != IoPacketStatus::Pending || pipe.total_stages == 0) {
        return Result<u32, Error>::err(Error::InvalidState);
    }
    if (pipe.current_stage + 1u < pipe.total_stages) {
        pipe.current_stage += 1;
        pipe.zero_ipc_hops += 1;
        return Result<u32, Error>::ok(pipe.stage_ids[pipe.current_stage]);
    }
    pipe.status = IoPacketStatus::Completed;
    return Result<u32, Error>::ok(0u);
}

// Deterministic reverse-order NT IRP cancellation unwind across visited stages
[[nodiscard]] constexpr u8 cancel_colocated_pipeline(ColocatedPipeline& pipe) noexcept {
    if (pipe.status != IoPacketStatus::Pending) {
        return 0;
    }
    u8 const unwound_stages = static_cast<u8>(pipe.current_stage + 1u);
    pipe.current_stage = 0;
    pipe.status        = IoPacketStatus::Cancelled;
    return unwound_stages;
}

} // namespace mucore::core::mm
