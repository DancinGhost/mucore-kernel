#pragma once
// ============================================================================
// μCore Functional Core — 4-Level x86_64 VmSpace, MPK PTEs & Optional KPTI
// ============================================================================
// Implements Locked-In Phase 2 Paging Architecture:
//   - Constitutional Hardware W^X: any mapping requesting both `Writable` and
//     `Executable` is rejected in the Pure Core with `Error::WxorXViolation`.
//   - Hardware MPK Tagging: encodes 4-bit `PkeyId` (`0..15`) into `PTE[62:59]`
//     so `WRPKRU` seals zero-copy `GrantArena` pages in ~20 cycles.
//   - Per-Domain `KptiMode`:
//       * `SharedHigherHalf` (default): shares `PML4[256..511]` (`Global=1`)
//         for 0-CR3-switch `SYSCALL` / IRQ / Kineticlet fast-paths.
//       * `StrictKpti` (sandbox opt-in): strips `PML4[256..510]`, exposing
//         only the `PML4[511]` entry trampoline to hostile Ring-3 code.
// ============================================================================

#include "mucore/result.hpp"
#include "mucore/types.hpp"

namespace mucore::core::vm {

// Architectural x86_64 64-bit Page Table Entry Flags
inline constexpr u64 PTE_PRESENT    = 1ULL << 0;
inline constexpr u64 PTE_WRITABLE   = 1ULL << 1;
inline constexpr u64 PTE_USER       = 1ULL << 2;
inline constexpr u64 PTE_WRITE_THRU = 1ULL << 3;
inline constexpr u64 PTE_CACHE_DIS  = 1ULL << 4;
inline constexpr u64 PTE_ACCESSED   = 1ULL << 5;
inline constexpr u64 PTE_DIRTY      = 1ULL << 6;
inline constexpr u64 PTE_HUGE_2M    = 1ULL << 7;
inline constexpr u64 PTE_GLOBAL     = 1ULL << 8;
inline constexpr u64 PTE_ADDR_MASK  = 0x000F'FFFF'FFFF'F000ULL;
inline constexpr u32 PTE_MPK_SHIFT  = 59u; // Bits 62:59 = 4-bit Protection Key!
inline constexpr u64 PTE_NX         = 1ULL << 63;

inline constexpr u64 HIGHER_HALF_BASE = 0xFFFF'8000'0000'0000ULL;
inline constexpr usize PT_ENTRIES     = 512;
inline constexpr usize MAX_PT_NODES   = 32; // Inline page-table node pool for Core/Tests

enum class KptiMode : u8 {
    SharedHigherHalf = 0, // Default: PML4[256..511] mapped Global (0 CR3 switch on IRQ!)
    StrictKpti       = 1, // Hostile sandbox: PML4[256..510] unmapped; trampoline in [511] only
};

struct MapPermissions {
    bool   writable{false};
    bool   executable{false};
    bool   user_accessible{false};
    bool   uncached_mmio{false};
    bool   global_tlb{false};
    PkeyId mpk_key{0};
};

struct alignas(PAGE_SIZE_4K) PageTableNode {
    u64 entries[PT_ENTRIES]{};
};

struct VmDomainDescriptor {
    bool     active{false};
    DomainId domain{};
    u16      pcid_12bit{0};
    KptiMode kpti_mode{KptiMode::SharedHigherHalf};
    u32      user_pml4_node{0};   // Index in page-table node pool
    u32      kernel_pml4_node{0}; // Shadow Kernel PML4 when `StrictKpti`
    PhysAddr user_pml4_phys{};
};

// ============================================================================
// PURE ADDRESS CANONICALITY, INDEX EXTRACTION & W^X PTE ENCODING
// ============================================================================

[[nodiscard]] constexpr bool is_canonical_48bit(VirtAddr va) noexcept {
    u64 const top17 = va.raw >> 47;
    return (top17 == 0ULL) || (top17 == 0x1FFFFULL);
}

[[nodiscard]] constexpr usize pml4_index(VirtAddr va) noexcept {
    return static_cast<usize>((va.raw >> 39) & 0x1FFULL);
}
[[nodiscard]] constexpr usize pdpt_index(VirtAddr va) noexcept {
    return static_cast<usize>((va.raw >> 30) & 0x1FFULL);
}
[[nodiscard]] constexpr usize pd_index(VirtAddr va) noexcept {
    return static_cast<usize>((va.raw >> 21) & 0x1FFULL);
}
[[nodiscard]] constexpr usize pt_index(VirtAddr va) noexcept {
    return static_cast<usize>((va.raw >> 12) & 0x1FFULL);
}

[[nodiscard]] constexpr PkeyId extract_pte_mpk(u64 pte) noexcept {
    return PkeyId{static_cast<u8>((pte >> PTE_MPK_SHIFT) & 0xFULL)};
}

// Constitutional W^X & Privilege Encoder
[[nodiscard]] constexpr Result<u64, Error> encode_leaf_pte(
    VirtAddr       va,
    PhysAddr       pa,
    MapPermissions perms
) noexcept {
    if (!va.is_page_aligned() || !pa.is_page_aligned() || !is_canonical_48bit(va)) {
        return Result<u64, Error>::err(Error::InvalidArgument);
    }

    // Constitutional Rule: A page may NEVER be simultaneously Writable and Executable!
    if (perms.writable && perms.executable) {
        return Result<u64, Error>::err(Error::WxorXViolation);
    }

    // Ring-3 User bit is strictly forbidden in Higher-Half Kernel virtual space!
    if (va.raw >= HIGHER_HALF_BASE && perms.user_accessible) {
        return Result<u64, Error>::err(Error::InsufficientRights);
    }

    if (perms.mpk_key.raw > 15u) {
        return Result<u64, Error>::err(Error::InvalidArgument);
    }

    u64 pte = (pa.raw & PTE_ADDR_MASK) | PTE_PRESENT;
    if (perms.writable)        pte |= PTE_WRITABLE;
    if (perms.user_accessible) pte |= PTE_USER;
    if (perms.uncached_mmio)   pte |= (PTE_CACHE_DIS | PTE_WRITE_THRU);
    if (perms.global_tlb)      pte |= PTE_GLOBAL;
    if (!perms.executable)     pte |= PTE_NX;

    pte |= (static_cast<u64>(perms.mpk_key.raw & 0xFu) << PTE_MPK_SHIFT);
    return Result<u64, Error>::ok(pte);
}

// ============================================================================
// DETERMINISTIC 4-LEVEL PAGE TABLE HIERARCHY BUILDER & KPTI CONFIGURATOR
// ============================================================================

struct VmTablePool {
    PageTableNode nodes[MAX_PT_NODES]{};
    PhysAddr      node_phys[MAX_PT_NODES]{};
    bool          allocated[MAX_PT_NODES]{};
    u32           used_count{0};

    constexpr VmTablePool() noexcept {
        for (usize i = 0; i < MAX_PT_NODES; ++i) {
            node_phys[i] = PhysAddr{0x0100'0000ULL + i * PAGE_SIZE_4K};
        }
    }
    VmTablePool(VmTablePool const&)            = delete;
    VmTablePool& operator=(VmTablePool const&) = delete;
};

[[nodiscard]] constexpr Result<u32, Error> alloc_pt_node(VmTablePool& pool) noexcept {
    for (u32 i = 0; i < MAX_PT_NODES; ++i) {
        if (!pool.allocated[i]) {
            pool.allocated[i] = true;
            pool.nodes[i]     = PageTableNode{};
            pool.used_count  += 1;
            return Result<u32, Error>::ok(i);
        }
    }
    return Result<u32, Error>::err(Error::OutOfMemory);
}

[[nodiscard]] constexpr Option<u32> phys_to_node_idx(
    VmTablePool const& pool,
    PhysAddr           pa
) noexcept {
    for (u32 i = 0; i < MAX_PT_NODES; ++i) {
        if (pool.allocated[i] && pool.node_phys[i] == pa) {
            return Option<u32>::some(i);
        }
    }
    return Option<u32>::none();
}

// Configure a Domain's Root PML4 from `kernel_pml4_idx` according to `KptiMode`!
[[nodiscard]] constexpr Result<VmDomainDescriptor, Error> create_domain_vmspace(
    VmTablePool& pool,
    u32          kernel_pml4_idx,
    DomainId     domain,
    KptiMode     mode
) noexcept {
    if (!domain || kernel_pml4_idx >= MAX_PT_NODES || !pool.allocated[kernel_pml4_idx]) {
        return Result<VmDomainDescriptor, Error>::err(Error::InvalidArgument);
    }

    auto u_res = alloc_pt_node(pool);
    if (u_res.is_err()) {
        return Result<VmDomainDescriptor, Error>::err(u_res.error());
    }
    u32 const user_idx = u_res.value();

    PageTableNode const& kpml4 = pool.nodes[kernel_pml4_idx];
    PageTableNode&       upml4 = pool.nodes[user_idx];

    if (mode == KptiMode::SharedHigherHalf) {
        // Share all Higher-Half Kernel + HHDM PML4 slots [256..511] -> 0 CR3 switches on IRQ!
        for (usize slot = 256; slot < PT_ENTRIES; ++slot) {
            upml4.entries[slot] = kpml4.entries[slot];
        }
    } else {
        // `StrictKpti`: slots [256..510] remain unmapped (`0`)! Only [511] trampoline exposed.
        upml4.entries[511] = kpml4.entries[511];
    }

    return Result<VmDomainDescriptor, Error>::ok(VmDomainDescriptor{
        .active           = true,
        .domain           = domain,
        .pcid_12bit       = static_cast<u16>(domain.raw & 0xFFFu),
        .kpti_mode        = mode,
        .user_pml4_node   = user_idx,
        .kernel_pml4_node = kernel_pml4_idx,
        .user_pml4_phys   = pool.node_phys[user_idx],
    });
}

// Map a 4 KiB page through 4-level hierarchy (`PML4 -> PDPT -> PD -> PT`),
// allocating intermediate directories on demand and enforcing W^X + MPK!
[[nodiscard]] constexpr Result<Unit, Error> map_page_4k(
    VmTablePool&   pool,
    u32            pml4_node_idx,
    VirtAddr       va,
    PhysAddr       pa,
    MapPermissions perms
) noexcept {
    if (pml4_node_idx >= MAX_PT_NODES || !pool.allocated[pml4_node_idx]) {
        return Result<Unit, Error>::err(Error::InvalidArgument);
    }

    auto leaf_res = encode_leaf_pte(va, pa, perms);
    if (leaf_res.is_err()) {
        return Result<Unit, Error>::err(leaf_res.error());
    }

    u64 const inter_flags = PTE_PRESENT | PTE_WRITABLE | (perms.user_accessible ? PTE_USER : 0ULL);
    usize const indices[3] = {pml4_index(va), pdpt_index(va), pd_index(va)};

    u32 cur_node = pml4_node_idx;
    for (usize lvl = 0; lvl < 3; ++lvl) {
        u64& entry = pool.nodes[cur_node].entries[indices[lvl]];
        if ((entry & PTE_PRESENT) == 0ULL) {
            auto next_res = alloc_pt_node(pool);
            if (next_res.is_err()) {
                return Result<Unit, Error>::err(next_res.error());
            }
            u32 const next_idx = next_res.value();
            entry    = (pool.node_phys[next_idx].raw & PTE_ADDR_MASK) | inter_flags;
            cur_node = next_idx;
        } else {
            if (perms.user_accessible) {
                entry |= PTE_USER;
            }
            PhysAddr const child_pa{entry & PTE_ADDR_MASK};
            auto child_opt = phys_to_node_idx(pool, child_pa);
            if (child_opt.is_none()) {
                return Result<Unit, Error>::err(Error::InvalidState);
            }
            cur_node = child_opt.value();
        }
    }

    pool.nodes[cur_node].entries[pt_index(va)] = leaf_res.value();
    return Result<Unit, Error>::ok(Unit{});
}

// Pure 4-level hardware MMU walk simulator (returns final leaf PTE if mapped!)
[[nodiscard]] constexpr Result<u64, Error> walk_page_table(
    VmTablePool const& pool,
    u32                pml4_node_idx,
    VirtAddr           va
) noexcept {
    if (pml4_node_idx >= MAX_PT_NODES || !pool.allocated[pml4_node_idx] || !is_canonical_48bit(va)) {
        return Result<u64, Error>::err(Error::InvalidArgument);
    }

    usize const indices[3] = {pml4_index(va), pdpt_index(va), pd_index(va)};
    u32 cur_node = pml4_node_idx;

    for (usize lvl = 0; lvl < 3; ++lvl) {
        u64 const entry = pool.nodes[cur_node].entries[indices[lvl]];
        if ((entry & PTE_PRESENT) == 0ULL) {
            return Result<u64, Error>::err(Error::NotFound);
        }
        auto next_opt = phys_to_node_idx(pool, PhysAddr{entry & PTE_ADDR_MASK});
        if (next_opt.is_none()) {
            return Result<u64, Error>::err(Error::InvalidState);
        }
        cur_node = next_opt.value();
    }

    u64 const leaf = pool.nodes[cur_node].entries[pt_index(va)];
    if ((leaf & PTE_PRESENT) == 0ULL) {
        return Result<u64, Error>::err(Error::NotFound);
    }
    return Result<u64, Error>::ok(leaf);
}

} // namespace mucore::core::vm
