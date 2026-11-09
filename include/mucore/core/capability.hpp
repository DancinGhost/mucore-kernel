#pragma once
// ============================================================================
// μCore Functional Core — Pragmatic Generational Capability Engine (v2)
// ============================================================================
// Synthesizes Zircon, L4, and Real-Time Capability Design:
//   1. Zircon Discipline (Zero Confused-Deputy Dual Authority):
//      `AmbientProfile` is strictly restricted to *intra-domain* private RAM,
//      local threads, and futexes — NO ambient global VFS back-door! External
//      resources are 100% capability-governed (composed via Plan-9 per-domain
//      namespaces in `namespace_p9.hpp`).
//   2. Dual-Granularity O(1) Revocation + Zero Zombie Slot Leakage:
//      - Surgical `plan_revoke_single`: O(1) generation bump on one slot
//        (zero collateral blast radius to sibling delegates!).
//      - Subtree `plan_revoke_lineage`: O(1) `RevocationGroupId` epoch bump
//        invalidating an entire delegation tree in 1 integer increment.
//      - Automatic Lazy Reclamation: slots with stale `bound_epoch` are
//        transparently recycled on allocation with incremented `generation`.
// ============================================================================

#include "mucore/result.hpp"
#include "mucore/types.hpp"

namespace mucore::core::cap {

inline constexpr usize MAX_CAP_SLOTS         = 256;
inline constexpr usize MAX_REVOCATION_GROUPS = 64;

enum class CapObjectKind : u8 {
    None          = 0,
    FluxConduit   = 1, // Wait-free async Ring0/Ring3 or Driver IPC channel
    FluxPort      = 2, // Zircon/NT-style O(1) multi-conduit readiness multiplexer
    GrantArena    = 3, // Zero-copy shared physical memory window (with MPK/DMA guard)
    MmioRegion    = 4, // Device BAR / MMIO physical frame range (Userspace Drivers)
    IrqHook       = 5, // Hardware interrupt line binding
    KineticSlot   = 6, // Authority to graft a verified Kineticlet into Ring 0
    RtBudget      = 7, // L4-MCS authority to reserve & donate CBS/EDF CPU bandwidth
    DomainControl = 8, // Authority to spawn or supervise a child ProtectionDomain
};

namespace CapRights {
    inline constexpr u16 None         = 0;
    inline constexpr u16 Read         = 1u << 0;
    inline constexpr u16 Write        = 1u << 1;
    inline constexpr u16 ExecuteRing0 = 1u << 2; // Install/trigger Ring-0 fast-path
    inline constexpr u16 Delegate     = 1u << 3; // Derive attenuated child caps
    inline constexpr u16 Revoke       = 1u << 4; // Revoke single slot or lineage epoch
    inline constexpr u16 UrgentRt     = 1u << 5; // Push Urgent RT + donate CBS context
    inline constexpr u16 DmaMap       = 1u << 6; // Program IOMMU DMA mappings
    inline constexpr u16 FastPromote  = 1u << 7; // Upgrade Plan-9 path to Hot zero-switch ring

    inline constexpr u16 All =
        Read | Write | ExecuteRing0 | Delegate | Revoke | UrgentRt | DmaMap | FastPromote;
} // namespace CapRights

struct RevocationGroupId {
    u16 raw{0};
    constexpr bool operator==(RevocationGroupId const&) const noexcept = default;
};

// Opaque 64-bit token held by Ring-3 software; forged tokens fail generation/epoch check
struct CapToken {
    u64 raw{0};

    constexpr bool operator==(CapToken const&) const noexcept = default;
    constexpr explicit operator bool() const noexcept { return raw != 0; }

    [[nodiscard]] static constexpr CapToken pack(
        u32 slot_idx, u32 generation, CapObjectKind kind, u16 rights_hint
    ) noexcept {
        u64 const s = static_cast<u64>(slot_idx & 0xFFFFFu);
        u64 const g = static_cast<u64>(generation & 0xFFFFFFu) << 20;
        u64 const r = static_cast<u64>(rights_hint & 0xFFFu) << 44;
        u64 const k = static_cast<u64>(kind) << 56;
        return CapToken{s | g | r | k};
    }

    [[nodiscard]] constexpr u32 slot_index() const noexcept {
        return static_cast<u32>(raw & 0xFFFFFu);
    }
    [[nodiscard]] constexpr u32 generation() const noexcept {
        return static_cast<u32>((raw >> 20) & 0xFFFFFFu);
    }
    [[nodiscard]] constexpr CapObjectKind kind_hint() const noexcept {
        return static_cast<CapObjectKind>((raw >> 56) & 0xFFu);
    }
};

// Strictly Local Intra-Domain Quotas (Zero ambient external authority!)
struct AmbientProfile {
    u32  quota_anon_pages{1024}; // Max private 4KiB pages without L4 frame-cap plumbing
    u16  max_local_threads{16};
    bool allow_local_futex{true};
};

// Authoritative Ring-0 Capability Slot Entry
struct CapEntry {
    bool              occupied{false};
    u32               generation{1};
    DomainId          owner{};
    CapObjectKind     kind{CapObjectKind::None};
    u16               rights{CapRights::None};
    RevocationGroupId rev_group{};
    u32               bound_epoch{0}; // Live iff == table.group_epochs[rev_group]
    u64               object_id{0};   // Target ConduitId / PortId / ArenaId / IrqLine
};

// Explicit State Mutation emitted by Pure Core functions
struct CapMutation {
    enum class Type : u8 {
        None = 0,
        WriteSlot,
        ClearSlot,
        BumpGroupEpoch,
    };

    Type              type{Type::None};
    u32               slot_idx{0};
    CapEntry          new_entry{};
    RevocationGroupId target_group{};
    CapToken          minted_token{};
};

// Capability State Table (implicit copy deleted — no hidden multi-KB memcpy!)
struct CapTable {
    CapEntry slots[MAX_CAP_SLOTS]{};
    u32      group_epochs[MAX_REVOCATION_GROUPS]{};

    constexpr CapTable() noexcept = default;
    CapTable(CapTable const&)            = delete;
    CapTable& operator=(CapTable const&) = delete;
    constexpr CapTable(CapTable&&) noexcept            = default;
    constexpr CapTable& operator=(CapTable&&) noexcept = default;
};

// ============================================================================
// PURE FUNCTIONAL CORE OPERATIONS (Zero Side Effects, Deterministic Bounds)
// ============================================================================

[[nodiscard]] constexpr bool is_slot_live(CapTable const& table, u32 idx) noexcept {
    if (idx == 0 || idx >= MAX_CAP_SLOTS) return false;
    CapEntry const& e = table.slots[idx];
    if (!e.occupied) return false;
    if (e.rev_group.raw >= MAX_REVOCATION_GROUPS) return false;
    return table.group_epochs[e.rev_group.raw] == e.bound_epoch;
}

// Reclaims both unoccupied slots AND epoch-expired zombie slots automatically!
[[nodiscard]] constexpr Option<u32> find_free_slot(CapTable const& table) noexcept {
    for (u32 i = 1; i < MAX_CAP_SLOTS; ++i) { // Slot 0 reserved as null sentinel
        if (!is_slot_live(table, i)) {
            return Option<u32>::some(i);
        }
    }
    return Option<u32>::none();
}

// Exact O(1) lock-free SMP validation:
//   - At compile time (`if consteval`): pure constexpr evaluation.
//   - At runtime on SMP: acquire-ordered generation/epoch loads + post-read
//     generation re-check (lock-free SeqLock pattern prevents torn slot reads!).
[[nodiscard]] constexpr Result<CapEntry, Error> validate_capability(
    CapTable const& table,
    DomainId        caller,
    CapToken        token,
    CapObjectKind   expected_kind,
    u16             required_rights
) noexcept {
    u32 const idx = token.slot_index();
    if (idx == 0 || idx >= MAX_CAP_SLOTS) {
        return Result<CapEntry, Error>::err(Error::InvalidCapability);
    }

    CapEntry const& slot = table.slots[idx];
    bool occ       = false;
    u32  gen_first = 0;

    if consteval {
        occ       = slot.occupied;
        gen_first = slot.generation;
    } else {
        occ       = __atomic_load_n(&slot.occupied, __ATOMIC_ACQUIRE);
        gen_first = __atomic_load_n(&slot.generation, __ATOMIC_ACQUIRE);
    }

    if (!occ || gen_first != token.generation()) {
        return Result<CapEntry, Error>::err(Error::InvalidCapability);
    }

    CapEntry snap{};
    snap.occupied   = occ;
    snap.generation = gen_first;

    if consteval {
        snap.owner       = slot.owner;
        snap.kind        = slot.kind;
        snap.rights      = slot.rights;
        snap.rev_group   = slot.rev_group;
        snap.bound_epoch = slot.bound_epoch;
        snap.object_id   = slot.object_id;
    } else {
        snap.owner       = DomainId{__atomic_load_n(&slot.owner.raw, __ATOMIC_RELAXED)};
        __atomic_load(&slot.kind, &snap.kind, __ATOMIC_RELAXED);
        snap.rights      = __atomic_load_n(&slot.rights, __ATOMIC_RELAXED);
        snap.rev_group   = RevocationGroupId{__atomic_load_n(&slot.rev_group.raw, __ATOMIC_RELAXED)};
        snap.bound_epoch = __atomic_load_n(&slot.bound_epoch, __ATOMIC_RELAXED);
        snap.object_id   = __atomic_load_n(&slot.object_id, __ATOMIC_RELAXED);
    }

    u32 cur_epoch  = 0;
    u32 gen_second = gen_first;
    if (snap.rev_group.raw >= MAX_REVOCATION_GROUPS) {
        return Result<CapEntry, Error>::err(Error::RevokedCapability);
    }

    if consteval {
        cur_epoch = table.group_epochs[snap.rev_group.raw];
    } else {
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        gen_second = __atomic_load_n(&slot.generation, __ATOMIC_ACQUIRE);
        bool const occ_second = __atomic_load_n(&slot.occupied, __ATOMIC_ACQUIRE);
        if (!occ_second || gen_second != gen_first) {
            return Result<CapEntry, Error>::err(Error::InvalidCapability);
        }
        cur_epoch = __atomic_load_n(&table.group_epochs[snap.rev_group.raw], __ATOMIC_ACQUIRE);
    }

    if (cur_epoch != snap.bound_epoch) {
        return Result<CapEntry, Error>::err(Error::RevokedCapability);
    }

    if (!(snap.owner == caller)) {
        return Result<CapEntry, Error>::err(Error::DomainMismatch);
    }

    if (expected_kind != CapObjectKind::None && snap.kind != expected_kind) {
        return Result<CapEntry, Error>::err(Error::InvalidCapability);
    }

    if ((snap.rights & required_rights) != required_rights) {
        return Result<CapEntry, Error>::err(Error::InsufficientRights);
    }

    return Result<CapEntry, Error>::ok(snap);
}

// Plan root capability creation (used by kernel bootstrap or privileged broker)
[[nodiscard]] constexpr Result<CapMutation, Error> plan_mint_root(
    CapTable const&   table,
    DomainId          owner,
    CapObjectKind     kind,
    u16               rights,
    u64               object_id,
    RevocationGroupId rev_group
) noexcept {
    if (!owner || kind == CapObjectKind::None || rev_group.raw >= MAX_REVOCATION_GROUPS) {
        return Result<CapMutation, Error>::err(Error::InvalidArgument);
    }

    auto free_slot = find_free_slot(table);
    if (free_slot.is_none()) {
        return Result<CapMutation, Error>::err(Error::TableFull);
    }

    u32 const idx        = free_slot.value();
    u32 const next_gen   = table.slots[idx].generation + 1;
    u32 const cur_epoch  = table.group_epochs[rev_group.raw];

    CapEntry entry{};
    entry.occupied    = true;
    entry.generation  = next_gen;
    entry.owner       = owner;
    entry.kind        = kind;
    entry.rights      = rights;
    entry.rev_group   = rev_group;
    entry.bound_epoch = cur_epoch;
    entry.object_id   = object_id;

    CapMutation mut{};
    mut.type         = CapMutation::Type::WriteSlot;
    mut.slot_idx     = idx;
    mut.new_entry    = entry;
    mut.minted_token = CapToken::pack(idx, next_gen, kind, rights);
    return Result<CapMutation, Error>::ok(mut);
}

// Plan capability delegation with strict Monotonic Rights Attenuation
[[nodiscard]] constexpr Result<CapMutation, Error> plan_delegate_attenuated(
    CapTable const& table,
    DomainId        caller,
    CapToken        parent_token,
    DomainId        recipient,
    u16             attenuated_rights
) noexcept {
    if (!recipient || attenuated_rights == CapRights::None) {
        return Result<CapMutation, Error>::err(Error::InvalidArgument);
    }

    auto valid_res = validate_capability(
        table, caller, parent_token, CapObjectKind::None, CapRights::Delegate
    );
    if (valid_res.is_err()) {
        return Result<CapMutation, Error>::err(valid_res.error());
    }

    CapEntry const& parent = valid_res.value();

    // Monotonicity theorem: child rights cannot contain any bit absent from parent!
    if ((attenuated_rights & ~parent.rights) != 0) {
        return Result<CapMutation, Error>::err(Error::InsufficientRights);
    }

    auto free_slot = find_free_slot(table);
    if (free_slot.is_none()) {
        return Result<CapMutation, Error>::err(Error::TableFull);
    }

    u32 const idx      = free_slot.value();
    u32 const next_gen = table.slots[idx].generation + 1;

    CapEntry child{};
    child.occupied    = true;
    child.generation  = next_gen;
    child.owner       = recipient;
    child.kind        = parent.kind;
    child.rights      = attenuated_rights;
    child.rev_group   = parent.rev_group;
    child.bound_epoch = parent.bound_epoch;
    child.object_id   = parent.object_id;

    CapMutation mut{};
    mut.type         = CapMutation::Type::WriteSlot;
    mut.slot_idx     = idx;
    mut.new_entry    = child;
    mut.minted_token = CapToken::pack(idx, next_gen, child.kind, attenuated_rights);
    return Result<CapMutation, Error>::ok(mut);
}

// Surgical O(1) Single-Delegate Revocation (zero collateral blast radius to siblings!)
[[nodiscard]] constexpr Result<CapMutation, Error> plan_revoke_single(
    CapTable const& table,
    DomainId        caller,
    CapToken        revoke_authority_token,
    u32             target_slot_idx
) noexcept {
    auto valid_res = validate_capability(
        table, caller, revoke_authority_token, CapObjectKind::None, CapRights::Revoke
    );
    if (valid_res.is_err()) {
        return Result<CapMutation, Error>::err(valid_res.error());
    }
    if (!is_slot_live(table, target_slot_idx)) {
        return Result<CapMutation, Error>::err(Error::NotFound);
    }
    if (!(table.slots[target_slot_idx].rev_group == valid_res.value().rev_group)) {
        return Result<CapMutation, Error>::err(Error::InsufficientRights);
    }

    CapMutation mut{};
    mut.type     = CapMutation::Type::ClearSlot;
    mut.slot_idx = target_slot_idx;
    return Result<CapMutation, Error>::ok(mut);
}

// Emergency O(1) Transitive Lineage Revocation: invalidates entire group in 1 increment!
[[nodiscard]] constexpr Result<CapMutation, Error> plan_revoke_lineage(
    CapTable const& table,
    DomainId        caller,
    CapToken        revoke_authority_token
) noexcept {
    auto valid_res = validate_capability(
        table, caller, revoke_authority_token, CapObjectKind::None, CapRights::Revoke
    );
    if (valid_res.is_err()) {
        return Result<CapMutation, Error>::err(valid_res.error());
    }

    CapMutation mut{};
    mut.type         = CapMutation::Type::BumpGroupEpoch;
    mut.target_group = valid_res.value().rev_group;
    return Result<CapMutation, Error>::ok(mut);
}

// Deterministic in-place application of a `CapMutation` (SMP release-ordered!)
constexpr void apply_mutation(CapTable& table, CapMutation const& mut) noexcept {
    switch (mut.type) {
        case CapMutation::Type::None:
            break;
        case CapMutation::Type::WriteSlot:
            if (mut.slot_idx > 0 && mut.slot_idx < MAX_CAP_SLOTS) {
                if consteval {
                    table.slots[mut.slot_idx] = mut.new_entry;
                } else {
                    CapEntry& dst = table.slots[mut.slot_idx];
                    // Mark unoccupied & invalidate generation (0) before touching payload fields!
                    __atomic_store_n(&dst.occupied, false, __ATOMIC_RELEASE);
                    __atomic_store_n(&dst.generation, 0u, __ATOMIC_RELEASE);
                    __atomic_thread_fence(__ATOMIC_RELEASE);
                    CapObjectKind kind_val = mut.new_entry.kind;
                    __atomic_store_n(&dst.owner.raw, mut.new_entry.owner.raw, __ATOMIC_RELAXED);
                    __atomic_store(&dst.kind, &kind_val, __ATOMIC_RELAXED);
                    __atomic_store_n(&dst.rights, mut.new_entry.rights, __ATOMIC_RELAXED);
                    __atomic_store_n(&dst.rev_group.raw, mut.new_entry.rev_group.raw, __ATOMIC_RELAXED);
                    __atomic_store_n(&dst.bound_epoch, mut.new_entry.bound_epoch, __ATOMIC_RELAXED);
                    __atomic_store_n(&dst.object_id, mut.new_entry.object_id, __ATOMIC_RELAXED);
                    __atomic_store_n(&dst.generation, mut.new_entry.generation, __ATOMIC_RELEASE);
                    __atomic_store_n(&dst.occupied, mut.new_entry.occupied, __ATOMIC_RELEASE);
                }
            }
            break;
        case CapMutation::Type::ClearSlot:
            if (mut.slot_idx > 0 && mut.slot_idx < MAX_CAP_SLOTS) {
                if consteval {
                    table.slots[mut.slot_idx].occupied = false;
                    table.slots[mut.slot_idx].generation += 1;
                } else {
                    CapEntry& dst = table.slots[mut.slot_idx];
                    __atomic_store_n(&dst.occupied, false, __ATOMIC_RELEASE);
                    (void)__atomic_fetch_add(&dst.generation, 1u, __ATOMIC_ACQ_REL);
                }
            }
            break;
        case CapMutation::Type::BumpGroupEpoch:
            if (mut.target_group.raw < MAX_REVOCATION_GROUPS) {
                if consteval {
                    table.group_epochs[mut.target_group.raw] += 1;
                } else {
                    (void)__atomic_fetch_add(
                        &table.group_epochs[mut.target_group.raw], 1u, __ATOMIC_ACQ_REL
                    );
                }
            }
            break;
    }
}

} // namespace mucore::core::cap
