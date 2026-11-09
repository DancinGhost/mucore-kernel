// ============================================================================
// μCore (mucore-kernel) — Compile-Time `static_assert` Kernel Proofs (v2)
// ============================================================================
// Proves all core invariants — including the Four-Lineage Synthesis (Zircon
// Ports, Windows NT DMA Quarantine, Plan 9 Union Namespaces, and L4-MCS Async
// CBS Context Donation) — inside the C++23 compiler at build time!
// ============================================================================

#include "mucore/core/dispatcher.hpp"

namespace mucore::proofs {

using namespace mucore::core;

// ----------------------------------------------------------------------------
// Proof 1: Monotonic Capability Attenuation, Surgical + Epoch Revocation
//          & Automatic Zombie Slot Reclamation (> MAX_CAP_SLOTS churn!)
// ----------------------------------------------------------------------------
consteval bool prove_capability_invariants() {
    cap::CapTable table{};
    DomainId const broker{1};
    DomainId const driver{2};
    DomainId const sibling{3};

    auto root_mut = cap::plan_mint_root(
        table, broker, cap::CapObjectKind::FluxConduit,
        cap::CapRights::Read | cap::CapRights::Write | cap::CapRights::Delegate | cap::CapRights::Revoke,
        42ULL, cap::RevocationGroupId{7}
    );
    if (root_mut.is_err()) return false;
    cap::apply_mutation(table, root_mut.value());
    cap::CapToken const root_tok = root_mut.value().minted_token;

    // Mint two sibling delegates (`driver` and `sibling`), applying each pure transition in turn
    auto drv_mut = cap::plan_delegate_attenuated(table, broker, root_tok, driver, cap::CapRights::Read);
    if (drv_mut.is_err()) return false;
    cap::apply_mutation(table, drv_mut.value());

    auto sib_mut = cap::plan_delegate_attenuated(table, broker, root_tok, sibling, cap::CapRights::Read);
    if (sib_mut.is_err()) return false;
    cap::apply_mutation(table, sib_mut.value());

    // Surgical O(1) revocation kills `driver` WITHOUT harming `sibling`!
    auto surg = cap::plan_revoke_single(table, broker, root_tok, drv_mut.value().slot_idx);
    if (surg.is_err()) return false;
    cap::apply_mutation(table, surg.value());

    if (cap::validate_capability(table, driver, drv_mut.value().minted_token,
                                 cap::CapObjectKind::FluxConduit, cap::CapRights::Read).is_ok()) {
        return false;
    }
    if (cap::validate_capability(table, sibling, sib_mut.value().minted_token,
                                 cap::CapObjectKind::FluxConduit, cap::CapRights::Read).is_err()) {
        return false;
    }

    // Churn test: mint + epoch-revoke 400 times (> MAX_CAP_SLOTS = 256!) to prove zero zombie leak!
    for (u32 iter = 0; iter < 400; ++iter) {
        auto m = cap::plan_mint_root(
            table, broker, cap::CapObjectKind::FluxConduit,
            cap::CapRights::Read | cap::CapRights::Revoke, 99ULL, cap::RevocationGroupId{8}
        );
        if (m.is_err()) return false; // Would fail at iter ~250 if zombie slots leaked!
        cap::apply_mutation(table, m.value());

        auto r = cap::plan_revoke_lineage(table, broker, m.value().minted_token);
        if (r.is_err()) return false;
        cap::apply_mutation(table, r.value());
    }

    return true;
}

static_assert(prove_capability_invariants(),
              "Compile-time proof failed: Capability revocation or zombie reclamation broken!");

// ----------------------------------------------------------------------------
// Proof 2: Kineticlet Static Verifier, Spectre-v1 `nospec` & Dynamic Indexing
// ----------------------------------------------------------------------------
consteval bool prove_kineticlet_and_nospec() {
    // Verify branchless Spectre-v1 ALU clamp across edge values including UINT64_MAX!
    if (nospec_index_pow2(5ULL, 16ULL) != 5ULL) return false;
    if (nospec_index_pow2(16ULL, 16ULL) != 0ULL) return false;
    if (nospec_index_pow2(0xFFFF'FFFF'FFFF'FFFFULL, 16ULL) != 0ULL) return false;

    // Verify dynamic register-indexed Arena lookup enforces `CapRights::Read` & clamps OOB!
    kinetic::KineticProgram prog{};
    prog.insns[0] = kinetic::dsl::load_arena_idx(0, 1); // R0 = arena[nospec(R1)]
    prog.insns[1] = kinetic::dsl::ret(kinetic::ReturnVerdict::CompleteFastPath);
    prog.len      = 2;

    if (kinetic::verify_program(prog, cap::CapRights::ExecuteRing0).error() !=
        Error::InsufficientRights) {
        return false;
    }
    auto ok = kinetic::verify_program(prog, cap::CapRights::ExecuteRing0 | cap::CapRights::Read);
    if (ok.is_err() || ok.value().wcet_ns != 8u) return false;

    u64 state[4]{};
    u64 arena[16]{};
    arena[0] = 777ULL;
    arena[3] = 999ULL;

    // Valid dynamic index 3 -> 999
    auto r1 = kinetic::execute_verified(prog, kinetic::KineticInput{0, 3, 0, 0}, state, arena);
    if (r1.is_err() || r1.value().return_value != 999ULL) return false;

    // Out-of-bounds dynamic index 9999 -> nospec clamps safely to slot 0 (777)!
    auto r2 = kinetic::execute_verified(prog, kinetic::KineticInput{0, 9999, 0, 0}, state, arena);
    return r2.is_ok() && r2.value().return_value == 777ULL;
}

static_assert(prove_kineticlet_and_nospec(),
              "Compile-time proof failed: Kineticlet verifier or Spectre-v1 nospec broken!");

// ----------------------------------------------------------------------------
// Proof 3: Zircon `FluxPort` O(1) Fan-In Readiness Aggregator
// ----------------------------------------------------------------------------
consteval bool prove_zircon_flux_port() {
    port::FluxPortState p{};
    p.active = true;
    p.id     = PortId{1};
    p.owner  = DomainId{1};

    // Bind 32 client conduits to 1 server port
    for (u32 i = 1; i <= 32; ++i) {
        auto b = port::bind_conduit_to_port(p, ConduitId{i}, 1000ULL + i);
        if (b.is_err()) return false;
    }

    // Signal normal traffic on slot 20, then Urgent RT on slot 29
    (void)port::signal_port_slot(p, 20, false);
    (void)port::signal_port_slot(p, 20, false); // Idempotent burst coalescing!
    (void)port::signal_port_slot(p, 29, true);

    // First pop MUST extract Urgent-RT slot 29 in O(1) without scanning slots 0..28!
    auto first = port::pop_ready_conduit(p);
    if (first.is_none() || !first.value().is_urgent_rt || first.value().conduit.raw != 30u) {
        return false;
    }

    // Second pop extracts normal slot 20; third pop sees empty port!
    auto second = port::pop_ready_conduit(p);
    if (second.is_none() || second.value().conduit.raw != 21u) return false;

    return !port::has_pending(p);
}

static_assert(prove_zircon_flux_port(),
              "Compile-time proof failed: Zircon FluxPort O(1) aggregator broken!");

// ----------------------------------------------------------------------------
// Proof 4: Plan 9 Per-Domain Capability Namespaces & Union Interposition
// ----------------------------------------------------------------------------
consteval bool prove_plan9_namespaces() {
    cap::CapTable caps{};
    ns::NamespaceTable nstab{};
    DomainId const app{5};

    // Mint direct NVMe conduit cap WITH `FastPromote` (Group 1)
    auto nvme_cap = cap::plan_mint_root(
        caps, app, cap::CapObjectKind::FluxConduit,
        cap::CapRights::Read | cap::CapRights::Write | cap::CapRights::FastPromote,
        10ULL, cap::RevocationGroupId{1}
    );
    cap::apply_mutation(caps, nvme_cap.value());

    // Mint tracing proxy conduit cap WITHOUT `FastPromote` (Group 2, revocable!)
    auto trace_cap = cap::plan_mint_root(
        caps, app, cap::CapObjectKind::FluxConduit,
        cap::CapRights::Read | cap::CapRights::Write | cap::CapRights::Revoke,
        99ULL, cap::RevocationGroupId{2}
    );
    cap::apply_mutation(caps, trace_cap.value());

    // Bind direct NVMe at `/dev/nvme0`
    if (ns::bind_capability_path(nstab, caps, app, "/dev/nvme0",
                                 nvme_cap.value().minted_token, ns::MountOrder::Replace).is_err()) {
        return false;
    }

    auto direct = ns::resolve_path(nstab, caps, app, "/dev/nvme0/ns1");
    if (direct.is_err() || !direct.value().can_promote_hot || direct.value().conduit_id.raw != 10u) {
        return false;
    }

    // Interpose tracing filter via Plan 9 `MountOrder::Before`!
    if (ns::bind_capability_path(nstab, caps, app, "/dev/nvme0",
                                 trace_cap.value().minted_token, ns::MountOrder::Before).is_err()) {
        return false;
    }

    auto interposed = ns::resolve_path(nstab, caps, app, "/dev/nvme0/ns1");
    if (interposed.is_err() || interposed.value().can_promote_hot ||
        interposed.value().conduit_id.raw != 99u || interposed.value().union_alternatives != 1u) {
        return false;
    }

    // Revoke tracing filter capability -> union automatically falls back to direct Hot NVMe!
    auto rev = cap::plan_revoke_lineage(caps, app, trace_cap.value().minted_token);
    cap::apply_mutation(caps, rev.value());

    auto fallback = ns::resolve_path(nstab, caps, app, "/dev/nvme0/ns1");
    return fallback.is_ok() && fallback.value().can_promote_hot &&
           fallback.value().conduit_id.raw == 10u;
}

static_assert(prove_plan9_namespaces(),
              "Compile-time proof failed: Plan 9 capability namespace union broken!");

// ----------------------------------------------------------------------------
// Proof 5: Windows NT DMA Crash Quarantine & Co-Located Filter Stack
// ----------------------------------------------------------------------------
consteval bool prove_nt_dma_quarantine() {
    mm::MemoryTable mem{};
    DomainId const client{1};
    DomainId const driver{2};

    auto ar = mm::create_grant_arena(mem, ArenaId{1}, client, 4, true, PkeyId{3});
    if (ar.is_err() || mem.pool.allocated_frames != 4u) return false;

    // Transfer & MPK-seal to driver, then begin active PCIe DMA
    if (mm::transfer_arena_lease(mem, ArenaId{1}, client, driver, true).is_err()) return false;
    if (mm::begin_arena_dma(mem, ArenaId{1}, driver).is_err()) return false;

    // Client crashes mid-DMA! Frames MUST be quarantined (NOT freed to PhysPool!)
    u32 const q = mm::quarantine_domain_arenas(mem, client);
    if (q != 1u || mem.pool.allocated_frames != 4u) return false;

    // Premature destroy attempt MUST fail with `DmaInFlightQuarantined`
    if (mm::destroy_grant_arena(mem, ArenaId{1}).error() != Error::DmaInFlightQuarantined) {
        return false;
    }

    // Once IOMMU/driver completes DMA drain, all 4 frames are safely reclaimed!
    auto drained = mm::complete_arena_dma_op(mem, ArenaId{1});
    return drained.is_ok() && drained.value() && (mem.pool.allocated_frames == 0u);
}

static_assert(prove_nt_dma_quarantine(),
              "Compile-time proof failed: NT IOMMU DMA crash quarantine broken!");

// ----------------------------------------------------------------------------
// Proof 6: L4-MCS Asynchronous CBS Deadline & Budget Donation
// ----------------------------------------------------------------------------
consteval bool prove_l4_mcs_async_donation() {
    sched::SchedTable st{};

    // Urgent Robotics Thread 1: 200us budget, 500us deadline!
    (void)sched::spawn_thread(
        st, ThreadId{1}, DomainId{1}, sched::SchedClass::IsochronousRt,
        sched::RtParams{200'000ULL, 500'000ULL}, TickNs{0}
    );
    // Medium RT Thread 2: 200us budget, 2000us deadline
    (void)sched::spawn_thread(
        st, ThreadId{2}, DomainId{2}, sched::SchedClass::IsochronousRt,
        sched::RtParams{200'000ULL, 2'000'000ULL}, TickNs{0}
    );
    // Userspace Driver Worker Thread 3: Tier-1 non-RT `AsyncThroughput` (normally lower than Thread 2!)
    (void)sched::spawn_thread(
        st, ThreadId{3}, DomainId{3}, sched::SchedClass::AsyncThroughput,
        sched::RtParams{}, TickNs{0}
    );

    // Without donation, Thread 2 (RT 2ms) would beat Thread 3 (non-RT) -> Priority Inversion!
    // Donate Thread 1's 500us deadline & 200us budget to Driver Worker Thread 3:
    if (sched::donate_cbs_context(st, ThreadId{1}, ThreadId{3}).is_err()) return false;

    // EDF MUST now pick Driver Worker Thread 3 FIRST (inherited 500us < 2000us)!
    auto dec0 = sched::schedule_at(st, TickNs{0});
    if (!(dec0.next_thread == ThreadId{3})) return false;

    // Driver runs for 50us (`t = 50,000ns`) and returns borrowed context
    (void)sched::schedule_at(st, TickNs{50'000ULL});
    auto ret = sched::return_cbs_context(st, ThreadId{3});
    if (ret.is_err() || !(ret.value() == ThreadId{1})) return false;

    // Verify exact CBS budget conservation: Thread 1 gets back 200us - 50us = 150us!
    u32 const t1_slot = sched::find_thread_slot(st, ThreadId{1}).value();
    if (st.threads[t1_slot].remaining_budget_ns != 150'000ULL) return false;

    auto dec1 = sched::schedule_at(st, TickNs{50'000ULL});
    return dec1.next_thread == ThreadId{1};
}

static_assert(prove_l4_mcs_async_donation(),
              "Compile-time proof failed: L4-MCS async CBS context donation broken!");

} // namespace mucore::proofs
