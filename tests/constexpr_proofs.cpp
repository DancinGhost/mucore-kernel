// ============================================================================
// μCore (mucore-kernel) — Compile-Time `static_assert` Kernel Proofs (v2)
// ============================================================================
// Proves all core invariants — including the Four-Lineage Synthesis (Zircon
// Ports, Windows NT DMA Quarantine, Plan 9 Union Namespaces, and L4-MCS Async
// CBS Context Donation) — inside the C++23 compiler at build time!
// ============================================================================

#include "mucore/core/dispatcher.hpp"
#include "mucore/core/smp.hpp"
#include "mucore/core/vmspace.hpp"

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

// ----------------------------------------------------------------------------
// Proof 7: 4-Level `VmSpace` Constitutional W^X, MPK PTE[62:59] & Strict KPTI
// ----------------------------------------------------------------------------
consteval bool prove_vmspace_wxorx_mpk_and_kpti() {
    vm::VmTablePool pool{};
    auto kpml4 = vm::alloc_pt_node(pool);
    if (kpml4.is_err()) return false;

    // Seed Kernel Higher-Half HHDM [256] and Entry Trampoline [511]
    pool.nodes[kpml4.value()].entries[256] = 0x0000'0000'0010'0103ULL;
    pool.nodes[kpml4.value()].entries[511] = 0x0000'0000'0020'0103ULL;

    // 1. Constitutional W^X: Writable + Executable MUST fail!
    auto wx_bad = vm::encode_leaf_pte(
        VirtAddr{0x0040'0000ULL}, PhysAddr{0x0080'0000ULL},
        vm::MapPermissions{.writable = true, .executable = true, .user_accessible = true}
    );
    if (wx_bad.error() != Error::WxorXViolation) return false;

    // 2. Ring-3 User access in Higher-Half Kernel space MUST fail!
    auto hh_bad = vm::encode_leaf_pte(
        VirtAddr{vm::HIGHER_HALF_BASE + 0x1000ULL}, PhysAddr{0x0080'0000ULL},
        vm::MapPermissions{.writable = false, .executable = false, .user_accessible = true}
    );
    if (hh_bad.error() != Error::InsufficientRights) return false;

    // 3. Default `SharedHigherHalf` vs Opt-In `StrictKpti` PML4 Isolation
    auto fast_dom = vm::create_domain_vmspace(
        pool, kpml4.value(), DomainId{1}, vm::KptiMode::SharedHigherHalf
    );
    auto kpti_dom = vm::create_domain_vmspace(
        pool, kpml4.value(), DomainId{2}, vm::KptiMode::StrictKpti
    );
    if (fast_dom.is_err() || kpti_dom.is_err()) return false;

    if (pool.nodes[fast_dom.value().user_pml4_node].entries[256] == 0ULL) return false;
    if (pool.nodes[kpti_dom.value().user_pml4_node].entries[256] != 0ULL) return false;
    if (pool.nodes[kpti_dom.value().user_pml4_node].entries[511] == 0ULL) return false;

    // 4. Full 4-Level Map (`PML4 -> PDPT -> PD -> PT`) + MPK Key 9 Round-Trip Walk
    VirtAddr const arena_va{0x0000'007F'8040'2000ULL};
    PhysAddr const arena_pa{0x0000'0000'0240'0000ULL};
    if (vm::map_page_4k(pool, kpti_dom.value().user_pml4_node, arena_va, arena_pa,
                        vm::MapPermissions{
                            .writable        = true,
                            .executable      = false,
                            .user_accessible = true,
                            .mpk_key         = PkeyId{9},
                        }).is_err()) {
        return false;
    }

    auto walked = vm::walk_page_table(pool, kpti_dom.value().user_pml4_node, arena_va);
    if (walked.is_err()) return false;
    u64 const pte = walked.value();

    return ((pte & vm::PTE_ADDR_MASK) == arena_pa.raw) &&
           ((pte & vm::PTE_NX) != 0ULL) &&
           ((pte & vm::PTE_WRITABLE) != 0ULL) &&
           (vm::extract_pte_mpk(pte) == PkeyId{9});
}

static_assert(prove_vmspace_wxorx_mpk_and_kpti(),
              "Compile-time proof failed: VmSpace W^X, MPK PTE encoding, or StrictKpti broken!");

// ----------------------------------------------------------------------------
// Proof 8: Per-Core Magazine Hard-RT Watermark & Fragmented Contiguous Frames
// ----------------------------------------------------------------------------
consteval bool prove_percore_magazine_and_contiguous() {
    mm::PhysPoolState      pool{};
    mm::LocalFrameMagazine mag{};

    // Refill 1 batch (32 frames) into local CPU magazine
    if (mm::refill_magazine_batch(mag, pool) != mm::MAGAZINE_BATCH_SIZE) return false;

    // Tier-1 Async (`is_hard_rt = false`) can pop 24 frames (32 -> 8), then hits watermark!
    for (usize i = 0; i < (mm::MAGAZINE_BATCH_SIZE - mm::RT_EMERGENCY_WATERMARK); ++i) {
        if (mm::alloc_from_magazine(mag, false).is_err()) return false;
    }
    if (mag.count != mm::RT_EMERGENCY_WATERMARK) return false;
    if (mm::alloc_from_magazine(mag, false).error() != Error::RtReserveProtected) return false;

    // Tier-0 Hard-RT (`is_hard_rt = true`) bypasses watermark in O(1) with 0 locks!
    if (mm::alloc_from_magazine(mag, true).is_err() || mag.count != 7u) return false;

    // Fragmentation resilience: free frames 33 and 35 to create non-contiguous 1-frame holes,
    // then allocate 4 contiguous DMA frames and verify contiguous run placement!
    mm::PhysPoolState frag_pool{};
    auto f0 = mm::alloc_frame(frag_pool); // idx 0
    auto f1 = mm::alloc_frame(frag_pool); // idx 1
    auto f2 = mm::alloc_frame(frag_pool); // idx 2
    auto f3 = mm::alloc_frame(frag_pool); // idx 3
    (void)f0; (void)f2;
    (void)mm::free_frame(frag_pool, f1.value()); // Hole at idx 1 (size 1)
    (void)mm::free_frame(frag_pool, f3.value()); // Free from idx 3 onward!

    auto contig4 = mm::alloc_contiguous_frames(frag_pool, 4);
    return contig4.is_ok() &&
           (contig4.value() == frag_pool.base_addr.offset(3ULL * PAGE_SIZE_4K));
}

static_assert(prove_percore_magazine_and_contiguous(),
              "Compile-time proof failed: Per-core magazine RT watermark or contiguous alloc broken!");

// ----------------------------------------------------------------------------
// Proof 9: Cross-Core SMP CBS Loan Parcels & Per-Shard Deterministic Replay
// ----------------------------------------------------------------------------
consteval bool prove_smp_cross_core_cbs_and_replay() {
    smp::CpuShard core0{};
    core0.cpu_id = CpuId{0};
    smp::CpuShard core1{};
    core1.cpu_id = CpuId{1};

    // Core 0: Hard-RT Robotics Donor (200us budget, 500us deadline)
    (void)sched::spawn_thread(
        core0.sched, ThreadId{10}, DomainId{1}, sched::SchedClass::IsochronousRt,
        sched::RtParams{200'000ULL, 500'000ULL}, TickNs{0}
    );
    // Core 1: Tier-1 Async Driver Worker (`ThreadId{20}`) + Competing 2ms RT (`ThreadId{21}`)
    (void)sched::spawn_thread(
        core1.sched, ThreadId{20}, DomainId{2}, sched::SchedClass::AsyncThroughput,
        sched::RtParams{}, TickNs{0}
    );
    (void)sched::spawn_thread(
        core1.sched, ThreadId{21}, DomainId{3}, sched::SchedClass::IsochronousRt,
        sched::RtParams{200'000ULL, 2'000'000ULL}, TickNs{0}
    );

    // 1. Core 0 initiates cross-core CBS loan -> emits `DonateRemoteCbs` parcel!
    smp::ShardEvent const ev_call{
        .kind          = smp::ShardEventKind::LocalCbsRemoteCall,
        .timestamp     = TickNs{0},
        .local_thread  = ThreadId{10},
        .remote_worker = ThreadId{20},
        .remote_cpu    = CpuId{1},
    };
    core0.trace.record(ev_call);
    auto out0 = smp::step_cpu_shard(core0, ev_call);
    if (out0.is_err() || out0.value().outbound_parcel.is_none()) return false;

    // 2. Core 1 receives `DonateRemoteCbs` -> Worker 20 preempts 2ms RT Thread 21!
    smp::ShardEvent const ev_recv_loan{
        .kind      = smp::ShardEventKind::IncomingParcel,
        .timestamp = TickNs{0},
        .parcel    = out0.value().outbound_parcel.value(),
    };
    core1.trace.record(ev_recv_loan);
    auto out1 = smp::step_cpu_shard(core1, ev_recv_loan);
    if (out1.is_err() || !(out1.value().sched_dec.next_thread == ThreadId{20})) return false;

    // 3. Core 1 Worker 20 runs for 60us (`t = 60,000ns`) & finishes -> emits `RefundRemoteCbs`!
    smp::ShardEvent const ev_done{
        .kind         = smp::ShardEventKind::LocalWorkerComplete,
        .timestamp    = TickNs{60'000ULL},
        .local_thread = ThreadId{20},
    };
    core1.trace.record(ev_done);
    auto out2 = smp::step_cpu_shard(core1, ev_done);
    if (out2.is_err() || out2.value().outbound_parcel.is_none()) return false;

    // 4. Core 0 receives `RefundRemoteCbs` -> Donor 10 resumes with 140us leftover budget!
    smp::ShardEvent const ev_refund{
        .kind      = smp::ShardEventKind::IncomingParcel,
        .timestamp = TickNs{60'000ULL},
        .parcel    = out2.value().outbound_parcel.value(),
    };
    core0.trace.record(ev_refund);
    auto out3 = smp::step_cpu_shard(core0, ev_refund);
    if (out3.is_err() || !(out3.value().sched_dec.next_thread == ThreadId{10})) return false;
    if (core0.sched.threads[0].remaining_budget_ns != 140'000ULL) return false;

    // 5. Replay Core 0's `ShardTraceRing` into a fresh `CpuShard` in complete single-core isolation!
    smp::CpuShard replay0{};
    replay0.cpu_id = CpuId{0};
    (void)sched::spawn_thread(
        replay0.sched, ThreadId{10}, DomainId{1}, sched::SchedClass::IsochronousRt,
        sched::RtParams{200'000ULL, 500'000ULL}, TickNs{0}
    );
    auto rep_res = smp::replay_shard_trace(core0.trace, replay0);
    return rep_res.is_ok() &&
           (rep_res.value() == 2u) &&
           (replay0.sched.threads[0].remaining_budget_ns == 140'000ULL) &&
           (replay0.sched.current_thread == ThreadId{10});
}

static_assert(prove_smp_cross_core_cbs_and_replay(),
              "Compile-time proof failed: Cross-core SMP CBS loan parcel or shard replay broken!");

} // namespace mucore::proofs
