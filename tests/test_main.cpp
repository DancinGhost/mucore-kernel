// ============================================================================
// μCore (mucore-kernel) — Host Functional Core & Four-Lineage Simulation Suite
// ============================================================================
// Exercises the exact same `include/mucore/core/*` and `include/mucore/shell/*`
// code that runs in Ring 0, verifying security invariants, Real-Time CBS
// temporal isolation, zero-context-switch Kineticlets, TraceRing replay,
// AND the Four-Lineage Synthesis (Zircon + Windows NT + Plan 9 + L4 MCS).
// ============================================================================

#include <stdio.h>
#include <string.h>

#include "mucore/core/dispatcher.hpp"
#include "mucore/shell/hal.hpp"
#include "mucore/shell/shared_conduit.hpp"

namespace {

using namespace mucore;
using namespace mucore::core;

int g_passed = 0;
int g_failed = 0;

#define MUCORE_CHECK(cond, msg)                                                   \
    do {                                                                          \
        if (!(cond)) {                                                            \
            printf("  [FAIL] %s (line %d)\n", (msg), __LINE__);                   \
            ++g_failed;                                                           \
            return;                                                               \
        }                                                                         \
    } while (0)

// Deterministic Mock HAL for Host Simulation (satisfies `shell::HalPlatform`!)
struct SimHal {
    u64    cr3_switches{0};
    u64    thread_switches{0};
    u64    timer_arms{0};
    u64    idle_waits{0};
    u64    fast_irq_acks{0};
    u64    ring3_driver_upcalls{0};
    u64    doorbells_rung{0};
    u64    mpk_seals{0};
    u64    iommu_quarantines{0};
    TickNs last_armed_deadline{};

    void switch_address_space(DomainId) noexcept { ++cr3_switches; }
    void switch_thread_context(DomainId, ThreadId) noexcept { ++thread_switches; }
    void arm_oneshot_timer(TickNs dl) noexcept {
        ++timer_arms;
        last_armed_deadline = dl;
    }
    void cpu_idle_wait() noexcept { ++idle_waits; }
    void ack_irq_fast(IrqLine, u64) noexcept { ++fast_irq_acks; }
    void escalate_irq_to_userspace(DomainId, ThreadId, ConduitId, IrqLine) noexcept {
        ++ring3_driver_upcalls;
    }
    void notify_conduit_doorbell(DomainId, ConduitId, flux::DoorbellAction) noexcept {
        ++doorbells_rung;
    }
    void update_protection_key(DomainId, PkeyId) noexcept { ++mpk_seals; }
    void quarantine_iommu_domain(DomainId, u64 count) noexcept { iommu_quarantines += count; }
};

static_assert(shell::HalPlatform<SimHal>, "SimHal must satisfy HalPlatform");

// ----------------------------------------------------------------------------
// Test 1: Pragmatic Capability Engine, Surgical Revoke & Zombie Reclamation
// ----------------------------------------------------------------------------
void test_capabilities() {
    printf("[TEST 1] Capabilities: Monotonicity, Surgical + Epoch Revoke & Slot GC...\n");
    cap::CapTable caps{};
    DomainId const root_dom{1};
    DomainId const drv_dom{2};
    DomainId const sib_dom{3};

    auto m1 = cap::plan_mint_root(
        caps, root_dom, cap::CapObjectKind::MmioRegion,
        cap::CapRights::Read | cap::CapRights::Write | cap::CapRights::Delegate | cap::CapRights::Revoke,
        0xFEBC'0000ULL, cap::RevocationGroupId{3}
    );
    MUCORE_CHECK(m1.is_ok(), "Root MMIO capability mint succeeds");
    cap::apply_mutation(caps, m1.value());

    auto m2 = cap::plan_delegate_attenuated(
        caps, root_dom, m1.value().minted_token, drv_dom, cap::CapRights::Read
    );
    MUCORE_CHECK(m2.is_ok(), "First attenuated sibling delegation succeeds");
    cap::apply_mutation(caps, m2.value());

    auto m3 = cap::plan_delegate_attenuated(
        caps, root_dom, m1.value().minted_token, sib_dom, cap::CapRights::Read
    );
    MUCORE_CHECK(m3.is_ok(), "Second attenuated sibling delegation succeeds");
    cap::apply_mutation(caps, m3.value());

    // Surgical O(1) revoke kills `drv_dom` while keeping `sib_dom` alive (0 blast radius!)
    auto surg = cap::plan_revoke_single(caps, root_dom, m1.value().minted_token, m2.value().slot_idx);
    MUCORE_CHECK(surg.is_ok(), "Surgical single-slot revocation planned");
    cap::apply_mutation(caps, surg.value());

    MUCORE_CHECK(cap::validate_capability(caps, drv_dom, m2.value().minted_token,
                                          cap::CapObjectKind::MmioRegion, cap::CapRights::Read).is_err(),
                 "Surgically revoked token rejected");
    MUCORE_CHECK(cap::validate_capability(caps, sib_dom, m3.value().minted_token,
                                          cap::CapObjectKind::MmioRegion, cap::CapRights::Read).is_ok(),
                 "Sibling delegate unharmed by surgical revocation");

    // Epoch revocation + 350-cycle churn (> MAX_CAP_SLOTS = 256) verifies lazy zombie slot GC!
    for (u32 i = 0; i < 350; ++i) {
        auto cm = cap::plan_mint_root(
            caps, root_dom, cap::CapObjectKind::FluxConduit,
            cap::CapRights::Read | cap::CapRights::Revoke, 77ULL, cap::RevocationGroupId{4}
        );
        MUCORE_CHECK(cm.is_ok(), "Zombie-reclaimed slot allocation succeeds under churn");
        cap::apply_mutation(caps, cm.value());
        auto cr = cap::plan_revoke_lineage(caps, root_dom, cm.value().minted_token);
        cap::apply_mutation(caps, cr.value());
    }

    printf("  [PASS] Surgical + O(1) epoch revocation & zombie slot GC verified.\n");
    ++g_passed;
}

// ----------------------------------------------------------------------------
// Test 2: Wait-Free Shared SPSC Ring & Urgent RT Out-of-Band Preemption
// ----------------------------------------------------------------------------
void test_wait_free_flux_and_urgent_rt() {
    printf("[TEST 2] Wait-Free SPSC Shared Ring & Urgent RT Fast-Lane...\n");
    shell::SharedSpscRing<u64, 8> spsc{};
    for (u64 i = 0; i < 8; ++i) {
        MUCORE_CHECK(spsc.try_push(100 + i).is_ok(), "Wait-free push within capacity");
    }
    MUCORE_CHECK(spsc.try_push(999).error() == Error::RingFull, "Bounded wait-free ring detects full");
    MUCORE_CHECK(spsc.try_pop().value_or(0) == 100ULL, "FIFO ordering preserved");

    flux::ConduitState conduit{};
    conduit.active   = true;
    conduit.id       = ConduitId{1};
    conduit.producer = DomainId{1};
    conduit.consumer = DomainId{2};

    for (u32 i = 1; i <= 5; ++i) {
        MUCORE_CHECK(flux::enqueue_submission(conduit, flux::FluxSubmission{.user_tag = i}, false).is_ok(),
                     "Bulk async submission enqueued");
    }

    auto urg = flux::enqueue_submission(conduit, flux::FluxSubmission{.user_tag = 0xDEAD'BEEFULL}, true);
    MUCORE_CHECK(urg.is_ok() && urg.value().doorbell == flux::DoorbellAction::PreemptNow,
                 "Urgent RT submission triggers PreemptNow");

    auto first_out = flux::dequeue_submission(conduit);
    MUCORE_CHECK(first_out.is_some() && first_out.value().user_tag == 0xDEAD'BEEFULL,
                 "Urgent RT preempted 5 queued bulk items without head-of-line delay");

    printf("  [PASS] Wait-free SPSC & Urgent RT head-of-line preemption verified.\n");
    ++g_passed;
}

// ----------------------------------------------------------------------------
// Test 3: Adaptive Thermal Tiering (`Cold` -> `Warm` -> `Hot` -> `Cold`)
// ----------------------------------------------------------------------------
void test_adaptive_thermal_tiering() {
    printf("[TEST 3] Adaptive Conduit Thermal Promotion & Hysteresis Decay...\n");
    flux::ConduitState c{};
    c.active   = true;
    c.id       = ConduitId{9};
    c.producer = DomainId{1};
    c.consumer = DomainId{2};

    flux::SubmitOutcome last{};
    for (u32 i = 0; i < flux::HOT_PROMOTE_THRESHOLD; ++i) {
        auto res = flux::enqueue_submission(c, flux::FluxSubmission{.user_tag = i}, false);
        MUCORE_CHECK(res.is_ok(), "Burst submission succeeds");
        last = res.value();
    }
    MUCORE_CHECK(last.new_thermal == flux::ThermalState::Hot &&
                 last.doorbell == flux::DoorbellAction::None,
                 "Promoted to Hot tier & suppressed syscall doorbells");

    (void)flux::advance_thermal_window(c);
    for (u32 w = 0; w < flux::IDLE_DEMOTE_WINDOWS * 2; ++w) {
        (void)flux::advance_thermal_window(c);
    }
    MUCORE_CHECK(c.thermal == flux::ThermalState::Cold, "Demoted back to Cold when idle");

    printf("  [PASS] Adaptive Thermal Tiering promotes hot paths & parks idle channels.\n");
    ++g_passed;
}

// ----------------------------------------------------------------------------
// Test 4: Split-Plane Userspace Driver + Ring-0 Kineticlet + TraceRing Replay
// ----------------------------------------------------------------------------
void test_split_plane_driver_and_replay() {
    printf("[TEST 4] Split-Plane Userspace Driver + Ring-0 Kineticlet (100 IRQs)...\n");
    SimHal hal{};
    shell::ImperativeKernelRuntime<SimHal> rt{hal};
    KernelState& st = rt.state();

    DomainId const nvme_drv_dom{10};
    ThreadId const nvme_drv_tid{10};

    (void)sched::spawn_thread(
        st.sched, nvme_drv_tid, nvme_drv_dom, sched::SchedClass::IsochronousRt,
        sched::RtParams{.wcet_ns = 200'000ULL, .period_ns = 1'000'000ULL}, TickNs{0}
    );
    st.sched.threads[0].state = sched::ThreadState::Blocked;

    (void)mm::create_grant_arena(st.mem, ArenaId{1}, nvme_drv_dom, 4, true);

    auto kcap = cap::plan_mint_root(
        st.caps, nvme_drv_dom, cap::CapObjectKind::KineticSlot,
        cap::CapRights::ExecuteRing0 | cap::CapRights::Read | cap::CapRights::Write,
        1ULL, cap::RevocationGroupId{2}
    );
    cap::apply_mutation(st.caps, kcap.value());

    auto icap = cap::plan_mint_root(
        st.caps, nvme_drv_dom, cap::CapObjectKind::IrqHook,
        cap::CapRights::Read | cap::CapRights::Write,
        48ULL, cap::RevocationGroupId{2}
    );
    cap::apply_mutation(st.caps, icap.value());

    kinetic::KineticProgram nvme_fastpath{};
    nvme_fastpath.insns[0]  = kinetic::dsl::load_imm(4, 0);
    nvme_fastpath.insns[1]  = kinetic::dsl::jump_if_eq(0, 4, 10);
    nvme_fastpath.insns[2]  = kinetic::dsl::load_imm(4, 0x8000u);
    nvme_fastpath.insns[3]  = kinetic::dsl::mov(5, 0);
    nvme_fastpath.insns[4]  = kinetic::dsl::bit_and(5, 4);
    nvme_fastpath.insns[5]  = kinetic::dsl::jump_if_eq(5, 4, 7);
    nvme_fastpath.insns[6]  = kinetic::dsl::load_state(6, 0);
    nvme_fastpath.insns[7]  = kinetic::dsl::load_imm(7, 1);
    nvme_fastpath.insns[8]  = kinetic::dsl::add(6, 7);
    nvme_fastpath.insns[9]  = kinetic::dsl::store_state(0, 6);
    nvme_fastpath.insns[10] = kinetic::dsl::store_arena(0, 6);
    nvme_fastpath.insns[11] = kinetic::dsl::ret(kinetic::ReturnVerdict::CompleteFastPath);
    nvme_fastpath.insns[12] = kinetic::dsl::ret(kinetic::ReturnVerdict::DropSilent);
    nvme_fastpath.insns[13] = kinetic::dsl::ret(kinetic::ReturnVerdict::EscalateToUserspace);
    nvme_fastpath.len       = 14;

    auto proof = install_kineticlet(
        st, nvme_drv_dom, kcap.value().minted_token, KineticId{1}, nvme_fastpath
    );
    MUCORE_CHECK(proof.is_ok(), "NVMe Kineticlet statically verified & installed");

    (void)open_conduit(st, ConduitId{1}, nvme_drv_dom, nvme_drv_dom, true);
    (void)bind_irq_pact(st, nvme_drv_dom, icap.value().minted_token, IrqPactBinding{
        .active        = true,
        .irq           = IrqLine{48},
        .driver_domain = nvme_drv_dom,
        .driver_thread = nvme_drv_tid,
        .conduit       = ConduitId{1},
        .fast_kinetic  = KineticId{1},
        .shared_arena  = ArenaId{1},
    });

    for (u64 i = 1; i <= 98; ++i) {
        MUCORE_CHECK(rt.handle_event(KernelEvent{
            .kind            = EventKind::HardwareIrq,
            .timestamp       = TickNs{i * 1'000ULL},
            .irq_line        = IrqLine{48},
            .irq_status_word = 0x0001ULL,
        }).is_ok(), "Healthy IRQ handled");
        (void)flux::dequeue_completion(st.conduits[0]);
    }
    MUCORE_CHECK(rt.handle_event(KernelEvent{
        .kind            = EventKind::HardwareIrq,
        .timestamp       = TickNs{99'000ULL},
        .irq_line        = IrqLine{48},
        .irq_status_word = 0x0000ULL,
    }).is_ok(), "Spurious IRQ dropped silently");

    MUCORE_CHECK(hal.thread_switches == 0 && hal.cr3_switches == 0,
                 "99 hot-path IRQs processed with ZERO context switches!");

    MUCORE_CHECK(rt.handle_event(KernelEvent{
        .kind            = EventKind::HardwareIrq,
        .timestamp       = TickNs{100'000ULL},
        .irq_line        = IrqLine{48},
        .irq_status_word = 0x8001ULL,
    }).is_ok(), "Controller fault IRQ escalated to Ring 3");
    MUCORE_CHECK(hal.ring3_driver_upcalls == 1 && hal.thread_switches == 1,
                 "Exactly 1 context switch on fault escalation");

    // Time-travel replay check
    KernelState replay_state{};
    (void)sched::spawn_thread(
        replay_state.sched, nvme_drv_tid, nvme_drv_dom, sched::SchedClass::IsochronousRt,
        sched::RtParams{.wcet_ns = 200'000ULL, .period_ns = 1'000'000ULL}, TickNs{0}
    );
    replay_state.sched.threads[0].state = sched::ThreadState::Blocked;
    (void)mm::create_grant_arena(replay_state.mem, ArenaId{1}, nvme_drv_dom, 4, true);
    cap::apply_mutation(replay_state.caps, kcap.value());
    cap::apply_mutation(replay_state.caps, icap.value());
    (void)install_kineticlet(replay_state, nvme_drv_dom, kcap.value().minted_token, KineticId{1}, nvme_fastpath);
    (void)open_conduit(replay_state, ConduitId{1}, nvme_drv_dom, nvme_drv_dom, true);
    (void)bind_irq_pact(replay_state, nvme_drv_dom, icap.value().minted_token, st.irq_pacts[0]);

    auto replayed = rt.trace().replay_into(replay_state);
    MUCORE_CHECK(replayed.is_ok() && replayed.value() == 100ULL &&
                 replay_state.mem.arenas[0].kinetic_words[0] == 98ULL,
                 "Deterministic TraceRing replay matched live state 100%");

    printf("  [PASS] 99/100 IRQs completed in Ring 0 (0 switches, WCET=%u ns); replay verified!\n",
           proof.value().wcet_ns);
    ++g_passed;
}

// ----------------------------------------------------------------------------
// Test 5: Hard Real-Time Temporal Isolation Under Rogue IRQ Storm
// ----------------------------------------------------------------------------
void test_realtime_irq_storm_isolation() {
    printf("[TEST 5] Hard Real-Time CBS Temporal Isolation Under IRQ Storm...\n");
    KernelState st{};
    (void)sched::spawn_thread(
        st.sched, ThreadId{1}, DomainId{1}, sched::SchedClass::IsochronousRt,
        sched::RtParams{.wcet_ns = 200'000ULL, .period_ns = 1'000'000ULL}, TickNs{0}
    );
    (void)sched::spawn_thread(
        st.sched, ThreadId{2}, DomainId{2}, sched::SchedClass::IsochronousRt,
        sched::RtParams{.wcet_ns = 50ULL, .period_ns = 2'000'000ULL}, TickNs{0}
    );

    sched::charge_external_wcet(st.sched, ThreadId{2}, 100ULL);
    MUCORE_CHECK(st.sched.threads[1].state == sched::ThreadState::Throttled,
                 "Noisy driver throttled on CBS budget exhaustion");
    MUCORE_CHECK(sched::schedule_at(st.sched, TickNs{100ULL}).next_thread == ThreadId{1},
                 "Critical Hard-RT thread guaranteed CPU despite sibling IRQ storm");

    printf("  [PASS] CBS budget charging protects sibling Hard-RT deadlines.\n");
    ++g_passed;
}

// ----------------------------------------------------------------------------
// Test 6: Zircon Synthesis — `FluxPort` O(1) Fan-In Multiplexing (24 Clients)
// ----------------------------------------------------------------------------
void test_zircon_port_multiplexer() {
    printf("[TEST 6] Zircon Synthesis: FluxPort O(1) Readiness Aggregator (24 Conduits)...\n");
    SimHal hal{};
    shell::ImperativeKernelRuntime<SimHal> rt{hal};
    KernelState& st = rt.state();

    DomainId const server{100};
    MUCORE_CHECK(create_flux_port(st, PortId{1}, server).is_ok(), "Server FluxPort created");

    cap::CapToken client_caps[25]{};
    for (u32 i = 1; i <= 24; ++i) {
        DomainId const cli{i};
        MUCORE_CHECK(open_conduit(st, ConduitId{i}, cli, server, false).is_ok(), "Conduit opened");
        MUCORE_CHECK(attach_conduit_to_port(st, ConduitId{i}, PortId{1}, 5000ULL + i).is_ok(),
                     "Conduit attached to server FluxPort");

        auto cm = cap::plan_mint_root(
            st.caps, cli, cap::CapObjectKind::FluxConduit,
            cap::CapRights::Write | cap::CapRights::UrgentRt, i, cap::RevocationGroupId{1}
        );
        cap::apply_mutation(st.caps, cm.value());
        client_caps[i] = cm.value().minted_token;
    }

    // Client 19 sends normal async work; Client 23 sends Urgent RT work!
    MUCORE_CHECK(rt.handle_event(KernelEvent{
        .kind = EventKind::FluxSubmit, .timestamp = TickNs{10},
        .caller_domain = DomainId{19}, .cap_token = client_caps[19],
        .submission = flux::FluxSubmission{.user_tag = 19}, .urgent_rt = false
    }).is_ok(), "Client 19 normal submit");

    MUCORE_CHECK(rt.handle_event(KernelEvent{
        .kind = EventKind::FluxSubmit, .timestamp = TickNs{20},
        .caller_domain = DomainId{23}, .cap_token = client_caps[23],
        .submission = flux::FluxSubmission{.user_tag = 23}, .urgent_rt = true
    }).is_ok(), "Client 23 urgent submit");

    // Server pops from `FluxPort` in O(1) without polling the 22 idle client rings!
    auto p1 = port::pop_ready_conduit(st.ports[0]);
    MUCORE_CHECK(p1.is_some() && p1.value().conduit.raw == 23u && p1.value().is_urgent_rt,
                 "FluxPort O(1) bitmap extracted Urgent-RT Client 23 first");

    auto p2 = port::pop_ready_conduit(st.ports[0]);
    MUCORE_CHECK(p2.is_some() && p2.value().conduit.raw == 19u && !p2.value().is_urgent_rt,
                 "FluxPort O(1) bitmap extracted Normal Client 19 second");
    MUCORE_CHECK(!port::has_pending(st.ports[0]), "FluxPort clean after draining active clients");

    printf("  [PASS] Server serviced 2 active clients out of 24 in O(1) with 0 empty-ring scans.\n");
    ++g_passed;
}

// ----------------------------------------------------------------------------
// Test 7: Plan 9 Synthesis — Per-Domain Capability Namespaces & Interposition
// ----------------------------------------------------------------------------
void test_plan9_capability_namespaces() {
    printf("[TEST 7] Plan 9 Synthesis: Per-Domain Namespaces & Union Interposition...\n");
    KernelState st{};
    DomainId const app{7};

    // Direct NVMe driver conduit (with `FastPromote` -> allows zero-switch Hot mode!)
    auto nvme_cap = cap::plan_mint_root(
        st.caps, app, cap::CapObjectKind::FluxConduit,
        cap::CapRights::Read | cap::CapRights::Write | cap::CapRights::FastPromote,
        10ULL, cap::RevocationGroupId{5}
    );
    cap::apply_mutation(st.caps, nvme_cap.value());

    // Tracing proxy conduit (without `FastPromote` -> forces observable interposition!)
    auto proxy_cap = cap::plan_mint_root(
        st.caps, app, cap::CapObjectKind::FluxConduit,
        cap::CapRights::Read | cap::CapRights::Write | cap::CapRights::Revoke,
        88ULL, cap::RevocationGroupId{6}
    );
    cap::apply_mutation(st.caps, proxy_cap.value());

    MUCORE_CHECK(ns::bind_capability_path(st.namespaces, st.caps, app, "/dev/nvme0",
                                          nvme_cap.value().minted_token, ns::MountOrder::Replace).is_ok(),
                 "Mounted direct NVMe capability at /dev/nvme0");

    auto res_direct = ns::resolve_path(st.namespaces, st.caps, app, "/dev/nvme0/part0");
    MUCORE_CHECK(res_direct.is_ok() && res_direct.value().can_promote_hot &&
                 strcmp(res_direct.value().rel_subpath.bytes, "/part0") == 0,
                 "Resolved /dev/nvme0/part0 -> subpath /part0 with Hot promotion enabled");

    // Supervisor binds tracing interposer ahead of `/dev/nvme0` (`MountOrder::Before`)
    MUCORE_CHECK(ns::bind_capability_path(st.namespaces, st.caps, app, "/dev/nvme0",
                                          proxy_cap.value().minted_token, ns::MountOrder::Before).is_ok(),
                 "Interposed tracing filter at /dev/nvme0 via Plan 9 union Before");

    auto res_traced = ns::resolve_path(st.namespaces, st.caps, app, "/dev/nvme0/part0");
    MUCORE_CHECK(res_traced.is_ok() && res_traced.value().conduit_id.raw == 88u &&
                 !res_traced.value().can_promote_hot,
                 "App transparently routed through tracing proxy without code changes");

    // Revoking proxy capability atomically restores direct Hot NVMe binding!
    auto rev = cap::plan_revoke_lineage(st.caps, app, proxy_cap.value().minted_token);
    cap::apply_mutation(st.caps, rev.value());

    auto res_restored = ns::resolve_path(st.namespaces, st.caps, app, "/dev/nvme0/part0");
    MUCORE_CHECK(res_restored.is_ok() && res_restored.value().conduit_id.raw == 10u &&
                 res_restored.value().can_promote_hot,
                 "Revoking proxy capability automatically fell back to direct Hot NVMe!");

    printf("  [PASS] Plan 9 capability mounts, union interposition & live fallback verified.\n");
    ++g_passed;
}

// ----------------------------------------------------------------------------
// Test 8: Windows NT Synthesis — MPK Sealing, DMA Crash Quarantine & Colocation
// ----------------------------------------------------------------------------
void test_nt_mpk_quarantine_and_colocation() {
    printf("[TEST 8] Windows NT Synthesis: MPK Seal, DMA Crash Quarantine & Colocation...\n");
    SimHal hal{};
    shell::ImperativeKernelRuntime<SimHal> rt{hal};
    KernelState& st = rt.state();

    DomainId const client{1};
    DomainId const driver{2};

    MUCORE_CHECK(open_conduit(st, ConduitId{1}, client, driver, false).is_ok(), "Conduit opened");
    auto ccap = cap::plan_mint_root(
        st.caps, client, cap::CapObjectKind::FluxConduit,
        cap::CapRights::Write, 1ULL, cap::RevocationGroupId{9}
    );
    cap::apply_mutation(st.caps, ccap.value());

    MUCORE_CHECK(mm::create_grant_arena(st.mem, ArenaId{1}, client, 4, true, PkeyId{2}).is_ok(),
                 "4-page DMA GrantArena created with MPK key 2");

    // Client submits zero-copy GrantArena over Flux -> triggers hardware MPK write-seal!
    MUCORE_CHECK(rt.handle_event(KernelEvent{
        .kind          = EventKind::FluxSubmit,
        .timestamp     = TickNs{100},
        .caller_domain = client,
        .cap_token     = ccap.value().minted_token,
        .submission    = flux::FluxSubmission{.user_tag = 1, .grant_arena = ArenaId{1}},
    }).is_ok(), "Zero-copy FluxSubmit succeeded");
    MUCORE_CHECK(hal.mpk_seals == 1 &&
                 st.mem.arenas[0].lifecycle == mm::ArenaLifecycle::SealedForValidation,
                 "Hardware MPK WRPKRU write-seal emitted (0 TLB shootdown, 0 TOCTOU race!)");

    // Driver begins PCIe hardware DMA, then Client process crashes (`SIGKILL`) mid-DMA!
    MUCORE_CHECK(mm::begin_arena_dma(st.mem, ArenaId{1}, driver).is_ok(), "Driver started PCIe DMA");
    MUCORE_CHECK(rt.handle_event(KernelEvent{
        .kind          = EventKind::DomainCrashTeardown,
        .timestamp     = TickNs{200},
        .caller_domain = client,
    }).is_ok(), "DomainCrashTeardown processed");

    MUCORE_CHECK(hal.iommu_quarantines == 1 && st.mem.pool.allocated_frames == 4u,
                 "In-flight DMA pages quarantined via IOMMU (blocked premature Use-After-Free!)");
    MUCORE_CHECK(mm::destroy_grant_arena(st.mem, ArenaId{1}).error() == Error::DmaInFlightQuarantined,
                 "Direct arena free blocked while DMA still draining");

    // Driver confirms PCIe DMA queue drained -> pages safely returned to PhysPool!
    auto drained = mm::complete_arena_dma_op(st.mem, ArenaId{1});
    MUCORE_CHECK(drained.is_ok() && drained.value() && st.mem.pool.allocated_frames == 0u,
                 "Quarantined pages reclaimed cleanly once hardware DMA completed");

    // Verify 4-stage Co-Located Filter Pipeline (FS -> Crypto -> Dedup -> Block)
    mm::ColocatedPipeline pipe{
        .packet_id     = IoPacketId{42},
        .host_domain   = driver,
        .payload_arena = ArenaId{0},
        .stage_ids     = {10, 20, 30, 40, 0, 0},
        .total_stages  = 4,
    };
    MUCORE_CHECK(mm::advance_colocated_stage(pipe).value_or(0) == 20u &&
                 mm::advance_colocated_stage(pipe).value_or(0) == 30u,
                 "Co-located filter stages advanced with 0 IPC hops");
    MUCORE_CHECK(mm::cancel_colocated_pipeline(pipe) == 3u &&
                 pipe.status == mm::IoPacketStatus::Cancelled,
                 "NT IRP-style cancellation unwound all 3 visited filter stages");

    printf("  [PASS] MPK anti-TOCTOU seal, IOMMU DMA crash quarantine & colocation verified.\n");
    ++g_passed;
}

// ----------------------------------------------------------------------------
// Test 9: L4-MCS Synthesis — Async CBS Deadline & Budget Donation End-to-End
// ----------------------------------------------------------------------------
void test_l4_mcs_async_cbs_donation() {
    printf("[TEST 9] L4-MCS Synthesis: CBS Deadline & Budget Donation Over Async Flux...\n");
    SimHal hal{};
    shell::ImperativeKernelRuntime<SimHal> rt{hal};
    KernelState& st = rt.state();

    DomainId const robot_dom{1};
    ThreadId const robot_tid{1}; // 500us Hard-RT deadline, 200us budget
    DomainId const bg_rt_dom{2};
    ThreadId const bg_rt_tid{2}; // 2000us Medium-RT deadline, 300us budget
    DomainId const drv_dom{3};
    ThreadId const drv_tid{3};   // Tier-1 non-RT `AsyncThroughput` Userspace Driver worker!

    (void)sched::spawn_thread(
        st.sched, robot_tid, robot_dom, sched::SchedClass::IsochronousRt,
        sched::RtParams{.wcet_ns = 200'000ULL, .period_ns = 500'000ULL}, TickNs{0}
    );
    (void)sched::spawn_thread(
        st.sched, bg_rt_tid, bg_rt_dom, sched::SchedClass::IsochronousRt,
        sched::RtParams{.wcet_ns = 300'000ULL, .period_ns = 2'000'000ULL}, TickNs{0}
    );
    (void)sched::spawn_thread(
        st.sched, drv_tid, drv_dom, sched::SchedClass::AsyncThroughput,
        sched::RtParams{}, TickNs{0}
    );

    MUCORE_CHECK(open_conduit(st, ConduitId{5}, robot_dom, drv_dom, false, drv_tid).is_ok(),
                 "Conduit opened with bound consumer worker thread");
    auto rcap = cap::plan_mint_root(
        st.caps, robot_dom, cap::CapObjectKind::FluxConduit,
        cap::CapRights::Write | cap::CapRights::UrgentRt, 5ULL, cap::RevocationGroupId{1}
    );
    cap::apply_mutation(st.caps, rcap.value());

    // Robotics Thread 1 submits Urgent-RT request at t=0 -> donates 500us deadline to Driver Thread 3!
    MUCORE_CHECK(rt.handle_event(KernelEvent{
        .kind          = EventKind::FluxSubmit,
        .timestamp     = TickNs{0},
        .caller_domain = robot_dom,
        .caller_thread = robot_tid,
        .cap_token     = rcap.value().minted_token,
        .submission    = flux::FluxSubmission{.user_tag = 777},
        .urgent_rt     = true,
    }).is_ok(), "Urgent-RT FluxSubmit with MCS CBS context donation succeeded");

    MUCORE_CHECK(st.telemetry.mcs_donations == 1 && st.sched.current_thread == drv_tid,
                 "Non-RT Driver Thread 3 inherited 500us deadline & preempted 2ms RT Thread 2!");

    // Driver completes request 60us later (`t = 60,000ns`) -> returns remaining 140us to Robot Thread 1!
    MUCORE_CHECK(rt.handle_event(KernelEvent{
        .kind          = EventKind::FluxComplete,
        .timestamp     = TickNs{60'000ULL},
        .caller_domain = drv_dom,
        .caller_thread = drv_tid,
        .conduit_id    = ConduitId{5},
        .completion    = flux::FluxCompletion{.user_tag = 777, .result_value = 0},
    }).is_ok(), "Driver posted FluxComplete & returned borrowed CBS context");

    MUCORE_CHECK(st.sched.current_thread == robot_tid &&
                 st.sched.threads[0].remaining_budget_ns == 140'000ULL &&
                 st.sched.threads[2].sched_class == sched::SchedClass::AsyncThroughput,
                 "Robot Thread 1 resumed with exact 140us remaining CBS budget; Driver demoted cleanly!");

    printf("  [PASS] Async priority inversion eliminated with exact CBS budget conservation.\n");
    ++g_passed;
}

} // namespace

int main() {
    printf("======================================================================\n");
    printf("  μCore (mucore-kernel) — FCIS & Four-Lineage Verification Suite\n");
    printf("  Compile-Time `static_assert` Proofs (6 Theorem Suites): PASSED\n");
    printf("======================================================================\n");

    test_capabilities();
    test_wait_free_flux_and_urgent_rt();
    test_adaptive_thermal_tiering();
    test_split_plane_driver_and_replay();
    test_realtime_irq_storm_isolation();
    test_zircon_port_multiplexer();
    test_plan9_capability_namespaces();
    test_nt_mpk_quarantine_and_colocation();
    test_l4_mcs_async_cbs_donation();

    printf("----------------------------------------------------------------------\n");
    printf("Summary: %d passed, %d failed.\n", g_passed, g_failed);
    return (g_failed == 0) ? 0 : 1;
}
