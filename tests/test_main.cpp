// ============================================================================
// μCore (mucore-kernel) — Host Functional Core & Four-Lineage Simulation Suite
// ============================================================================
// Exercises the exact same `include/mucore/core/*` and `include/mucore/shell/*`
// code that runs in Ring 0, verifying security invariants, Real-Time CBS
// temporal isolation, zero-context-switch Kineticlets, TraceRing replay,
// AND the Four-Lineage Synthesis (Zircon + Windows NT + Plan 9 + L4 MCS).
// ============================================================================

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "mucore/core/dispatcher.hpp"
#include "mucore/core/init.hpp"
#include "mucore/core/smp.hpp"
#include "mucore/core/vmspace.hpp"
#include "mucore/shell/cli.hpp"
#include "mucore/shell/hal.hpp"
#include "mucore/shell/shared_conduit.hpp"
#include "kernel/boot_manifest.hpp"
#include "tests/init_fixture.hpp"

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

// ----------------------------------------------------------------------------
// Test 10: Phase 2 — 4-Level `VmSpace` (W^X, MPK, KPTI) & Per-Core Magazines
// ----------------------------------------------------------------------------
void test_vmspace_and_percore_magazines() {
    printf("[TEST 10] VmSpace 4-Level Paging (W^X, MPK, StrictKpti) & Magazines...\n");
    static vm::VmTablePool pool{};
    auto kpml4 = vm::alloc_pt_node(pool);
    MUCORE_CHECK(kpml4.is_ok(), "Allocated root Kernel PML4 node");

    pool.nodes[kpml4.value()].entries[256] = 0x0000'0000'0010'0103ULL; // HHDM Global
    pool.nodes[kpml4.value()].entries[511] = 0x0000'0000'0020'0103ULL; // Kernel Trampoline

    // 1. Constitutional W^X check
    auto wx_err = vm::encode_leaf_pte(
        VirtAddr{0x0040'0000ULL}, PhysAddr{0x0080'0000ULL},
        vm::MapPermissions{.writable = true, .executable = true, .user_accessible = true}
    );
    MUCORE_CHECK(wx_err.error() == Error::WxorXViolation,
                 "Simultaneous Writable + Executable mapping rejected with WxorXViolation");

    // 2. Compare `SharedHigherHalf` (0-CR3 switch default) vs `StrictKpti` (sandbox opt-in)
    auto shared_dom = vm::create_domain_vmspace(
        pool, kpml4.value(), DomainId{11}, vm::KptiMode::SharedHigherHalf
    );
    auto kpti_dom = vm::create_domain_vmspace(
        pool, kpml4.value(), DomainId{12}, vm::KptiMode::StrictKpti
    );
    MUCORE_CHECK(shared_dom.is_ok() && kpti_dom.is_ok(), "Created SharedHigherHalf and StrictKpti domains");
    MUCORE_CHECK(pool.nodes[shared_dom.value().user_pml4_node].entries[256] != 0ULL,
                 "SharedHigherHalf retains Global HHDM PML4[256] for 0-CR3-switch fast path");
    MUCORE_CHECK(pool.nodes[kpti_dom.value().user_pml4_node].entries[256] == 0ULL &&
                 pool.nodes[kpti_dom.value().user_pml4_node].entries[511] != 0ULL,
                 "StrictKpti strips PML4[256..510] while keeping PML4[511] entry trampoline");

    // 3. Map & walk 4-level GrantArena page tagged with MPK `PkeyId{11}`
    VirtAddr const va{0x0000'003F'1020'4000ULL};
    PhysAddr const pa{0x0000'0000'0480'0000ULL};
    MUCORE_CHECK(vm::map_page_4k(pool, kpti_dom.value().user_pml4_node, va, pa,
                                 vm::MapPermissions{
                                     .writable        = true,
                                     .executable      = false,
                                     .user_accessible = true,
                                     .mpk_key         = PkeyId{11},
                                 }).is_ok(),
                 "Mapped 4 KiB page across 4-level PML4->PDPT->PD->PT hierarchy");

    auto leaf = vm::walk_page_table(pool, kpti_dom.value().user_pml4_node, va);
    MUCORE_CHECK(leaf.is_ok() &&
                 (leaf.value() & vm::PTE_ADDR_MASK) == pa.raw &&
                 vm::extract_pte_mpk(leaf.value()) == PkeyId{11} &&
                 (leaf.value() & vm::PTE_NX) != 0ULL,
                 "4-level MMU walk verified physical address, NX bit, and MPK PkeyId{11}");

    // 4. Per-Core Magazine Hard-RT Reserve Watermark (`RT_EMERGENCY_WATERMARK = 8`)
    mm::PhysPoolState      pstate{};
    mm::LocalFrameMagazine mag{};
    MUCORE_CHECK(mm::refill_magazine_batch(mag, pstate) == 32u, "Batch-refilled 32 frames");
    for (usize i = 0; i < 24u; ++i) {
        MUCORE_CHECK(mm::alloc_from_magazine(mag, false).is_ok(), "Tier-1 pop above watermark");
    }
    MUCORE_CHECK(mm::alloc_from_magazine(mag, false).error() == Error::RtReserveProtected,
                 "Tier-1 Async blocked from exhausting last 8 Hard-RT emergency frames");
    MUCORE_CHECK(mm::alloc_from_magazine(mag, true).is_ok(),
                 "Tier-0 Hard-RT allocated immediately from emergency watermark with 0 locks");

    printf("  [PASS] 4-level VmSpace W^X/MPK/StrictKpti & Hard-RT Magazine reserve verified.\n");
    ++g_passed;
}

// ----------------------------------------------------------------------------
// Test 11: Phase 2 — 4-OS-Thread Concurrent SMP Stress & Deterministic Replay
// ----------------------------------------------------------------------------
struct SmpThreadCtx {
    smp::SmpNodeState* node{nullptr};
    u16                cpu_idx{0};
    cap::CapToken      shared_live_cap{};
    PhysAddr           allocated_frames[40]{};
    u32                start_barrier{0};
    bool               ok{true};
};

static u32 g_smp_ready_count = 0;
static u32 g_smp_phase2_go   = 0;

void* smp_worker_entry(void* raw_arg) {
    auto* ctx = static_cast<SmpThreadCtx*>(raw_arg);
    smp::SmpNodeState& node = *ctx->node;
    CpuId const cpu{ctx->cpu_idx};

    // Synchronize all 4 OS threads so contention is maximally simultaneous!
    (void)__atomic_fetch_add(&g_smp_ready_count, 1u, __ATOMIC_ACQ_REL);
    while (__atomic_load_n(&g_smp_ready_count, __ATOMIC_ACQUIRE) < 4u) {
        #if defined(__x86_64__)
        asm volatile("pause" : : : "memory");
        #endif
    }

    // 1. Parallel Per-Core Magazine Allocations (40 frames * 4 threads = 160 frames!)
    for (usize i = 0; i < 40; ++i) {
        auto f = smp::alloc_shard_frame(node, cpu, (i >= 32));
        if (f.is_err()) {
            ctx->ok = false;
            return nullptr;
        }
        ctx->allocated_frames[i] = f.value();
    }

    // 2. Lock-Free SeqLock `CapTable` Validation Under Live Concurrent Churn!
    for (u32 iter = 0; iter < 500; ++iter) {
        auto v = cap::validate_capability(
            node.shared_caps, DomainId{1}, ctx->shared_live_cap,
            cap::CapObjectKind::FluxConduit, cap::CapRights::Read
        );
        if (v.is_err()) {
            ctx->ok = false;
            return nullptr;
        }

        // Core 0 simultaneously churns transient capabilities + epoch revocations!
        if (cpu.raw == 0 && (iter % 10u == 0u)) {
            node.cold_lock.lock();
            auto m = cap::plan_mint_root(
                node.shared_caps, DomainId{9}, cap::CapObjectKind::FluxConduit,
                cap::CapRights::Read | cap::CapRights::Revoke, 999ULL, cap::RevocationGroupId{20}
            );
            if (m.is_ok()) {
                cap::apply_mutation(node.shared_caps, m.value());
                auto r = cap::plan_revoke_lineage(node.shared_caps, DomainId{9}, m.value().minted_token);
                if (r.is_ok()) cap::apply_mutation(node.shared_caps, r.value());
            }
            node.cold_lock.unlock();
        }
    }

    // Barrier before cross-core PKRU shootdown + L4-MCS CBS parcel exchange
    (void)__atomic_fetch_add(&g_smp_phase2_go, 1u, __ATOMIC_ACQ_REL);
    while (__atomic_load_n(&g_smp_phase2_go, __ATOMIC_ACQUIRE) < 4u) {
        #if defined(__x86_64__)
        asm volatile("pause" : : : "memory");
        #endif
    }

    // 3. Cross-Core L4-MCS CBS Loans + Targeted `PKRU` Coherence
    //    - Pair A: Core 0 (RT Donor 100) -> Core 1 (Async Worker 101)
    //    - Pair B: Core 2 (RT Donor 200) -> Core 3 (Async Worker 201)
    //    - PKRU:   Core 0 seals single-core `DomainId{10}` (0 IPIs!) and
    //              2-core `DomainId{20}` shared ONLY with Core 2 (1 targeted IPI!)
    if (cpu.raw == 0) {
        u32 const ipis_single = smp::seal_domain_pkru_coherent(node, cpu, DomainId{10}, PkeyId{3});
        u32 const ipis_shared = smp::seal_domain_pkru_coherent(node, cpu, DomainId{20}, PkeyId{7});
        if (ipis_single != 0u || ipis_shared != 1u) {
            ctx->ok = false;
            return nullptr;
        }

        // Loan 200us budget / 500us deadline from Core 0 Thread 100 -> Core 1 Thread 101
        if (smp::execute_on_cpu_shard(node, cpu, smp::ShardEvent{
                .kind          = smp::ShardEventKind::LocalCbsRemoteCall,
                .timestamp     = TickNs{1'000ULL},
                .local_thread  = ThreadId{100},
                .remote_worker = ThreadId{101},
                .remote_cpu    = CpuId{1},
            }).is_err()) {
            ctx->ok = false;
            return nullptr;
        }

        // Wait for Core 1's `RefundRemoteCbs` parcel!
        while (node.shards[0].telemetry.remote_cbs_refunds_rcvd == 0) {
            (void)smp::drain_incoming_parcels(node, cpu, TickNs{51'000ULL});
        }
    } else if (cpu.raw == 1) {
        // Wait for Core 0's `DonateRemoteCbs` parcel, run for 50us, and return leftover!
        while (node.shards[1].telemetry.parcels_received == 0) {
            (void)smp::drain_incoming_parcels(node, cpu, TickNs{1'000ULL});
        }
        if (smp::execute_on_cpu_shard(node, cpu, smp::ShardEvent{
                .kind         = smp::ShardEventKind::LocalWorkerComplete,
                .timestamp    = TickNs{51'000ULL},
                .local_thread = ThreadId{101},
            }).is_err()) {
            ctx->ok = false;
            return nullptr;
        }
    } else if (cpu.raw == 2) {
        // Loan 300us budget / 600us deadline from Core 2 Thread 200 -> Core 3 Thread 201
        if (smp::execute_on_cpu_shard(node, cpu, smp::ShardEvent{
                .kind          = smp::ShardEventKind::LocalCbsRemoteCall,
                .timestamp     = TickNs{2'000ULL},
                .local_thread  = ThreadId{200},
                .remote_worker = ThreadId{201},
                .remote_cpu    = CpuId{3},
            }).is_err()) {
            ctx->ok = false;
            return nullptr;
        }

        // Wait for BOTH Core 0's targeted `SyncPkruSeal` AND Core 3's `RefundRemoteCbs`!
        while (node.shards[2].telemetry.remote_cbs_refunds_rcvd == 0 ||
               node.shards[2].telemetry.pkru_seals_applied == 0) {
            (void)smp::drain_incoming_parcels(node, cpu, TickNs{82'000ULL});
        }
    } else if (cpu.raw == 3) {
        // Wait for Core 2's `DonateRemoteCbs` parcel, run for 80us, and return leftover!
        while (node.shards[3].telemetry.parcels_received == 0) {
            (void)smp::drain_incoming_parcels(node, cpu, TickNs{2'000ULL});
        }
        if (smp::execute_on_cpu_shard(node, cpu, smp::ShardEvent{
                .kind         = smp::ShardEventKind::LocalWorkerComplete,
                .timestamp    = TickNs{82'000ULL},
                .local_thread = ThreadId{201},
            }).is_err()) {
            ctx->ok = false;
            return nullptr;
        }
    }

    return nullptr;
}

void seed_smp_core_threads(sched::SchedTable& sc, u16 cpu_idx) {
    if (cpu_idx == 0) {
        (void)sched::spawn_thread(
            sc, ThreadId{100}, DomainId{10}, sched::SchedClass::IsochronousRt,
            sched::RtParams{.wcet_ns = 200'000ULL, .period_ns = 500'000ULL}, TickNs{0}
        );
    } else if (cpu_idx == 1) {
        (void)sched::spawn_thread(
            sc, ThreadId{101}, DomainId{11}, sched::SchedClass::AsyncThroughput,
            sched::RtParams{}, TickNs{0}
        );
    } else if (cpu_idx == 2) {
        (void)sched::spawn_thread(
            sc, ThreadId{200}, DomainId{20}, sched::SchedClass::IsochronousRt,
            sched::RtParams{.wcet_ns = 300'000ULL, .period_ns = 600'000ULL}, TickNs{0}
        );
    } else if (cpu_idx == 3) {
        (void)sched::spawn_thread(
            sc, ThreadId{201}, DomainId{21}, sched::SchedClass::AsyncThroughput,
            sched::RtParams{}, TickNs{0}
        );
    }
}

void test_concurrent_4thread_smp_sharding_and_replay() {
    printf("[TEST 11] 4-OS-Thread SMP Sharding, CBS IPI Loans, PKRU & Per-Core Replay...\n");
    static smp::SmpNodeState smp_node{};

    // Mint shared read-lockless capability validated concurrently by all 4 OS threads
    auto live_mut = cap::plan_mint_root(
        smp_node.shared_caps, DomainId{1}, cap::CapObjectKind::FluxConduit,
        cap::CapRights::Read | cap::CapRights::Write, 42ULL, cap::RevocationGroupId{1}
    );
    MUCORE_CHECK(live_mut.is_ok(), "Minted shared root capability");
    cap::apply_mutation(smp_node.shared_caps, live_mut.value());

    // Configure active-domain CPU bitmasks:
    //   - `DomainId{10}` runs ONLY on Core 0 -> 0-IPI local WRPKRU fast path!
    //   - `DomainId{20}` runs on Core 0 AND Core 2 -> targeted 1-IPI shootdown to Core 2 ONLY!
    smp::track_domain_enter_cpu(smp_node, DomainId{10}, CpuId{0});
    smp::track_domain_enter_cpu(smp_node, DomainId{20}, CpuId{0});
    smp::track_domain_enter_cpu(smp_node, DomainId{20}, CpuId{2});

    for (u16 c = 0; c < 4; ++c) {
        smp_node.shards[c].online = true;
        seed_smp_core_threads(smp_node.shards[c].sched, c);
    }

    pthread_t    threads[4]{};
    SmpThreadCtx ctxs[4]{};
    g_smp_ready_count = 0;
    g_smp_phase2_go   = 0;

    for (u16 c = 0; c < 4; ++c) {
        ctxs[c].node            = &smp_node;
        ctxs[c].cpu_idx         = c;
        ctxs[c].shared_live_cap = live_mut.value().minted_token;
        MUCORE_CHECK(pthread_create(&threads[c], nullptr, &smp_worker_entry, &ctxs[c]) == 0,
                     "Spawned OS pthread for simulated SMP CPU core");
    }
    for (u16 c = 0; c < 4; ++c) {
        (void)pthread_join(threads[c], nullptr);
        MUCORE_CHECK(ctxs[c].ok, "SMP core pthread completed all invariants cleanly");
    }

    // 1. Verify all 160 physical frames allocated across 4 cores are 100% unique!
    for (u16 c1 = 0; c1 < 4; ++c1) {
        for (usize i = 0; i < 40; ++i) {
            for (u16 c2 = c1; c2 < 4; ++c2) {
                for (usize j = (c1 == c2 ? i + 1 : 0); j < 40; ++j) {
                    MUCORE_CHECK(!(ctxs[c1].allocated_frames[i] == ctxs[c2].allocated_frames[j]),
                                 "Zero duplicate physical frames across concurrent 4-core magazines");
                }
            }
        }
    }

    // 2. Verify Active-Core Targeted `PKRU` Coherence (Cores 1 and 3 received ZERO PKRU IPIs!)
    MUCORE_CHECK(smp_node.shards[0].telemetry.local_zero_ipi_seals == 1 &&
                 smp_node.shards[0].telemetry.targeted_pkru_ipis_sent == 1,
                 "Core 0 used 0-IPI fast path for Domain 10 and 1 targeted IPI for Domain 20");
    MUCORE_CHECK(smp_node.shards[2].telemetry.pkru_seals_applied == 1 &&
                 smp_node.shards[1].telemetry.pkru_seals_applied == 0 &&
                 smp_node.shards[3].telemetry.pkru_seals_applied == 0,
                 "Targeted SyncPkruSeal delivered ONLY to sibling Core 2 (Cores 1 & 3 undisturbed!)");

    // 3. Verify Exact Cross-Core CBS Bandwidth Conservation
    MUCORE_CHECK(smp_node.shards[0].sched.threads[0].remaining_budget_ns == 150'000ULL &&
                 smp_node.shards[2].sched.threads[0].remaining_budget_ns == 220'000ULL,
                 "Exact CBS budget conservation across concurrent cross-core IPI loans (150us & 220us)");

    // 4. Deterministic Per-Core Time-Travel Replay (`replay_shard_trace`) on All 4 Shards!
    static smp::CpuShard replayed[4]{};
    for (u16 c = 0; c < 4; ++c) {
        replayed[c].cpu_id = CpuId{c};
        seed_smp_core_threads(replayed[c].sched, c);

        auto rep = smp::replay_shard_trace(smp_node.shards[c].trace, replayed[c]);
        MUCORE_CHECK(rep.is_ok() && rep.value() == smp_node.shards[c].trace.count(),
                     "Single-core deterministic replay succeeded on recorded SMP shard trace");
        MUCORE_CHECK(replayed[c].sched.current_thread == smp_node.shards[c].sched.current_thread &&
                     replayed[c].sched.threads[0].remaining_budget_ns ==
                         smp_node.shards[c].sched.threads[0].remaining_budget_ns &&
                     replayed[c].sched.threads[0].total_runtime_ns ==
                         smp_node.shards[c].sched.threads[0].total_runtime_ns &&
                     replayed[c].telemetry.parcels_received ==
                         smp_node.shards[c].telemetry.parcels_received,
                     "Replayed shard state matches live 4-thread SMP run 100% bit-for-bit!");
    }

    printf("  [PASS] 4-thread SMP sharding, 160 magazine allocs, targeted PKRU & 4-core replay verified!\n");
    ++g_passed;
}

// ----------------------------------------------------------------------------
// Test 12: Init — Manifest Boot, Capability Wiring, Crash Supervision & Replay
// ----------------------------------------------------------------------------
bool init_tables_match(
    KernelState const& a, init::InitState const& ia,
    KernelState const& b, init::InitState const& ib
) {
    for (usize i = 0; i < init::MAX_SERVICES; ++i) {
        init::ServiceRuntime const& x = ia.services[i];
        init::ServiceRuntime const& y = ib.services[i];
        if (x.state != y.state || x.restarts != y.restarts ||
            !(x.control_cap == y.control_cap) || !(x.port_cap == y.port_cap)) {
            return false;
        }
        for (usize g = 0; g < init::MAX_GRANTS_PER_SERVICE; ++g) {
            if (!(x.grant_caps[g] == y.grant_caps[g])) return false;
        }
        for (usize k = 0; k < init::MAX_IMPORTS_PER_SERVICE; ++k) {
            if (!(x.import_caps[k] == y.import_caps[k])) return false;
        }
    }
    for (usize s = 0; s < cap::MAX_CAP_SLOTS; ++s) {
        cap::CapEntry const& x = a.caps.slots[s];
        cap::CapEntry const& y = b.caps.slots[s];
        if (x.occupied != y.occupied || x.generation != y.generation ||
            !(x.owner == y.owner) || x.object_id != y.object_id || x.rights != y.rights) {
            return false;
        }
    }
    for (usize g = 0; g < cap::MAX_REVOCATION_GROUPS; ++g) {
        if (a.caps.group_epochs[g] != b.caps.group_epochs[g]) return false;
    }
    for (usize c = 0; c < MAX_CONDUITS; ++c) {
        if (a.conduits[c].active != b.conduits[c].active ||
            !(a.conduits[c].id == b.conduits[c].id)) {
            return false;
        }
    }
    return ia.restarts == ib.restarts && ia.failures == ib.failures &&
           ia.exits_handled == ib.exits_handled;
}

void test_init_boot_and_supervision() {
    printf("[TEST 12] Init: Compile-Time Manifest, Capability Wiring & Crash Supervision...\n");
    using namespace mucore::fixture;

    SimHal hal{};
    shell::ImperativeKernelRuntime<SimHal> rt{hal};
    KernelState&          st   = rt.state();
    init::InitState       ini{};
    init::BootPlan const& plan = PLAN;

    // The live shell's domain-exit path: kernel teardown event, then init supervision.
    auto crash = [&](DomainId dom, u64 at_ns) -> init::SuperviseOutcome {
        KernelEvent const ev{
            .kind          = EventKind::DomainCrashTeardown,
            .timestamp     = TickNs{at_ns},
            .caller_domain = dom,
        };
        if (rt.handle_event(ev).is_err()) return init::SuperviseOutcome{};
        return init::supervise_after_event(st, ini, plan, ev);
    };

    // --- Boot -------------------------------------------------------------
    auto boot = init::boot_services(st, ini, plan, TickNs{0});
    MUCORE_CHECK(boot.is_ok() && boot.value().started == 4u && boot.value().failed == 0u,
                 "All four manifest services started in dependency order");
    MUCORE_CHECK(init::boot_services(st, ini, plan, TickNs{0}).error() == Error::InvalidState,
                 "Init refuses to boot twice");
    MUCORE_CHECK(st.sched.reserved_rt_ppm == 100'000ULL,
                 "Tier-0 driver admitted with exactly its manifest bandwidth");

    auto traced = ns::resolve_path(st.namespaces, st.caps, VFS_DOM, "/dev/nvme0/ns1");
    MUCORE_CHECK(traced.is_ok() && traced.value().conduit_id == VFS_TO_BLKTRACE &&
                 !traced.value().can_promote_hot && traced.value().union_alternatives == 1u &&
                 strcmp(traced.value().rel_subpath.bytes, "/ns1") == 0,
                 "vfs reaches /dev/nvme0 through the blktrace interposer, direct path as fallback");
    MUCORE_CHECK(ns::resolve_path(st.namespaces, st.caps, SHELL_DOM, "/dev/nvme0").error() ==
                 Error::NamespaceNotFound,
                 "shell has no path to the disk: it was never granted one");
    MUCORE_CHECK(cap::validate_capability(st.caps, SHELL_DOM, traced.value().conduit_cap,
                                          cap::CapObjectKind::FluxConduit, cap::CapRights::Read)
                     .error() == Error::DomainMismatch,
                 "A capability minted for vfs is useless to shell");

    // A submission over the wired conduit reaches the provider's port with the right cookie.
    MUCORE_CHECK(rt.handle_event(KernelEvent{
        .kind = EventKind::FluxSubmit, .timestamp = TickNs{100},
        .caller_domain = VFS_DOM, .cap_token = traced.value().conduit_cap,
        .submission = flux::FluxSubmission{.user_tag = 7},
    }).is_ok(), "vfs submits to blktrace over its init-wired conduit");
    auto blk_port = find_port_idx(st, plan.services[BLKTRACE].port);
    MUCORE_CHECK(blk_port.is_some(), "blktrace owns a readiness port");
    auto ready = port::pop_ready_conduit(st.ports[blk_port.value()]);
    MUCORE_CHECK(ready.is_some() && ready.value().conduit == VFS_TO_BLKTRACE &&
                 ready.value().user_key == init::port_user_key(VFS, 0),
                 "blktrace's port reports the ready client conduit and its cookie");

    // The driver uses the capabilities init granted it to install its Ring-0 fast path.
    kinetic::KineticProgram ack{};
    ack.insns[0] = kinetic::dsl::ret(kinetic::ReturnVerdict::CompleteFastPath);
    ack.len      = 1;
    MUCORE_CHECK(install_kineticlet(st, NVME_DOM, ini.services[NVME].grant_caps[0],
                                    KineticId{1}, ack).is_ok(),
                 "nvme installs a Kineticlet with its granted KineticSlot capability");
    MUCORE_CHECK(bind_irq_pact(st, NVME_DOM, ini.services[NVME].grant_caps[1], IrqPactBinding{
        .active        = true,
        .irq           = IrqLine{static_cast<u16>(NVME_IRQ)},
        .driver_domain = NVME_DOM,
        .driver_thread = NVME_TID,
        .fast_kinetic  = KineticId{1},
    }).is_ok(), "nvme binds its IRQ with its granted IrqHook capability");
    MUCORE_CHECK(install_kineticlet(st, VFS_DOM, ini.services[NVME].grant_caps[0],
                                    KineticId{2}, ack).is_err(),
                 "vfs cannot use the driver's KineticSlot capability");

    // --- Crash 1: interposer dies while holding a CBS loan from the driver ----
    MUCORE_CHECK(sched::donate_cbs_context(st.sched, NVME_TID, BLKTRACE_TID).is_ok(),
                 "nvme lends its CBS context to the blktrace worker");
    cap::CapToken const dead_tok = ini.services[VFS].import_caps[0];

    auto first = crash(BLKTRACE_DOM, 10'000);
    MUCORE_CHECK(first.verdict == init::Verdict::Restarted && first.restarts == 1u,
                 "blktrace restarted on its first crash");
    // (Rejected as revoked, or as a stale generation once the restart has recycled its slot.)
    MUCORE_CHECK(cap::validate_capability(st.caps, VFS_DOM, dead_tok,
                                          cap::CapObjectKind::FluxConduit, cap::CapRights::Read)
                     .is_err(),
                 "vfs's capability on the dead instance no longer validates");
    u32 const donor = sched::find_thread_slot(st.sched, NVME_TID).value();
    MUCORE_CHECK(!st.sched.threads[donor].loaned_to &&
                 st.sched.threads[donor].state == sched::ThreadState::Ready &&
                 st.sched.threads[donor].remaining_budget_ns == NVME_WCET_NS,
                 "The dead worker's borrowed CBS budget went back to its donor");
    auto rewired = ns::resolve_path(st.namespaces, st.caps, VFS_DOM, "/dev/nvme0/ns1");
    MUCORE_CHECK(rewired.is_ok() && rewired.value().conduit_id == VFS_TO_BLKTRACE &&
                 !(rewired.value().conduit_cap == dead_tok) &&
                 rewired.value().union_alternatives == 1u,
                 "vfs was re-wired to the new blktrace instance without restarting");
    auto fresh_port = find_port_idx(st, plan.services[BLKTRACE].port);
    MUCORE_CHECK(fresh_port.is_some() && !port::has_pending(st.ports[fresh_port.value()]),
                 "The restarted provider starts with an empty port");

    // --- Crash 2: restart budget exhausted, union falls back ------------------
    auto second = crash(BLKTRACE_DOM, 20'000);
    MUCORE_CHECK(second.verdict == init::Verdict::GaveUp &&
                 ini.services[BLKTRACE].state == init::ServiceState::Failed,
                 "blktrace is given up on after max_restarts");
    MUCORE_CHECK(sched::find_thread_slot(st.sched, BLKTRACE_TID).is_none() &&
                 find_conduit_idx(st, VFS_TO_BLKTRACE).is_none() &&
                 find_conduit_idx(st, BLKTRACE_TO_NVME).is_none() &&
                 find_port_idx(st, plan.services[BLKTRACE].port).is_none(),
                 "A failed service leaves no thread, conduit or port behind");
    auto direct = ns::resolve_path(st.namespaces, st.caps, VFS_DOM, "/dev/nvme0/ns1");
    MUCORE_CHECK(direct.is_ok() && direct.value().conduit_id == VFS_TO_NVME &&
                 direct.value().can_promote_hot && direct.value().union_alternatives == 0u,
                 "vfs falls back to the direct hot-promotable driver endpoint");
    MUCORE_CHECK(crash(BLKTRACE_DOM, 21'000).verdict == init::Verdict::Unmanaged,
                 "An exit report for a service that is not running is ignored");

    // --- Crash 3: Tier-0 driver ------------------------------------------------
    auto rt_restart = crash(NVME_DOM, 30'000);
    MUCORE_CHECK(rt_restart.verdict == init::Verdict::Restarted, "nvme restarted");
    MUCORE_CHECK(find_kinetic_idx(st, KineticId{1}).is_none() && !st.irq_pacts[0].active,
                 "The dead driver's Kineticlet and IRQ pact were released");
    MUCORE_CHECK(rt.handle_event(KernelEvent{
        .kind = EventKind::HardwareIrq, .timestamp = TickNs{31'000},
        .irq_line = IrqLine{static_cast<u16>(NVME_IRQ)},
    }).error() == Error::NotFound, "An IRQ for the dead instance is not routed anywhere");
    MUCORE_CHECK(st.sched.reserved_rt_ppm == 100'000ULL,
                 "Restart neither leaks nor double-counts admitted RT bandwidth");
    u32 const reborn = sched::find_thread_slot(st.sched, NVME_TID).value();
    MUCORE_CHECK(st.sched.threads[reborn].state == sched::ThreadState::Throttled &&
                 st.sched.threads[reborn].remaining_budget_ns == 0ULL,
                 "The restarted RT thread gets no budget inside the crashed period");
    MUCORE_CHECK(!(sched::schedule_at(st.sched, TickNs{40'000}).next_thread == NVME_TID),
                 "It is not scheduled before its next period boundary");
    MUCORE_CHECK(sched::schedule_at(st.sched, TickNs{30'000 + NVME_PERIOD_NS}).next_thread ==
                 NVME_TID,
                 "It runs again once the CBS period boundary replenishes it");
    MUCORE_CHECK(rt.handle_event(KernelEvent{
        .kind = EventKind::FluxSubmit, .timestamp = TickNs{1'100'000},
        .caller_domain = VFS_DOM, .cap_token = ini.services[VFS].import_caps[1],
        .submission = flux::FluxSubmission{.user_tag = 8},
    }).is_ok(), "vfs talks to the restarted driver over its re-issued capability");

    // --- Policies ---------------------------------------------------------------
    MUCORE_CHECK(crash(SHELL_DOM, 1'200'000).verdict == init::Verdict::GaveUp &&
                 ini.services[SHELL].restarts == 0u,
                 "A RestartPolicy::Never service is not restarted");
    auto fatal = crash(NVME_DOM, 1'300'000);
    MUCORE_CHECK(fatal.verdict == init::Verdict::HaltSystem && st.sched.reserved_rt_ppm == 0ULL,
                 "A critical service out of restarts asks the shell to halt");
    MUCORE_CHECK(ini.exits_handled == 5u && ini.restarts == 2u && ini.failures == 3u &&
                 ini.wiring_failures == 0u,
                 "Supervision telemetry matches the crash history");

    // --- Replay: boot a second kernel from the same plan and feed it the trace --
    KernelState     replay{};
    init::InitState replay_ini{};
    MUCORE_CHECK(init::boot_services(replay, replay_ini, plan, TickNs{0}).is_ok(),
                 "Replay kernel booted from the same plan");
    auto replayed = init::replay_supervised(rt.trace(), replay, replay_ini, plan);
    MUCORE_CHECK(replayed.is_ok() && replayed.value() == rt.trace().total_recorded(),
                 "Every recorded event replayed");
    MUCORE_CHECK(init_tables_match(st, ini, replay, replay_ini),
                 "Replay reproduced every restart, capability token and conduit bit-for-bit");

    printf("  [PASS] 4 services wired from a compile-time plan; %u crashes -> %u restarts, "
           "%u given up; replay exact.\n", ini.exits_handled, ini.restarts, ini.failures);
    ++g_passed;
}

// ----------------------------------------------------------------------------
// Test 13: Interactive Command Shell & Diagnostics REPL Execution
// ----------------------------------------------------------------------------
void test_interactive_command_shell() {
    printf("[TEST 13] Interactive Command Shell: REPL Commands, Supervision & IRQ Fast-Path...\n");
    SimHal hal{};
    shell::ImperativeKernelRuntime<SimHal> rt{hal};
    init::InitState                        ini{};
    smp::SmpNodeState                      smp{};

    MUCORE_CHECK(init::boot_services(rt.state(), ini, boot::PLAN, TickNs{1'000'000ULL}).is_ok(),
                 "Shell booted services from boot::PLAN");

    // Prime Kineticlet
    init::PlannedService const& nvme = boot::PLAN.services[boot::NVME];
    cap::CapToken const kin_cap = ini.services[boot::NVME].grant_caps[boot::NVME_GRANT_KINETIC];
    cap::CapToken const irq_cap = ini.services[boot::NVME].grant_caps[boot::NVME_GRANT_IRQ];

    kinetic::KineticProgram prog{};
    prog.insns[0] = kinetic::dsl::load_imm(4, 0x8000u);
    prog.insns[1] = kinetic::dsl::mov(5, 0);
    prog.insns[2] = kinetic::dsl::bit_and(5, 4);
    prog.insns[3] = kinetic::dsl::jump_if_eq(5, 4, 5);
    prog.insns[4] = kinetic::dsl::load_state(6, 0);
    prog.insns[5] = kinetic::dsl::load_imm(7, 1);
    prog.insns[6] = kinetic::dsl::add(6, 7);
    prog.insns[7] = kinetic::dsl::store_state(0, 6);
    prog.insns[8] = kinetic::dsl::ret(kinetic::ReturnVerdict::CompleteFastPath);
    prog.insns[9] = kinetic::dsl::ret(kinetic::ReturnVerdict::EscalateToUserspace);
    prog.len      = 10;

    MUCORE_CHECK(install_kineticlet(
        rt.state(), nvme.domain, kin_cap, KineticId{static_cast<u32>(boot::NVME_KINETIC_SLOT)}, prog
    ).is_ok(), "Kineticlet installed for shell test");
    MUCORE_CHECK(open_conduit(rt.state(), ConduitId{1}, nvme.domain, nvme.domain, true).is_ok(),
                 "Conduit opened");
    MUCORE_CHECK(bind_irq_pact(rt.state(), nvme.domain, irq_cap, IrqPactBinding{
        .active        = true,
        .irq           = IrqLine{static_cast<u16>(boot::NVME_IRQ_LINE)},
        .driver_domain = nvme.domain,
        .driver_thread = nvme.thread,
        .conduit       = ConduitId{1},
        .fast_kinetic  = KineticId{static_cast<u32>(boot::NVME_KINETIC_SLOT)},
    }).is_ok(), "IRQ pact bound");

    smp.shards[0].online = true;
    smp.shards[0].cpu_id = CpuId{0};
    MUCORE_CHECK(smp::alloc_shard_frame(smp, CpuId{0}, true).is_ok(), "Magazine primed");

    shell::CommandShell<SimHal> cmd_shell{rt, ini, boot::PLAN, &smp};
    shell::StringBuffer<4096> buf{};

    auto run_cmd = [&](const char* cmd_str) {
        buf.clear();
        char line[128]{};
        usize i = 0;
        while (cmd_str[i] != '\0' && i + 1 < sizeof(line)) {
            line[i] = cmd_str[i];
            ++i;
        }
        line[i] = '\0';
        cmd_shell.execute_line(line, buf.writer());
    };

    // 1. help
    run_cmd("help");
    MUCORE_CHECK(strstr(buf.data, "Interactive Diagnostic Shell") != nullptr, "help command executed");

    // 2. version
    run_cmd("version");
    MUCORE_CHECK(strstr(buf.data, "Four Synthesized Lineages") != nullptr, "version command executed");

    // 3. services
    run_cmd("services");
    MUCORE_CHECK(strstr(buf.data, "nvme") != nullptr && strstr(buf.data, "vfs") != nullptr,
                 "services command lists manifest services");

    // 4. ps
    run_cmd("ps");
    MUCORE_CHECK(strstr(buf.data, "IsochronousRt") != nullptr, "ps command lists Tier-0 RT threads");

    // 5. ns
    run_cmd("ns");
    MUCORE_CHECK(strstr(buf.data, "/dev/nvme0") != nullptr, "ns command lists per-domain namespaces");

    // 6. resolve
    run_cmd("resolve 3 /dev/nvme0");
    MUCORE_CHECK(strstr(buf.data, "CanPromoteHot: true") != nullptr, "resolve command resolves path");

    // 7. smp
    run_cmd("smp");
    MUCORE_CHECK(strstr(buf.data, "8 frames") != nullptr, "smp command reports magazine & watermark");

    // 8. mem
    run_cmd("mem");
    MUCORE_CHECK(strstr(buf.data, "4096") != nullptr, "mem command reports physical frame capacity");

    // 9. irq fast
    u64 const fast_before = rt.state().telemetry.ring0_fast_handled;
    run_cmd("irq fast");
    MUCORE_CHECK(strstr(buf.data, "CompleteFastPath") != nullptr, "irq fast executes Kineticlet in Ring 0");
    MUCORE_CHECK(rt.state().telemetry.ring0_fast_handled == fast_before + 1,
                 "telemetry tracks fast IRQ dispatch");

    // 10. irq fault
    u64 const esc_before = rt.state().telemetry.ring3_escalations;
    run_cmd("irq fault");
    MUCORE_CHECK(strstr(buf.data, "EscalateToUserspace") != nullptr, "irq fault detects error bit");
    MUCORE_CHECK(rt.state().telemetry.ring3_escalations == esc_before + 1,
                 "telemetry tracks Ring-3 escalation");

    // 11. crash supervision
    run_cmd("crash vfs");
    MUCORE_CHECK(strstr(buf.data, "RESTARTED via epoch bump") != nullptr,
                 "crash vfs triggers supervisor restart");
    MUCORE_CHECK(ini.services[boot::VFS].restarts == 1, "vfs restart counter bumped to 1");

    // 12. bench
    run_cmd("bench");
    MUCORE_CHECK(strstr(buf.data, "Context switches emitted: 0") != nullptr,
                 "bench verifies 0 switches in Ring 0");

    // 13. echo & clear
    run_cmd("echo hello mucore");
    MUCORE_CHECK(strstr(buf.data, "hello mucore") != nullptr, "echo works");
    run_cmd("clear");
    MUCORE_CHECK(strstr(buf.data, "\033[2J") != nullptr, "clear emits ANSI escape");

    // 14. caps
    run_cmd("caps");
    MUCORE_CHECK(strstr(buf.data, "DomainControl") != nullptr && strstr(buf.data, "Total active capabilities") != nullptr,
                 "caps command lists capability slots");

    // 15. trace
    run_cmd("trace");
    MUCORE_CHECK(strstr(buf.data, "Total Flight Recorder events logged") != nullptr,
                 "trace command reports Flight Recorder events");

    printf("  [PASS] 15 shell commands verified; REPL output, supervision & IRQs exact.\n");
    ++g_passed;
}

} // namespace

int main() {
    printf("======================================================================\n");
    printf("  μCore (mucore-kernel) — FCIS, Four-Lineage & SMP Verification Suite\n");
    printf("  Compile-Time `static_assert` Proofs (10 Theorem Suites): PASSED\n");
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
    test_vmspace_and_percore_magazines();
    test_concurrent_4thread_smp_sharding_and_replay();
    test_init_boot_and_supervision();
    test_interactive_command_shell();

    printf("----------------------------------------------------------------------\n");
    printf("Summary: %d passed, %d failed.\n", g_passed, g_failed);
    return (g_failed == 0) ? 0 : 1;
}
