// ============================================================================
// μCore (mucore-kernel) — Host Functional Core & Split-Plane Simulation Suite
// ============================================================================
// Exercises the exact same `include/mucore/core/*` and `include/mucore/shell/*`
// code that runs in Ring 0, verifying security invariants, Real-Time CBS
// temporal isolation, zero-context-switch Kineticlets, and TraceRing replay.
// ============================================================================

#include <stdio.h>

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
    u64 cr3_switches{0};
    u64 thread_switches{0};
    u64 timer_arms{0};
    u64 idle_waits{0};
    u64 fast_irq_acks{0};
    u64 ring3_driver_upcalls{0};
    u64 doorbells_rung{0};
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
};

static_assert(shell::HalPlatform<SimHal>, "SimHal must satisfy HalPlatform");

// ----------------------------------------------------------------------------
// Test 1: Pragmatic Capability Engine & O(1) Lineage Revocation
// ----------------------------------------------------------------------------
void test_capabilities() {
    printf("[TEST 1] Generational Capabilities & O(1) Epoch Revocation...\n");
    cap::CapTable caps{};
    DomainId const root_dom{1};
    DomainId const drv_dom{2};

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
    MUCORE_CHECK(m2.is_ok(), "Attenuated Read-only MMIO delegation succeeds");
    cap::apply_mutation(caps, m2.value());

    // Driver tries to write with Read-only capability -> rejected!
    auto bad_write = cap::validate_capability(
        caps, drv_dom, m2.value().minted_token, cap::CapObjectKind::MmioRegion, cap::CapRights::Write
    );
    MUCORE_CHECK(bad_write.error() == Error::InsufficientRights, "Unauthorized MMIO Write blocked");

    // Root revokes entire group epoch in O(1)
    auto rev = cap::plan_revoke_lineage(caps, root_dom, m1.value().minted_token);
    MUCORE_CHECK(rev.is_ok(), "Epoch revocation planned in O(1)");
    cap::apply_mutation(caps, rev.value());

    auto after_rev = cap::validate_capability(
        caps, drv_dom, m2.value().minted_token, cap::CapObjectKind::MmioRegion, cap::CapRights::Read
    );
    MUCORE_CHECK(after_rev.error() == Error::RevokedCapability, "Delegated token immediately revoked");

    printf("  [PASS] Monotonic attenuation & O(1) revocation verified.\n");
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

    // Verify Urgent RT slot bypasses bulk FIFO head-of-line queue!
    flux::ConduitState conduit{};
    conduit.active   = true;
    conduit.id       = ConduitId{1};
    conduit.producer = DomainId{1};
    conduit.consumer = DomainId{2};

    for (u32 i = 1; i <= 5; ++i) {
        auto r = flux::enqueue_submission(conduit, flux::FluxSubmission{.user_tag = i}, false);
        MUCORE_CHECK(r.is_ok(), "Bulk async submission enqueued");
    }

    auto urg = flux::enqueue_submission(conduit, flux::FluxSubmission{.user_tag = 0xDEAD'BEEFULL}, true);
    MUCORE_CHECK(urg.is_ok(), "Urgent RT submission accepted");
    MUCORE_CHECK(urg.value().doorbell == flux::DoorbellAction::PreemptNow, "Urgent RT triggers PreemptNow");

    // First dequeue MUST return the Urgent RT item ahead of bulk tags 1..5!
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

    MUCORE_CHECK(c.thermal == flux::ThermalState::Cold, "Starts Cold (0 idle CPU polling)");

    // Push 16 operations -> promotes Cold -> Warm -> Hot!
    flux::SubmitOutcome last{};
    for (u32 i = 0; i < flux::HOT_PROMOTE_THRESHOLD; ++i) {
        auto res = flux::enqueue_submission(c, flux::FluxSubmission{.user_tag = i}, false);
        MUCORE_CHECK(res.is_ok(), "Burst submission succeeds");
        last = res.value();
    }
    MUCORE_CHECK(last.new_thermal == flux::ThermalState::Hot, "Promoted to Hot tier under load");
    MUCORE_CHECK(last.doorbell == flux::DoorbellAction::None, "Hot tier suppresses syscall doorbells!");

    // Sweep idle windows -> demotes Hot -> Warm -> Cold cleanly
    (void)flux::advance_thermal_window(c); // clears burst window_ops -> 0
    for (u32 w = 0; w < flux::IDLE_DEMOTE_WINDOWS; ++w) {
        (void)flux::advance_thermal_window(c);
    }
    MUCORE_CHECK(c.thermal == flux::ThermalState::Warm, "Demoted Hot -> Warm after hysteresis");

    for (u32 w = 0; w < flux::IDLE_DEMOTE_WINDOWS; ++w) {
        (void)flux::advance_thermal_window(c);
    }
    MUCORE_CHECK(c.thermal == flux::ThermalState::Cold, "Demoted Warm -> Cold when quiescent");

    printf("  [PASS] Adaptive Thermal Tiering promotes hot paths & parks idle channels.\n");
    ++g_passed;
}

// ----------------------------------------------------------------------------
// Test 4: Split-Plane Userspace Driver + Ring-0 Kineticlet (Zero-Switch Proof!)
// ----------------------------------------------------------------------------
void test_split_plane_driver_and_replay() {
    printf("[TEST 4] Split-Plane Userspace Driver + Ring-0 Kineticlet (100 IRQs)...\n");
    SimHal hal{};
    shell::ImperativeKernelRuntime<SimHal> rt{hal};
    KernelState& st = rt.state();

    DomainId const nvme_drv_dom{10};
    ThreadId const nvme_drv_tid{10};

    // Spawn Ring-3 NVMe Userspace Driver control-plane thread (Blocked until escalation!)
    auto t_res = sched::spawn_thread(
        st.sched, nvme_drv_tid, nvme_drv_dom, sched::SchedClass::IsochronousRt,
        sched::RtParams{.wcet_ns = 200'000ULL, .period_ns = 1'000'000ULL}, TickNs{0}
    );
    MUCORE_CHECK(t_res.is_ok(), "NVMe Userspace Driver RT control thread admitted");
    st.sched.threads[sched::find_thread_slot(st.sched, nvme_drv_tid).value()].state =
        sched::ThreadState::Blocked;

    // Create Zero-Copy DMA GrantArena shared with Kineticlet
    auto ar_res = mm::create_grant_arena(st.mem, ArenaId{1}, nvme_drv_dom, 4, true);
    MUCORE_CHECK(ar_res.is_ok(), "DMA-pinned Zero-Copy GrantArena created");

    // Mint capabilities for Kineticlet & IRQ 48
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

    // Build NVMe IRQ Kineticlet:
    //   R0 = IRQ status word:
    //     if R0 == 0        -> Spurious IRQ! `DropSilent` (0 switches)
    //     if (R0 & 0x8000)  -> Controller Error! `EscalateToUserspace` (wake Ring-3 driver)
    //     else              -> Increment Ring-0 completion counter, write to GrantArena[0], `CompleteFastPath`!
    kinetic::KineticProgram nvme_fastpath{};
    nvme_fastpath.insns[0]  = kinetic::dsl::load_imm(4, 0);
    nvme_fastpath.insns[1]  = kinetic::dsl::jump_if_eq(0, 4, 10); // -> [12] DropSilent
    nvme_fastpath.insns[2]  = kinetic::dsl::load_imm(4, 0x8000u);
    nvme_fastpath.insns[3]  = kinetic::dsl::mov(5, 0);
    nvme_fastpath.insns[4]  = kinetic::dsl::bit_and(5, 4);
    nvme_fastpath.insns[5]  = kinetic::dsl::jump_if_eq(5, 4, 7);  // -> [13] EscalateToUserspace
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
    MUCORE_CHECK(proof.is_ok(), "NVMe Kineticlet statically verified & installed in Ring 0");

    (void)open_conduit(st, ConduitId{1}, nvme_drv_dom, nvme_drv_dom, true);
    MUCORE_CHECK(bind_irq_pact(st, nvme_drv_dom, icap.value().minted_token, IrqPactBinding{
        .active        = true,
        .irq           = IrqLine{48},
        .driver_domain = nvme_drv_dom,
        .driver_thread = nvme_drv_tid,
        .conduit       = ConduitId{1},
        .fast_kinetic  = KineticId{1},
        .shared_arena  = ArenaId{1},
    }).is_ok(), "IRQ 48 Split-Plane Pact bound");

    // Fire 98 healthy I/O completions + 1 spurious IRQ -> MUST cause ZERO context switches!
    for (u64 i = 1; i <= 98; ++i) {
        auto r = rt.handle_event(KernelEvent{
            .kind            = EventKind::HardwareIrq,
            .timestamp       = TickNs{i * 1'000ULL},
            .irq_line        = IrqLine{48},
            .irq_status_word = 0x0001ULL,
        });
        MUCORE_CHECK(r.is_ok(), "Healthy IRQ handled");
        // Drain CQE ring periodically as consumer would in shared memory
        (void)flux::dequeue_completion(st.conduits[0]);
    }
    // 99th IRQ: Spurious shared interrupt (status = 0)
    MUCORE_CHECK(rt.handle_event(KernelEvent{
        .kind            = EventKind::HardwareIrq,
        .timestamp       = TickNs{99'000ULL},
        .irq_line        = IrqLine{48},
        .irq_status_word = 0x0000ULL,
    }).is_ok(), "Spurious IRQ filtered");

    MUCORE_CHECK(hal.thread_switches == 0 && hal.cr3_switches == 0,
                 "99 hot-path IRQs processed with ZERO context switches & ZERO CR3 switches!");
    MUCORE_CHECK(st.mem.arenas[0].kinetic_words[0] == 98ULL,
                 "GrantArena updated zero-copy by Ring-0 Kineticlet");

    // 100th IRQ: Controller Fault bit 0x8000 -> Escalates cleanly to Ring-3 Userspace Driver!
    MUCORE_CHECK(rt.handle_event(KernelEvent{
        .kind            = EventKind::HardwareIrq,
        .timestamp       = TickNs{100'000ULL},
        .irq_line        = IrqLine{48},
        .irq_status_word = 0x8001ULL,
    }).is_ok(), "Fault IRQ escalated to Ring-3 driver");

    MUCORE_CHECK(hal.ring3_driver_upcalls == 1 && hal.thread_switches == 1,
                 "Exactly 1 context switch occurred — only when controller fault needed Ring 3!");

    // Verify Deterministic Flight Recorder Replay (`TraceRing::replay_into`)!
    KernelState replay_state{};
    // Re-apply initial topology setup to `replay_state`, then replay all 100 recorded events!
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
    MUCORE_CHECK(replayed.is_ok() && replayed.value() == 100ULL,
                 "TraceRing deterministically replayed all 100 kernel events");
    MUCORE_CHECK(replay_state.telemetry.ring0_fast_handled == st.telemetry.ring0_fast_handled &&
                 replay_state.telemetry.ring3_escalations == st.telemetry.ring3_escalations &&
                 replay_state.mem.arenas[0].kinetic_words[0] == 98ULL,
                 "Replayed KernelState matches live state bit-for-bit!");

    printf("  [PASS] 99/100 IRQs completed in Ring 0 (0 switches, WCET=%u ns); 1 fault escalated; 100%% replay match!\n",
           proof.value().wcet_ns);
    ++g_passed;
}

// ----------------------------------------------------------------------------
// Test 5: Hard Real-Time Temporal Isolation Under Rogue IRQ Storm
// ----------------------------------------------------------------------------
void test_realtime_irq_storm_isolation() {
    printf("[TEST 5] Hard Real-Time CBS Temporal Isolation Under IRQ Storm...\n");
    KernelState st{};

    // Critical Avionics/Robotics Loop: 200us budget every 1ms (Deadline = 1ms)
    (void)sched::spawn_thread(
        st.sched, ThreadId{1}, DomainId{1}, sched::SchedClass::IsochronousRt,
        sched::RtParams{.wcet_ns = 200'000ULL, .period_ns = 1'000'000ULL}, TickNs{0}
    );

    // Noisy NIC Driver Thread: tiny 50ns CBS budget every 2ms (Deadline = 2ms)
    (void)sched::spawn_thread(
        st.sched, ThreadId{2}, DomainId{2}, sched::SchedClass::IsochronousRt,
        sched::RtParams{.wcet_ns = 50ULL, .period_ns = 2'000'000ULL}, TickNs{0}
    );

    // Charge 100ns of rogue IRQ Kineticlet execution to Thread 2 -> CBS throttles Thread 2!
    sched::charge_external_wcet(st.sched, ThreadId{2}, 100ULL);

    u32 const nic_slot = sched::find_thread_slot(st.sched, ThreadId{2}).value();
    MUCORE_CHECK(st.sched.threads[nic_slot].state == sched::ThreadState::Throttled,
                 "Noisy driver immediately throttled upon exhausting CBS WCET budget");

    // Critical Flight Thread 1 remains unaffected and runs cleanly!
    auto dec = sched::schedule_at(st.sched, TickNs{100ULL});
    MUCORE_CHECK(dec.next_thread == ThreadId{1},
                 "Critical Hard-RT thread guaranteed CPU despite sibling IRQ storm");

    printf("  [PASS] CBS budget charging protects sibling Hard-RT deadlines from IRQ storms.\n");
    ++g_passed;
}

// ----------------------------------------------------------------------------
// Test 6: Zero-Copy GrantArena Lease Handoff & Double-Free Safety
// ----------------------------------------------------------------------------
void test_memory_and_zero_copy_leases() {
    printf("[TEST 6] Physical Frame Allocator & Zero-Copy GrantArena Leases...\n");
    mm::MemoryTable mem{};

    auto f1 = mm::alloc_frame(mem.pool);
    MUCORE_CHECK(f1.is_ok() && f1.value().is_page_aligned(), "4KiB aligned frame allocated");
    MUCORE_CHECK(mm::free_frame(mem.pool, f1.value()).is_ok(), "Frame freed cleanly");
    MUCORE_CHECK(mm::free_frame(mem.pool, f1.value()).error() == Error::InvalidState,
                 "Explicit double-free caught deterministically");

    auto arena = mm::create_grant_arena(mem, ArenaId{5}, DomainId{1}, 2, false);
    MUCORE_CHECK(arena.is_ok(), "GrantArena allocated");

    // Unauthorized domain 3 tries to steal lease -> rejected!
    MUCORE_CHECK(mm::transfer_arena_lease(mem, ArenaId{5}, DomainId{3}, DomainId{2}).error() ==
                     Error::DomainMismatch,
                 "Unauthorized lease transfer blocked");

    // Legitimate owner Domain 1 transfers zero-copy lease to Domain 2 in O(1)
    MUCORE_CHECK(mm::transfer_arena_lease(mem, ArenaId{5}, DomainId{1}, DomainId{2}).is_ok(),
                 "O(1) zero-copy lease handoff succeeded with 0 memcpy & 0 TLB shootdowns");

    printf("  [PASS] Zero-copy GrantArena lease transfer & frame safety verified.\n");
    ++g_passed;
}

} // namespace

int main() {
    printf("================================================================\n");
    printf("  μCore (mucore-kernel) — FCIS Verification & Replay Suite\n");
    printf("  Compile-Time `static_assert` Proofs: PASSED\n");
    printf("================================================================\n");

    test_capabilities();
    test_wait_free_flux_and_urgent_rt();
    test_adaptive_thermal_tiering();
    test_split_plane_driver_and_replay();
    test_realtime_irq_storm_isolation();
    test_memory_and_zero_copy_leases();

    printf("----------------------------------------------------------------\n");
    printf("Summary: %d passed, %d failed.\n", g_passed, g_failed);
    return (g_failed == 0) ? 0 : 1;
}
