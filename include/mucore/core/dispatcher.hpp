#pragma once
// ============================================================================
// μCore Functional Core — Top-Level Deterministic Kernel State Machine (v2)
// ============================================================================
// Unifies the Four-Lineage Hybrid Synthesis behind a Pure Functional Core:
//   - Zircon: `FluxPort` O(1) multi-conduit readiness & zero ambient VFS.
//   - Windows NT: MPK `GrantArena` TOCTOU sealing, IOMMU DMA crash quarantine,
//                 and co-located zero-IPC filter pipelines.
//   - Plan 9: Per-domain capability namespaces (`NamespaceTable`) with union
//             mount interposition ("Plan 9 Cold, Zero-Switch Hot").
//   - L4 MCS: Asynchronous CBS deadline & budget donation over Urgent Flux.
// ============================================================================

#include "mucore/core/capability.hpp"
#include "mucore/core/effects.hpp"
#include "mucore/core/flux.hpp"
#include "mucore/core/kinetic.hpp"
#include "mucore/core/memory.hpp"
#include "mucore/core/namespace_p9.hpp"
#include "mucore/core/port.hpp"
#include "mucore/core/scheduler.hpp"

namespace mucore::core {

inline constexpr usize MAX_CONDUITS      = 32;
inline constexpr usize MAX_KINETIC_SLOTS = 16;
inline constexpr usize MAX_IRQ_BINDINGS  = 16;

struct IrqPactBinding {
    bool      active{false};
    IrqLine   irq{};
    DomainId  driver_domain{};
    ThreadId  driver_thread{};
    ThreadId  urgent_wake_thread{};
    ConduitId conduit{};
    KineticId fast_kinetic{};
    ArenaId   shared_arena{};
};

struct KernelTelemetry {
    u64 total_events{0};
    u64 ring0_fast_handled{0};
    u64 ring3_escalations{0};
    u64 context_switches_emitted{0};
    u64 cr3_switches_emitted{0};
    u64 mcs_donations{0};
    u64 dma_quarantines{0};
};

struct KernelState {
    cap::CapTable             caps{};
    sched::SchedTable         sched{};
    mm::MemoryTable           mem{};
    ns::NamespaceTable        namespaces{};
    port::FluxPortState       ports[port::MAX_PORTS]{};
    flux::ConduitState        conduits[MAX_CONDUITS]{};
    kinetic::KineticSlotState kinetics[MAX_KINETIC_SLOTS]{};
    IrqPactBinding            irq_pacts[MAX_IRQ_BINDINGS]{};
    KernelTelemetry           telemetry{};

    constexpr KernelState() noexcept = default;
    KernelState(KernelState const&)            = delete;
    KernelState& operator=(KernelState const&) = delete;
    constexpr KernelState(KernelState&&) noexcept            = default;
    constexpr KernelState& operator=(KernelState&&) noexcept = default;
};

// ============================================================================
// HELPER LOOKUPS & PACT CONFIGURATION (Pure Deterministic Core)
// ============================================================================

[[nodiscard]] constexpr Option<usize> find_conduit_idx(
    KernelState const& state,
    ConduitId          id
) noexcept {
    if (!id) return Option<usize>::none();
    for (usize i = 0; i < MAX_CONDUITS; ++i) {
        if (state.conduits[i].active && state.conduits[i].id == id) {
            return Option<usize>::some(i);
        }
    }
    return Option<usize>::none();
}

[[nodiscard]] constexpr Option<usize> find_port_idx(
    KernelState const& state,
    PortId             id
) noexcept {
    if (!id) return Option<usize>::none();
    for (usize i = 0; i < port::MAX_PORTS; ++i) {
        if (state.ports[i].active && state.ports[i].id == id) {
            return Option<usize>::some(i);
        }
    }
    return Option<usize>::none();
}

[[nodiscard]] constexpr Option<usize> find_kinetic_idx(
    KernelState const& state,
    KineticId          id
) noexcept {
    if (!id) return Option<usize>::none();
    for (usize i = 0; i < MAX_KINETIC_SLOTS; ++i) {
        if (state.kinetics[i].installed && state.kinetics[i].id == id) {
            return Option<usize>::some(i);
        }
    }
    return Option<usize>::none();
}

[[nodiscard]] constexpr Result<ConduitId, Error> open_conduit(
    KernelState& state,
    ConduitId    desired_id,
    DomainId     producer,
    DomainId     consumer,
    bool         pinned_hot      = false,
    ThreadId     consumer_worker = ThreadId{0}
) noexcept {
    if (!desired_id || !producer || !consumer || find_conduit_idx(state, desired_id).is_some()) {
        return Result<ConduitId, Error>::err(Error::InvalidArgument);
    }
    for (usize i = 0; i < MAX_CONDUITS; ++i) {
        if (!state.conduits[i].active) {
            flux::ConduitState c{};
            c.active          = true;
            c.id              = desired_id;
            c.producer        = producer;
            c.consumer        = consumer;
            c.consumer_worker = consumer_worker;
            c.pinned_hot      = pinned_hot;
            c.thermal         = pinned_hot ? flux::ThermalState::Hot : flux::ThermalState::Cold;
            state.conduits[i] = c;
            return Result<ConduitId, Error>::ok(desired_id);
        }
    }
    return Result<ConduitId, Error>::err(Error::TableFull);
}

// Create a Zircon/NT-style O(1) readiness aggregator port
[[nodiscard]] constexpr Result<PortId, Error> create_flux_port(
    KernelState& state,
    PortId       desired_id,
    DomainId     owner,
    ThreadId     server_thread = ThreadId{0}
) noexcept {
    if (!desired_id || !owner || find_port_idx(state, desired_id).is_some()) {
        return Result<PortId, Error>::err(Error::InvalidArgument);
    }
    for (usize i = 0; i < port::MAX_PORTS; ++i) {
        if (!state.ports[i].active) {
            port::FluxPortState p{};
            p.active                = true;
            p.id                    = desired_id;
            p.owner                 = owner;
            p.waiting_server_thread = server_thread;
            state.ports[i]          = p;
            return Result<PortId, Error>::ok(desired_id);
        }
    }
    return Result<PortId, Error>::err(Error::TableFull);
}

// Bind a `FluxConduit` into a `FluxPort` so server polls 1 port in O(1) instead of N rings
[[nodiscard]] constexpr Result<Unit, Error> attach_conduit_to_port(
    KernelState& state,
    ConduitId    conduit_id,
    PortId       port_id,
    u64          user_key
) noexcept {
    auto c_idx = find_conduit_idx(state, conduit_id);
    auto p_idx = find_port_idx(state, port_id);
    if (c_idx.is_none() || p_idx.is_none()) {
        return Result<Unit, Error>::err(Error::NotFound);
    }

    auto slot_res = port::bind_conduit_to_port(state.ports[p_idx.value()], conduit_id, user_key);
    if (slot_res.is_err()) {
        return Result<Unit, Error>::err(slot_res.error());
    }

    state.conduits[c_idx.value()].bound_port     = port_id;
    state.conduits[c_idx.value()].port_bind_slot = slot_res.value();
    return Result<Unit, Error>::ok(Unit{});
}

[[nodiscard]] constexpr Result<kinetic::VerifyReport, Error> install_kineticlet(
    KernelState&                   state,
    DomainId                       caller,
    cap::CapToken                  kinetic_cap,
    KineticId                      desired_id,
    kinetic::KineticProgram const& program
) noexcept {
    if (!desired_id || find_kinetic_idx(state, desired_id).is_some()) {
        return Result<kinetic::VerifyReport, Error>::err(Error::InvalidArgument);
    }

    auto cap_res = cap::validate_capability(
        state.caps,
        caller,
        kinetic_cap,
        cap::CapObjectKind::KineticSlot,
        cap::CapRights::ExecuteRing0
    );
    if (cap_res.is_err()) {
        return Result<kinetic::VerifyReport, Error>::err(cap_res.error());
    }

    auto proof_res = kinetic::verify_program(program, cap_res.value().rights);
    if (proof_res.is_err()) {
        return Result<kinetic::VerifyReport, Error>::err(proof_res.error());
    }

    for (usize i = 0; i < MAX_KINETIC_SLOTS; ++i) {
        if (!state.kinetics[i].installed) {
            kinetic::KineticSlotState slot{};
            slot.installed    = true;
            slot.id           = desired_id;
            slot.owner        = caller;
            slot.program      = program;
            slot.proof        = proof_res.value();
            state.kinetics[i] = slot;
            return Result<kinetic::VerifyReport, Error>::ok(slot.proof);
        }
    }
    return Result<kinetic::VerifyReport, Error>::err(Error::TableFull);
}

[[nodiscard]] constexpr Result<Unit, Error> bind_irq_pact(
    KernelState&          state,
    DomainId              driver_domain,
    cap::CapToken         irq_cap,
    IrqPactBinding const& pact
) noexcept {
    auto cap_res = cap::validate_capability(
        state.caps,
        driver_domain,
        irq_cap,
        cap::CapObjectKind::IrqHook,
        cap::CapRights::Read | cap::CapRights::Write
    );
    if (cap_res.is_err()) {
        return Result<Unit, Error>::err(cap_res.error());
    }
    if (cap_res.value().object_id != pact.irq.raw) {
        return Result<Unit, Error>::err(Error::InvalidCapability);
    }

    for (usize i = 0; i < MAX_IRQ_BINDINGS; ++i) {
        if (!state.irq_pacts[i].active) {
            state.irq_pacts[i]        = pact;
            state.irq_pacts[i].active = true;
            return Result<Unit, Error>::ok(Unit{});
        }
    }
    return Result<Unit, Error>::err(Error::TableFull);
}

// ============================================================================
// TEARDOWN COUNTERPARTS (cold path: used when a domain exits or is restarted)
// ============================================================================

// Close a conduit: drop its `FluxPort` binding (with any pending readiness) and free the slot.
// Queued submissions and completions are discarded.
constexpr Result<Unit, Error> close_conduit(KernelState& state, ConduitId id) noexcept {
    auto c_idx = find_conduit_idx(state, id);
    if (c_idx.is_none()) {
        return Result<Unit, Error>::err(Error::NotFound);
    }
    flux::ConduitState& conduit = state.conduits[c_idx.value()];

    auto p_idx = find_port_idx(state, conduit.bound_port);
    if (p_idx.is_some()) {
        port::FluxPortState& p    = state.ports[p_idx.value()];
        u8 const             slot = conduit.port_bind_slot;
        if (slot < port::MAX_BOUND_PER_PORT && p.bindings[slot].bound &&
            p.bindings[slot].conduit == id) {
            (void)port::unbind_port_slot(p, slot);
        }
    }

    conduit = flux::ConduitState{};
    return Result<Unit, Error>::ok(Unit{});
}

// Close every conduit that has `domain` on either end.
constexpr u32 close_domain_conduits(KernelState& state, DomainId domain) noexcept {
    u32 closed = 0;
    for (usize i = 0; i < MAX_CONDUITS; ++i) {
        flux::ConduitState const& c = state.conduits[i];
        if (c.active && (c.producer == domain || c.consumer == domain)) {
            (void)close_conduit(state, c.id);
            ++closed;
        }
    }
    return closed;
}

// Destroy a readiness port; conduits still attached to it are detached, not closed.
constexpr Result<Unit, Error> destroy_flux_port(KernelState& state, PortId id) noexcept {
    auto p_idx = find_port_idx(state, id);
    if (p_idx.is_none()) {
        return Result<Unit, Error>::err(Error::NotFound);
    }
    for (usize i = 0; i < MAX_CONDUITS; ++i) {
        if (state.conduits[i].active && state.conduits[i].bound_port == id) {
            state.conduits[i].bound_port     = PortId{0};
            state.conduits[i].port_bind_slot = 0;
        }
    }
    state.ports[p_idx.value()] = port::FluxPortState{};
    return Result<Unit, Error>::ok(Unit{});
}

// Unbind the IRQ pacts and uninstall the Ring-0 Kineticlets owned by `domain`, so no
// interrupt can be routed to (or charged against) a domain that no longer exists.
constexpr u32 release_domain_fast_paths(KernelState& state, DomainId domain) noexcept {
    u32 released = 0;
    for (usize i = 0; i < MAX_IRQ_BINDINGS; ++i) {
        if (state.irq_pacts[i].active && state.irq_pacts[i].driver_domain == domain) {
            state.irq_pacts[i] = IrqPactBinding{};
            ++released;
        }
    }
    for (usize i = 0; i < MAX_KINETIC_SLOTS; ++i) {
        if (state.kinetics[i].installed && state.kinetics[i].owner == domain) {
            state.kinetics[i] = kinetic::KineticSlotState{};
            ++released;
        }
    }
    return released;
}

constexpr void append_sched_effects(
    KernelState&                state,
    EffectBatch&                effects,
    sched::SchedDecision const& dec
) noexcept {
    if (dec.requires_address_space_switch && dec.next_domain) {
        state.telemetry.cr3_switches_emitted += 1;
        (void)effects.push(KernelEffect{
            .kind          = EffectKind::SwitchAddressSpace,
            .target_domain = dec.next_domain,
        });
    }
    if (dec.requires_context_switch && dec.next_thread) {
        state.telemetry.context_switches_emitted += 1;
        (void)effects.push(KernelEffect{
            .kind          = EffectKind::SwitchThreadContext,
            .target_domain = dec.next_domain,
            .target_thread = dec.next_thread,
        });
    }
    if (dec.next_timer_deadline.raw != 0) {
        (void)effects.push(KernelEffect{
            .kind     = EffectKind::ArmOneShotTimer,
            .deadline = dec.next_timer_deadline,
        });
    }
    if (!dec.next_thread) {
        (void)effects.push(KernelEffect{
            .kind = EffectKind::CpuIdleWait,
        });
    }
}

// ============================================================================
// TOP-LEVEL PURE EVENT DISPATCHER (`KernelEvent` -> `EffectBatch`)
// ============================================================================

[[nodiscard]] constexpr Result<EffectBatch, Error> dispatch_event(
    KernelState&       state,
    KernelEvent const& ev
) noexcept {
    state.telemetry.total_events += 1;
    EffectBatch effects{};

    switch (ev.kind) {
        // --------------------------------------------------------------------
        // 1. Tickless One-Shot Timer Expiration -> CBS/EDF + Async Reschedule
        // --------------------------------------------------------------------
        case EventKind::TimerExpired: {
            auto dec = sched::schedule_at(state.sched, ev.timestamp);
            append_sched_effects(state, effects, dec);
            return Result<EffectBatch, Error>::ok(mucore::move(effects));
        }

        // --------------------------------------------------------------------
        // 2. Hardware IRQ -> Split-Plane Ring-0 Kineticlet OR Ring-3 Driver!
        // --------------------------------------------------------------------
        case EventKind::HardwareIrq: {
            Option<usize> pact_idx = Option<usize>::none();
            for (usize i = 0; i < MAX_IRQ_BINDINGS; ++i) {
                if (state.irq_pacts[i].active && state.irq_pacts[i].irq == ev.irq_line) {
                    pact_idx = Option<usize>::some(i);
                    break;
                }
            }
            if (pact_idx.is_none()) {
                return Result<EffectBatch, Error>::err(Error::NotFound);
            }

            IrqPactBinding const& pact = state.irq_pacts[pact_idx.value()];
            auto kin_idx = find_kinetic_idx(state, pact.fast_kinetic);

            if (kin_idx.is_some()) {
                kinetic::KineticSlotState& kslot = state.kinetics[kin_idx.value()];
                kslot.invocations += 1;

                u64* arena_ptr = nullptr;
                auto ar_idx = mm::find_arena_slot(state.mem, pact.shared_arena);
                if (ar_idx.is_some()) {
                    arena_ptr = state.mem.arenas[ar_idx.value()].kinetic_words;
                }

                kinetic::KineticInput const input{
                    .arg0 = ev.irq_status_word,
                    .arg1 = ev.timestamp.raw,
                    .arg2 = pact.irq.raw,
                    .arg3 = 0,
                };

                auto exec_res = kinetic::execute_verified(
                    kslot.program, input, kslot.persistent_state, arena_ptr
                );
                if (exec_res.is_err()) {
                    return Result<EffectBatch, Error>::err(exec_res.error());
                }

                kinetic::KineticOutput const& kout = exec_res.value();
                for (usize s = 0; s < kinetic::NUM_KINETIC_STATE_REGS; ++s) {
                    kslot.persistent_state[s] = kout.next_state[s];
                }

                sched::charge_external_wcet(state.sched, pact.driver_thread, kslot.proof.wcet_ns);

                switch (kout.verdict) {
                    case kinetic::ReturnVerdict::CompleteFastPath:
                    case kinetic::ReturnVerdict::DropSilent: {
                        kslot.fast_completions += 1;
                        state.telemetry.ring0_fast_handled += 1;

                        if (kout.verdict == kinetic::ReturnVerdict::CompleteFastPath) {
                            auto c_idx = find_conduit_idx(state, pact.conduit);
                            if (c_idx.is_some()) {
                                state.conduits[c_idx.value()].zero_switch_fast_ops += 1;
                                (void)flux::enqueue_completion(
                                    state.conduits[c_idx.value()],
                                    flux::FluxCompletion{
                                        .user_tag     = ev.timestamp.raw,
                                        .result_value = static_cast<i32>(kout.return_value),
                                        .status       = Error::None,
                                    }
                                );
                            }
                        }

                        (void)effects.push(KernelEffect{
                            .kind        = EffectKind::AckIrqFastPath,
                            .irq_line    = pact.irq,
                            .fast_result = kout.return_value,
                        });
                        return Result<EffectBatch, Error>::ok(mucore::move(effects));
                    }

                    case kinetic::ReturnVerdict::WakeUrgentRt: {
                        kslot.fast_completions += 1;
                        state.telemetry.ring0_fast_handled += 1;

                        auto wake_slot = sched::find_thread_slot(state.sched, pact.urgent_wake_thread);
                        if (wake_slot.is_some()) {
                            auto& tcb = state.sched.threads[wake_slot.value()];
                            if (tcb.state == sched::ThreadState::Blocked) {
                                tcb.state = sched::ThreadState::Ready;
                            }
                        }

                        (void)effects.push(KernelEffect{
                            .kind        = EffectKind::AckIrqFastPath,
                            .irq_line    = pact.irq,
                            .fast_result = kout.return_value,
                        });
                        auto dec = sched::schedule_at(state.sched, ev.timestamp);
                        append_sched_effects(state, effects, dec);
                        return Result<EffectBatch, Error>::ok(mucore::move(effects));
                    }

                    case kinetic::ReturnVerdict::EscalateToUserspace:
                        kslot.escalations += 1;
                        break;
                }
            }

            state.telemetry.ring3_escalations += 1;
            auto drv_slot = sched::find_thread_slot(state.sched, pact.driver_thread);
            if (drv_slot.is_some()) {
                auto& drv_tcb = state.sched.threads[drv_slot.value()];
                if (drv_tcb.state == sched::ThreadState::Blocked) {
                    drv_tcb.state = sched::ThreadState::Ready;
                }
            }

            (void)effects.push(KernelEffect{
                .kind          = EffectKind::EscalateToUserspaceDrv,
                .target_domain = pact.driver_domain,
                .target_thread = pact.driver_thread,
                .conduit_id    = pact.conduit,
                .irq_line      = pact.irq,
            });

            auto dec = sched::schedule_at(state.sched, ev.timestamp);
            append_sched_effects(state, effects, dec);
            return Result<EffectBatch, Error>::ok(mucore::move(effects));
        }

        // --------------------------------------------------------------------
        // 3. Flux Async Conduit Submission (MPK Seal + Port O(1) + L4 MCS Loan!)
        // --------------------------------------------------------------------
        case EventKind::FluxSubmit: {
            u16 req_rights = cap::CapRights::Write;
            if (ev.urgent_rt) {
                req_rights |= cap::CapRights::UrgentRt;
            }

            auto cap_res = cap::validate_capability(
                state.caps,
                ev.caller_domain,
                ev.cap_token,
                cap::CapObjectKind::FluxConduit,
                req_rights
            );
            if (cap_res.is_err()) {
                return Result<EffectBatch, Error>::err(cap_res.error());
            }

            ConduitId const cid{static_cast<u32>(cap_res.value().object_id)};
            auto c_idx = find_conduit_idx(state, cid);
            if (c_idx.is_none()) {
                return Result<EffectBatch, Error>::err(Error::NotFound);
            }

            flux::ConduitState& conduit = state.conduits[c_idx.value()];

            // If zero-copy GrantArena attached, transfer lease & MPK-seal sender writes!
            if (ev.submission.grant_arena) {
                auto seal_res = mm::transfer_arena_lease(
                    state.mem,
                    ev.submission.grant_arena,
                    ev.caller_domain,
                    conduit.consumer,
                    true
                );
                if (seal_res.is_err()) {
                    return Result<EffectBatch, Error>::err(seal_res.error());
                }
                (void)effects.push(KernelEffect{
                    .kind          = EffectKind::UpdateProtectionKey,
                    .target_domain = ev.caller_domain,
                    .mpk_key       = seal_res.value(),
                });
            }

            // Optional Ring-0 Kineticlet synchronous fast-path interception
            auto kin_idx = find_kinetic_idx(state, conduit.attached_kinetic);
            if (kin_idx.is_some() && !ev.urgent_rt) {
                kinetic::KineticSlotState& kslot = state.kinetics[kin_idx.value()];
                kslot.invocations += 1;

                u64* arena_ptr = nullptr;
                auto ar_idx = mm::find_arena_slot(state.mem, ev.submission.grant_arena);
                if (ar_idx.is_some()) {
                    arena_ptr = state.mem.arenas[ar_idx.value()].kinetic_words;
                }

                kinetic::KineticInput const input{
                    .arg0 = static_cast<u64>(ev.submission.opcode),
                    .arg1 = ev.submission.offset_or_arg0,
                    .arg2 = ev.submission.length_or_arg1,
                    .arg3 = ev.submission.aux_param,
                };

                auto exec_res = kinetic::execute_verified(
                    kslot.program, input, kslot.persistent_state, arena_ptr
                );
                if (exec_res.is_ok() &&
                    exec_res.value().verdict == kinetic::ReturnVerdict::CompleteFastPath) {
                    auto const& kout = exec_res.value();
                    for (usize s = 0; s < kinetic::NUM_KINETIC_STATE_REGS; ++s) {
                        kslot.persistent_state[s] = kout.next_state[s];
                    }
                    kslot.fast_completions += 1;
                    conduit.zero_switch_fast_ops += 1;
                    state.telemetry.ring0_fast_handled += 1;

                    (void)flux::enqueue_completion(
                        conduit,
                        flux::FluxCompletion{
                            .user_tag     = ev.submission.user_tag,
                            .result_value = static_cast<i32>(kout.return_value),
                            .status       = Error::None,
                        }
                    );
                    return Result<EffectBatch, Error>::ok(mucore::move(effects));
                }
            }

            auto sub_res = flux::enqueue_submission(conduit, ev.submission, ev.urgent_rt);
            if (sub_res.is_err()) {
                return Result<EffectBatch, Error>::err(sub_res.error());
            }

            // Signal Zircon/NT O(1) `FluxPort` aggregator if bound!
            if (conduit.bound_port) {
                auto p_idx = find_port_idx(state, conduit.bound_port);
                if (p_idx.is_some()) {
                    (void)port::signal_port_slot(
                        state.ports[p_idx.value()], conduit.port_bind_slot, ev.urgent_rt
                    );
                }
            }

            // L4-MCS Scheduling Context Donation on Urgent-RT calls!
            if (ev.urgent_rt && ev.caller_thread && conduit.consumer_worker) {
                auto loan_res = sched::donate_cbs_context(
                    state.sched, ev.caller_thread, conduit.consumer_worker
                );
                if (loan_res.is_ok()) {
                    state.telemetry.mcs_donations += 1;
                }
            }

            flux::SubmitOutcome const& outcome = sub_res.value();
            if (outcome.doorbell == flux::DoorbellAction::None) {
                conduit.zero_switch_fast_ops += 1;
                state.telemetry.ring0_fast_handled += 1;
            } else {
                (void)effects.push(KernelEffect{
                    .kind          = EffectKind::NotifyConduitDoorbell,
                    .target_domain = conduit.consumer,
                    .conduit_id    = conduit.id,
                    .doorbell      = outcome.doorbell,
                });
            }

            if (outcome.doorbell == flux::DoorbellAction::PreemptNow) {
                auto dec = sched::schedule_at(state.sched, ev.timestamp);
                append_sched_effects(state, effects, dec);
            }
            return Result<EffectBatch, Error>::ok(mucore::move(effects));
        }

        // --------------------------------------------------------------------
        // 4. Flux Completion + L4-MCS Borrowed CBS Context Return!
        // --------------------------------------------------------------------
        case EventKind::FluxComplete: {
            auto c_idx = find_conduit_idx(state, ev.conduit_id);
            if (c_idx.is_none()) {
                return Result<EffectBatch, Error>::err(Error::NotFound);
            }

            auto comp_res = flux::enqueue_completion(state.conduits[c_idx.value()], ev.completion);
            if (comp_res.is_err()) {
                return Result<EffectBatch, Error>::err(comp_res.error());
            }

            if (ev.caller_thread) {
                // Account elapsed worker runtime BEFORE returning leftover CBS budget to donor!
                (void)sched::schedule_at(state.sched, ev.timestamp);
                auto ret_res = sched::return_cbs_context(state.sched, ev.caller_thread);
                if (ret_res.is_ok()) {
                    auto dec = sched::schedule_at(state.sched, ev.timestamp);
                    append_sched_effects(state, effects, dec);
                }
            }
            return Result<EffectBatch, Error>::ok(mucore::move(effects));
        }

        // --------------------------------------------------------------------
        // 5. Periodic Thermal Sweep (Demotes Idle Hot Conduits -> Warm -> Cold)
        // --------------------------------------------------------------------
        case EventKind::ThermalSweep: {
            for (usize i = 0; i < MAX_CONDUITS; ++i) {
                if (state.conduits[i].active) {
                    (void)flux::advance_thermal_window(state.conduits[i]);
                }
            }
            return Result<EffectBatch, Error>::ok(mucore::move(effects));
        }

        // --------------------------------------------------------------------
        // 6. O(1) Epoch Lineage Revocation
        // --------------------------------------------------------------------
        case EventKind::RevokeCapability: {
            auto mut_res = cap::plan_revoke_lineage(
                state.caps, ev.caller_domain, ev.cap_token
            );
            if (mut_res.is_err()) {
                return Result<EffectBatch, Error>::err(mut_res.error());
            }
            cap::apply_mutation(state.caps, mut_res.value());
            return Result<EffectBatch, Error>::ok(mucore::move(effects));
        }

        // --------------------------------------------------------------------
        // 7. NT-Style Crash Teardown & IOMMU DMA Quarantine
        // --------------------------------------------------------------------
        case EventKind::DomainCrashTeardown: {
            u32 const quarantined = mm::quarantine_domain_arenas(state.mem, ev.caller_domain);
            if (quarantined > 0) {
                state.telemetry.dma_quarantines += quarantined;
                (void)effects.push(KernelEffect{
                    .kind          = EffectKind::QuarantineIommuDomain,
                    .target_domain = ev.caller_domain,
                    .fast_result   = quarantined,
                });
            }
            return Result<EffectBatch, Error>::ok(mucore::move(effects));
        }
    }

    return Result<EffectBatch, Error>::err(Error::InvalidArgument);
}

} // namespace mucore::core
