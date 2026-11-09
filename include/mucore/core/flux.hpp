#pragma once
// ============================================================================
// μCore Functional Core — Flux Asynchronous Conduits & Thermal Tiering
// ============================================================================
// Resolves two classic OS contradictions:
//   1. Async Batching vs. Hard Real-Time Latency:
//      Bulk throughput travels over a Wait-Free SPSC ring (exact O(1) index
//      advance, zero CAS livelock), while time-critical events use a dedicated
//      capability-gated `UrgentSlot` that preempts head-of-line bulk queues.
//   2. Ring-0 Performance vs. Ring-3 Isolation:
//      Adaptive `ThermalState` hysteresis (`Cold` -> `Warm` -> `Hot`) promotes
//      high-frequency Conduits to Ring-0 polled / Kineticlet-intercepted mode
//      (0 syscalls, 0 context switches under load) and parks idle Conduits
//      in `Cold` doorbell-driven sleep (0 wasted CPU watts).
// ============================================================================

#include "mucore/result.hpp"
#include "mucore/types.hpp"

namespace mucore::core::flux {

inline constexpr u32 FLUX_RING_CAPACITY     = 32; // Power-of-two ring slots
inline constexpr u32 FLUX_RING_MASK         = FLUX_RING_CAPACITY - 1;
inline constexpr u32 WARM_PROMOTE_THRESHOLD = 4;
inline constexpr u32 HOT_PROMOTE_THRESHOLD  = 16;
inline constexpr u32 IDLE_DEMOTE_WINDOWS    = 3;

enum class ThermalState : u8 {
    Cold = 0, // Rare traffic: explicit SYSCALL doorbell wakes quiescent endpoint
    Warm = 1, // Moderate traffic: batched async ring + coalesced wakeup
    Hot  = 2, // High-frequency / RT pinned: Ring-0 SQ poll / Kineticlet active (0 syscalls!)
};

enum class DoorbellAction : u8 {
    None       = 0, // Receiver already polling in Hot mode — zero syscall/IRQ needed!
    BatchWake  = 1, // Wake receiver when batch watermark or timer expires
    WakeNow    = 2, // Cold channel transition — wake quiescent receiver
    PreemptNow = 3, // Urgent Real-Time slot populated — immediate scheduler preemption!
};

enum class FluxOpcode : u8 {
    Nop          = 0,
    ReadGrant    = 1, // Zero-copy read from GrantArena offset/len
    WriteGrant   = 2, // Zero-copy write into GrantArena offset/len
    DriverCmd    = 3, // Userspace driver command (e.g., NVMe/NIC descriptor batch)
    IrqAck       = 4, // Driver IRQ acknowledgement / completion
    CustomPact   = 5, // Service-defined Pact operation
};

// 32-byte cache-friendly Submission Queue Entry (SQE)
struct FluxSubmission {
    u64        user_tag{0};     // Caller correlation cookie (enables out-of-order completion!)
    FluxOpcode opcode{FluxOpcode::Nop};
    u8         flags{0};
    u16        sub_op{0};
    ArenaId    grant_arena{};   // Zero-copy shared memory arena (0 = inline payload)
    u32        offset_or_arg0{0};
    u32        length_or_arg1{0};
    u32        aux_param{0};
};

// 16-byte Completion Queue Entry (CQE)
struct FluxCompletion {
    u64   user_tag{0};
    i32   result_value{0};
    Error status{Error::None};
    u8    reserved[3]{};
};

// Pure Logical State of a Flux Conduit (Pure Functional Core model)
struct ConduitState {
    bool           active{false};
    ConduitId      id{};
    DomainId       producer{};
    DomainId       consumer{};
    ThreadId       consumer_worker{};  // Optional worker thread for L4-MCS CBS donation!
    PortId         bound_port{};       // Optional Zircon/NT O(1) readiness aggregator!
    u8             port_bind_slot{0};
    KineticId      attached_kinetic{}; // Optional Ring-0 Kineticlet fast-path hook!

    // Wait-Free SPSC ring indices (monotonic wrapping u32; occupancy = head - tail)
    u32            sq_head{0};
    u32            sq_tail{0};
    FluxSubmission sq_entries[FLUX_RING_CAPACITY]{};

    u32            cq_head{0};
    u32            cq_tail{0};
    FluxCompletion cq_entries[FLUX_RING_CAPACITY]{};

    // Out-of-band Hard Real-Time Urgent Slot (bypasses FIFO ring head-of-line blocking)
    bool           urgent_occupied{false};
    FluxSubmission urgent_entry{};

    // Adaptive Thermal Tiering telemetry
    ThermalState   thermal{ThermalState::Cold};
    bool           pinned_hot{false};  // True for Hard-RT channels locked in Hot tier
    u32            window_ops{0};
    u32            idle_windows{0};
    u64            zero_switch_fast_ops{0}; // Telemetry: ops completed with 0 context switches!
};

struct SubmitOutcome {
    u32            queued_depth{0};
    ThermalState   new_thermal{ThermalState::Cold};
    DoorbellAction doorbell{DoorbellAction::None};
};

// ============================================================================
// PURE FUNCTIONAL CORE RING & THERMAL LOGIC
// ============================================================================

[[nodiscard]] constexpr u32 sq_occupancy(ConduitState const& c) noexcept {
    return c.sq_head - c.sq_tail;
}

[[nodiscard]] constexpr u32 cq_occupancy(ConduitState const& c) noexcept {
    return c.cq_head - c.cq_tail;
}

[[nodiscard]] constexpr bool sq_is_full(ConduitState const& c) noexcept {
    return sq_occupancy(c) >= FLUX_RING_CAPACITY;
}

[[nodiscard]] constexpr bool cq_is_full(ConduitState const& c) noexcept {
    return cq_occupancy(c) >= FLUX_RING_CAPACITY;
}

// Pure thermal transition function with hysteresis (prevents thrashing between tiers)
[[nodiscard]] constexpr ThermalState compute_next_thermal(
    ThermalState current,
    bool         pinned_hot,
    u32          window_ops,
    u32          idle_windows
) noexcept {
    if (pinned_hot) {
        return ThermalState::Hot;
    }
    if (window_ops >= HOT_PROMOTE_THRESHOLD) {
        return ThermalState::Hot;
    }
    if (window_ops >= WARM_PROMOTE_THRESHOLD && current == ThermalState::Cold) {
        return ThermalState::Warm;
    }
    if (window_ops == 0 && idle_windows >= IDLE_DEMOTE_WINDOWS) {
        if (current == ThermalState::Hot) {
            return ThermalState::Warm;
        }
        return ThermalState::Cold;
    }
    return current;
}

// Pure doorbells minimization policy:
//   - If Urgent RT: ALWAYS `PreemptNow`.
//   - If `Hot` (polled / Kineticlet): `None` -> ZERO SYSCALL / ZERO CONTEXT SWITCH!
//   - If `Warm`: `BatchWake` only when ring transitions from empty or hits half-full watermark.
//   - If `Cold`: `WakeNow` on submission.
[[nodiscard]] constexpr DoorbellAction decide_doorbell(
    ThermalState thermal,
    bool         is_urgent,
    u32          prev_occupancy,
    u32          new_occupancy
) noexcept {
    if (is_urgent) {
        return DoorbellAction::PreemptNow;
    }
    switch (thermal) {
        case ThermalState::Hot:
            return DoorbellAction::None; // Receiver/Ring-0 fast path handles without trap!
        case ThermalState::Warm:
            if (prev_occupancy == 0 || new_occupancy >= (FLUX_RING_CAPACITY / 2)) {
                return DoorbellAction::BatchWake;
            }
            return DoorbellAction::None;
        case ThermalState::Cold:
            return DoorbellAction::WakeNow;
    }
    return DoorbellAction::WakeNow;
}

// Deterministic O(1) non-blocking submission into ConduitState
[[nodiscard]] constexpr Result<SubmitOutcome, Error> enqueue_submission(
    ConduitState&         conduit,
    FluxSubmission const& sub,
    bool                  urgent_rt
) noexcept {
    if (!conduit.active) {
        return Result<SubmitOutcome, Error>::err(Error::InvalidState);
    }

    u32 const prev_occ = sq_occupancy(conduit);

    if (urgent_rt) {
        if (conduit.urgent_occupied) {
            return Result<SubmitOutcome, Error>::err(Error::RingFull);
        }
        conduit.urgent_entry    = sub;
        conduit.urgent_occupied = true;
    } else {
        if (sq_is_full(conduit)) {
            return Result<SubmitOutcome, Error>::err(Error::RingFull);
        }
        conduit.sq_entries[conduit.sq_head & FLUX_RING_MASK] = sub;
        conduit.sq_head += 1;
    }

    conduit.window_ops += 1;
    conduit.idle_windows = 0;
    conduit.thermal = compute_next_thermal(
        conduit.thermal, conduit.pinned_hot, conduit.window_ops, conduit.idle_windows
    );

    u32 const new_occ = sq_occupancy(conduit);
    DoorbellAction const db = decide_doorbell(conduit.thermal, urgent_rt, prev_occ, new_occ);

    return Result<SubmitOutcome, Error>::ok(SubmitOutcome{
        .queued_depth = new_occ + (conduit.urgent_occupied ? 1u : 0u),
        .new_thermal  = conduit.thermal,
        .doorbell     = db,
    });
}

// Deterministic O(1) non-blocking dequeue: Urgent RT slot ALWAYS preempts bulk FIFO!
[[nodiscard]] constexpr Option<FluxSubmission> dequeue_submission(ConduitState& conduit) noexcept {
    if (!conduit.active) {
        return Option<FluxSubmission>::none();
    }
    if (conduit.urgent_occupied) {
        conduit.urgent_occupied = false;
        return Option<FluxSubmission>::some(conduit.urgent_entry);
    }
    if (sq_occupancy(conduit) == 0) {
        return Option<FluxSubmission>::none();
    }
    FluxSubmission const out = conduit.sq_entries[conduit.sq_tail & FLUX_RING_MASK];
    conduit.sq_tail += 1;
    return Option<FluxSubmission>::some(out);
}

[[nodiscard]] constexpr Result<Unit, Error> enqueue_completion(
    ConduitState&         conduit,
    FluxCompletion const& comp
) noexcept {
    if (!conduit.active) {
        return Result<Unit, Error>::err(Error::InvalidState);
    }
    if (cq_is_full(conduit)) {
        return Result<Unit, Error>::err(Error::RingFull);
    }
    conduit.cq_entries[conduit.cq_head & FLUX_RING_MASK] = comp;
    conduit.cq_head += 1;
    return Result<Unit, Error>::ok(Unit{});
}

[[nodiscard]] constexpr Option<FluxCompletion> dequeue_completion(ConduitState& conduit) noexcept {
    if (!conduit.active || cq_occupancy(conduit) == 0) {
        return Option<FluxCompletion>::none();
    }
    FluxCompletion const out = conduit.cq_entries[conduit.cq_tail & FLUX_RING_MASK];
    conduit.cq_tail += 1;
    return Option<FluxCompletion>::some(out);
}

// Periodic thermal decay tick (parks idle Hot channels back to Warm -> Cold)
constexpr ThermalState advance_thermal_window(ConduitState& conduit) noexcept {
    if (conduit.window_ops == 0) {
        conduit.idle_windows += 1;
    } else {
        conduit.idle_windows = 0;
    }
    conduit.thermal = compute_next_thermal(
        conduit.thermal, conduit.pinned_hot, conduit.window_ops, conduit.idle_windows
    );
    conduit.window_ops = 0;
    return conduit.thermal;
}

} // namespace mucore::core::flux
