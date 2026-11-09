#pragma once
// ============================================================================
// μCore Functional Core — Explicit Algebraic Events & Hardware Effects
// ============================================================================
// The Strict Boundary of Functional Core / Imperative Shell (FCIS):
//   - Imperative Shell translates messy hardware interrupts, `SYSCALL` traps,
//     and APIC timer ticks into pure value `KernelEvent` structs.
//   - Functional Core computes state transitions deterministically and returns
//     an explicit `EffectBatch` (`StaticVec<KernelEffect, 8>`).
//   - Imperative Shell executes each `KernelEffect` against real CPU registers,
//     MMU CR3/PCID, PKRU/MPK keys, IOMMU quarantine, and APIC TSC-Deadline.
// ============================================================================

#include "mucore/array_vec.hpp"
#include "mucore/types.hpp"
#include "mucore/core/capability.hpp"
#include "mucore/core/flux.hpp"

namespace mucore::core {

inline constexpr usize MAX_EFFECTS_PER_STEP = 8;

enum class EventKind : u8 {
    TimerExpired        = 0, // One-shot APIC TSC-Deadline timer fired
    HardwareIrq         = 1, // External device interrupt (MSI-X / IOAPIC)
    FluxSubmit          = 2, // Async Conduit submission (+ optional L4-MCS CBS donation!)
    FluxComplete        = 3, // Server/Driver completion (+ returns borrowed CBS context!)
    ThermalSweep        = 4, // Periodic hysteresis window decay check
    RevokeCapability    = 5, // O(1) epoch lineage revocation request
    DomainCrashTeardown = 6, // NT-style domain crash teardown & IOMMU DMA quarantine
};

struct KernelEvent {
    EventKind             kind{EventKind::TimerExpired};
    TickNs                timestamp{};
    DomainId              caller_domain{};
    ThreadId              caller_thread{};

    // Event-specific payload fields (flat explicit layout; zero heap/RTTI)
    IrqLine               irq_line{};
    u64                   irq_status_word{0};

    cap::CapToken         cap_token{};
    ConduitId             conduit_id{};
    flux::FluxSubmission  submission{};
    flux::FluxCompletion  completion{};
    bool                  urgent_rt{false};
};

enum class EffectKind : u8 {
    None                   = 0,
    SwitchAddressSpace     = 1, // Reload CR3 / PCID (`CR3_NOFLUSH`) for `target_domain`
    SwitchThreadContext    = 2, // Context switch CPU registers to `target_thread`
    ArmOneShotTimer        = 3, // Program APIC TSC-Deadline timer for `deadline`
    CpuIdleWait            = 4, // Enter low-power C-state (`hlt`/`mwait`) until IRQ/timer
    AckIrqFastPath         = 5, // EOI hardware interrupt immediately in Ring 0 (0 Ring-3 switch!)
    EscalateToUserspaceDrv = 6, // Mask IRQ & wake isolated Ring-3 Userspace Driver control plane
    NotifyConduitDoorbell  = 7, // Signal receiver according to `flux::DoorbellAction`
    UpdateProtectionKey    = 8, // x86 MPK/PKRU write-seal (`WRPKRU`) — anti-TOCTOU, 0 TLB shootdown!
    QuarantineIommuDomain  = 9, // NT-style IOMMU abort/quarantine before freeing crashed DMA pages!
};

struct KernelEffect {
    EffectKind           kind{EffectKind::None};
    DomainId             target_domain{};
    ThreadId             target_thread{};
    ConduitId            conduit_id{};
    IrqLine              irq_line{};
    PkeyId               mpk_key{};
    TickNs               deadline{};
    flux::DoorbellAction doorbell{flux::DoorbellAction::None};
    u64                  fast_result{0};
};

using EffectBatch = StaticVec<KernelEffect, MAX_EFFECTS_PER_STEP>;

} // namespace mucore::core
