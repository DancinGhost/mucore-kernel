#pragma once
// ============================================================================
// μCore Imperative Shell — Zero-Vtable Hardware Abstraction & Effect Executor
// ============================================================================
// Enforces "No Hidden Mechanisms" at the Architecture Boundary:
//   - Uses C++20/23 `concept` static polymorphism instead of `virtual` methods.
//   - Eliminates hidden vtable pointers, indirect-branch Spectre mitigations
//     (retpolines), and unpredictable instruction-cache misses in Ring 0.
//   - `ImperativeKernelRuntime<Hal>` is the thin Imperative Shell that feeds
//     hardware `KernelEvent`s into the Pure Functional Core, logs transitions
//     to `TraceRing`, and executes the resulting `EffectBatch` on hardware.
// ============================================================================

#include "mucore/core/dispatcher.hpp"
#include "mucore/shell/trace_ring.hpp"

namespace mucore::shell {

template <typename P>
concept HalPlatform = requires(
    P&                   platform,
    DomainId             domain,
    ThreadId             thread,
    ConduitId            conduit,
    IrqLine              irq,
    TickNs               deadline,
    core::flux::DoorbellAction doorbell,
    u64                  fast_res
) {
    { platform.switch_address_space(domain) } noexcept;
    { platform.switch_thread_context(domain, thread) } noexcept;
    { platform.arm_oneshot_timer(deadline) } noexcept;
    { platform.cpu_idle_wait() } noexcept;
    { platform.ack_irq_fast(irq, fast_res) } noexcept;
    { platform.escalate_irq_to_userspace(domain, thread, conduit, irq) } noexcept;
    { platform.notify_conduit_doorbell(domain, conduit, doorbell) } noexcept;
};

template <HalPlatform Hal>
class ImperativeKernelRuntime {
public:
    explicit constexpr ImperativeKernelRuntime(Hal& hal) noexcept : hal_(hal) {}

    ImperativeKernelRuntime(ImperativeKernelRuntime const&)            = delete;
    ImperativeKernelRuntime& operator=(ImperativeKernelRuntime const&) = delete;

    [[nodiscard]] constexpr core::KernelState&       state() noexcept       { return state_; }
    [[nodiscard]] constexpr core::KernelState const& state() const noexcept { return state_; }
    [[nodiscard]] constexpr TraceRing const&         trace() const noexcept { return trace_; }

    // Single entry point for all syscalls, doorbells, timers, and hardware IRQs
    [[nodiscard]] Result<usize, Error> handle_event(core::KernelEvent const& ev) noexcept {
        auto res = core::dispatch_event(state_, ev);
        if (res.is_err()) {
            trace_.record(ev, res.error(), 0);
            return Result<usize, Error>::err(res.error());
        }

        core::EffectBatch const& batch = res.value();
        trace_.record(ev, Error::None, batch.size());

        // Imperatively execute every explicit hardware side-effect in sequence
        for (usize i = 0; i < batch.size(); ++i) {
            core::KernelEffect const& eff = batch[i];
            switch (eff.kind) {
                case core::EffectKind::None:
                    break;
                case core::EffectKind::SwitchAddressSpace:
                    hal_.switch_address_space(eff.target_domain);
                    break;
                case core::EffectKind::SwitchThreadContext:
                    hal_.switch_thread_context(eff.target_domain, eff.target_thread);
                    break;
                case core::EffectKind::ArmOneShotTimer:
                    hal_.arm_oneshot_timer(eff.deadline);
                    break;
                case core::EffectKind::CpuIdleWait:
                    hal_.cpu_idle_wait();
                    break;
                case core::EffectKind::AckIrqFastPath:
                    hal_.ack_irq_fast(eff.irq_line, eff.fast_result);
                    break;
                case core::EffectKind::EscalateToUserspaceDrv:
                    hal_.escalate_irq_to_userspace(
                        eff.target_domain, eff.target_thread, eff.conduit_id, eff.irq_line
                    );
                    break;
                case core::EffectKind::NotifyConduitDoorbell:
                    hal_.notify_conduit_doorbell(
                        eff.target_domain, eff.conduit_id, eff.doorbell
                    );
                    break;
            }
        }

        return Result<usize, Error>::ok(batch.size());
    }

private:
    core::KernelState state_{};
    TraceRing         trace_{};
    Hal&              hal_;
};

} // namespace mucore::shell
