#pragma once
// ============================================================================
// μCore Imperative Shell — Zero-Vtable Hardware Abstraction & Effect Executor
// ============================================================================

#include "mucore/core/dispatcher.hpp"
#include "mucore/shell/trace_ring.hpp"

namespace mucore::shell {

template <typename P>
concept HalPlatform = requires(
    P&                         platform,
    DomainId                   domain,
    ThreadId                   thread,
    ConduitId                  conduit,
    IrqLine                    irq,
    PkeyId                     pkey,
    TickNs                     deadline,
    core::flux::DoorbellAction doorbell,
    u64                        fast_res
) {
    { platform.switch_address_space(domain) } noexcept;
    { platform.switch_thread_context(domain, thread) } noexcept;
    { platform.arm_oneshot_timer(deadline) } noexcept;
    { platform.cpu_idle_wait() } noexcept;
    { platform.ack_irq_fast(irq, fast_res) } noexcept;
    { platform.escalate_irq_to_userspace(domain, thread, conduit, irq) } noexcept;
    { platform.notify_conduit_doorbell(domain, conduit, doorbell) } noexcept;
    { platform.update_protection_key(domain, pkey) } noexcept;
    { platform.quarantine_iommu_domain(domain, fast_res) } noexcept;
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

    [[nodiscard]] Result<usize, Error> handle_event(core::KernelEvent const& ev) noexcept {
        auto res = core::dispatch_event(state_, ev);
        if (res.is_err()) {
            trace_.record(ev, res.error(), 0);
            return Result<usize, Error>::err(res.error());
        }

        core::EffectBatch const& batch = res.value();
        trace_.record(ev, Error::None, batch.size());

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
                case core::EffectKind::UpdateProtectionKey:
                    hal_.update_protection_key(eff.target_domain, eff.mpk_key);
                    break;
                case core::EffectKind::QuarantineIommuDomain:
                    hal_.quarantine_iommu_domain(eff.target_domain, eff.fast_result);
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
