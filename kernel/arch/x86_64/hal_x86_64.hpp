#pragma once
// ============================================================================
// μCore x86_64 Imperative Shell — Concrete Bare-Metal `HalPlatform`
// ============================================================================
// Satisfies `mucore::shell::HalPlatform` via static C++23 `concept` dispatch
// (zero virtual methods, zero vtables, deterministic instruction path).
// ============================================================================

#include "mucore/shell/hal.hpp"
#include "kernel/arch/x86_64/cpu.hpp"
#include "kernel/arch/x86_64/serial.hpp"

namespace mucore::arch::x86_64 {

class X86Hal {
public:
    constexpr X86Hal() noexcept = default;

    void set_hardware_live(bool live) noexcept { hardware_live_ = live; }

    void switch_address_space(DomainId domain) noexcept {
        cr3_reloads_ += 1;
        if (hardware_live_) {
            // Map DomainId -> 12-bit PCID with CR3_PCID_NOFLUSH to preserve TLB entries!
            u16 const pcid = static_cast<u16>(domain.raw & 0xFFFu);
            PhysAddr const pml4 = domain_pml4_phys_[domain.raw & 31u];
            if (pml4.raw != 0) {
                switch_cr3_pcid(pml4, pcid, true);
            }
        }
    }

    void switch_thread_context(DomainId /*domain*/, ThreadId thread) noexcept {
        active_thread_ = thread;
        ctx_switches_ += 1;
    }

    void arm_oneshot_timer(TickNs deadline) noexcept {
        next_deadline_ = deadline;
        timer_arms_ += 1;
        if (hardware_live_) {
            // Program architectural APIC TSC-Deadline one-shot MSR (zero periodic tick jitter!)
            wrmsr(MSR_IA32_TSC_DEADLINE, deadline.raw);
        }
    }

    void cpu_idle_wait() noexcept {
        if (hardware_live_) {
            asm volatile("sti; hlt; cli" : : : "memory");
        }
    }

    void ack_irq_fast(IrqLine /*irq*/, u64 /*fast_res*/) noexcept {
        fast_eois_ += 1;
        if (hardware_live_) {
            wrmsr(MSR_X2APIC_EOI, 0ULL);
        }
    }

    void escalate_irq_to_userspace(
        DomainId  /*domain*/,
        ThreadId  /*thread*/,
        ConduitId /*conduit*/,
        IrqLine   /*irq*/
    ) noexcept {
        ring3_upcalls_ += 1;
        if (hardware_live_) {
            wrmsr(MSR_X2APIC_EOI, 0ULL);
        }
    }

    void notify_conduit_doorbell(
        DomainId                   /*domain*/,
        ConduitId                  /*conduit*/,
        core::flux::DoorbellAction /*action*/
    ) noexcept {
        doorbells_ += 1;
    }

    void update_protection_key(DomainId /*domain*/, PkeyId pkey) noexcept {
        mpk_seals_ += 1;
        if (hardware_live_ && pku_supported_) {
            write_pkru_seal_writes(pkey);
        }
    }

    void quarantine_iommu_domain(DomainId /*domain*/, u64 count) noexcept {
        iommu_quarantines_ += count;
    }

    [[nodiscard]] u64 fast_eois() const noexcept     { return fast_eois_; }
    [[nodiscard]] u64 ring3_upcalls() const noexcept { return ring3_upcalls_; }
    [[nodiscard]] u64 cr3_reloads() const noexcept   { return cr3_reloads_; }

private:
    bool     hardware_live_{false};
    bool     pku_supported_{false};
    PhysAddr domain_pml4_phys_[32]{};
    ThreadId active_thread_{};
    TickNs   next_deadline_{};

    u64      cr3_reloads_{0};
    u64      ctx_switches_{0};
    u64      timer_arms_{0};
    u64      fast_eois_{0};
    u64      ring3_upcalls_{0};
    u64      doorbells_{0};
    u64      mpk_seals_{0};
    u64      iommu_quarantines_{0};
};

// Compile-time static concept verification (Zero vtable, 100% static check!)
static_assert(shell::HalPlatform<X86Hal>, "X86Hal must satisfy mucore::shell::HalPlatform");

} // namespace mucore::arch::x86_64
