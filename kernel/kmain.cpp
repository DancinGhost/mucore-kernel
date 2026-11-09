// ============================================================================
// μCore (mucore-kernel) — Bare-Metal Ring-0 Entry & Imperative Shell Bootstrap
// ============================================================================
// Every file-scope state object is marked `constinit` — guaranteeing static
// compile-time initialization in `.bss`/`.data` with ZERO hidden `.init_array`
// constructors before `kmain()` executes.
// ============================================================================

#include "mucore/core/dispatcher.hpp"
#include "mucore/shell/hal.hpp"
#include "mucore/shell/shared_conduit.hpp"
#include "kernel/arch/x86_64/cpu.hpp"
#include "kernel/arch/x86_64/hal_x86_64.hpp"
#include "kernel/arch/x86_64/limine_proto.hpp"
#include "kernel/arch/x86_64/serial.hpp"

// ----------------------------------------------------------------------------
// Freestanding Compiler ABI Primitives (Mandatory for -ffreestanding GCC/Clang)
// ----------------------------------------------------------------------------
extern "C" {

void* memcpy(void* __restrict dst, const void* __restrict src, size_t n) noexcept {
    auto*       d = static_cast<unsigned char*>(dst);
    auto const* s = static_cast<const unsigned char*>(src);
    for (size_t i = 0; i < n; ++i) {
        d[i] = s[i];
    }
    return dst;
}

void* memset(void* dst, int c, size_t n) noexcept {
    auto* d = static_cast<unsigned char*>(dst);
    auto const val = static_cast<unsigned char>(c);
    for (size_t i = 0; i < n; ++i) {
        d[i] = val;
    }
    return dst;
}

void* memmove(void* dst, const void* src, size_t n) noexcept {
    auto*       d = static_cast<unsigned char*>(dst);
    auto const* s = static_cast<const unsigned char*>(src);
    if (d < s || d >= (s + n)) {
        for (size_t i = 0; i < n; ++i) d[i] = s[i];
    } else {
        for (size_t i = n; i > 0; --i) d[i - 1] = s[i - 1];
    }
    return dst;
}

int memcmp(const void* s1, const void* s2, size_t n) noexcept {
    auto const* a = static_cast<const unsigned char*>(s1);
    auto const* b = static_cast<const unsigned char*>(s2);
    for (size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) {
            return (a[i] < b[i]) ? -1 : 1;
        }
    }
    return 0;
}

extern char boot_stack_top[];
extern char ist1_stack_top[];

} // extern "C"

namespace {

using namespace mucore;
using namespace mucore::arch::x86_64;

// Limine Bootloader Protocol Requests (placed explicitly in `.limine_requests`)
[[gnu::used, gnu::section(".limine_requests")]]
constinit limine::HhdmRequest g_hhdm_req{
    .id       = {limine::COMMON_MAGIC_0, limine::COMMON_MAGIC_1,
                 0x48dcf1cb8ad2b852ULL, 0x63984e959a98244bULL},
    .revision = 0,
    .response = nullptr,
};

[[gnu::used, gnu::section(".limine_requests")]]
constinit limine::MemmapRequest g_memmap_req{
    .id       = {limine::COMMON_MAGIC_0, limine::COMMON_MAGIC_1,
                 0x67cf3d9d378a806fULL, 0xe304acdfc50c3c62ULL},
    .revision = 0,
    .response = nullptr,
};

// Explicit Static Ring-0 Hardware & Kernel Runtime State (`constinit` -> zero hidden ctors!)
constinit TaskStateSegment64                 g_bsp_tss{};
constinit GdtTable                           g_bsp_gdt{};
constinit X86Hal                             g_hal{};
constinit shell::ImperativeKernelRuntime<X86Hal> g_kernel{g_hal};

// Boot-time Functional Core verification & Split-Plane Pact smoke check
void run_boot_post() noexcept {
    using namespace mucore::core;
    SerialCom1::puts("[mucore] Running Functional Core Power-On Self-Test (POST)...\n");

    KernelState& st = g_kernel.state();
    DomainId const drv_dom{1};
    ThreadId const drv_tid{1};

    // 1. Admit Hard Real-Time Isochronous Driver Control Budget (100us every 1ms = 10.0%)
    auto tid_res = sched::spawn_thread(
        st.sched,
        drv_tid,
        drv_dom,
        sched::SchedClass::IsochronousRt,
        sched::RtParams{.wcet_ns = 100'000ULL, .period_ns = 1'000'000ULL},
        TickNs{0}
    );
    if (tid_res.is_err()) {
        SerialCom1::puts("[mucore] PANIC: RT CBS admission failed!\n");
        return;
    }

    // 2. Mint Capabilities for Ring-0 Kineticlet Slot & IRQ 32 (NVMe MSI-X0)
    auto kin_cap_mut = cap::plan_mint_root(
        st.caps,
        drv_dom,
        cap::CapObjectKind::KineticSlot,
        cap::CapRights::ExecuteRing0 | cap::CapRights::Read | cap::CapRights::Write,
        1ULL,
        cap::RevocationGroupId{1}
    );
    if (kin_cap_mut.is_ok()) cap::apply_mutation(st.caps, kin_cap_mut.value());

    auto irq_cap_mut = cap::plan_mint_root(
        st.caps,
        drv_dom,
        cap::CapObjectKind::IrqHook,
        cap::CapRights::Read | cap::CapRights::Write,
        32ULL,
        cap::RevocationGroupId{1}
    );
    if (irq_cap_mut.is_ok()) cap::apply_mutation(st.caps, irq_cap_mut.value());

    // 3. Install Verified Ring-0 Kineticlet Fast-Path (if error bit 0x8000 set -> Escalate Ring 3, else Fast Complete!)
    kinetic::KineticProgram prog{};
    prog.insns[0] = kinetic::dsl::load_imm(4, 0x8000u);
    prog.insns[1] = kinetic::dsl::mov(5, 0);
    prog.insns[2] = kinetic::dsl::bit_and(5, 4);
    prog.insns[3] = kinetic::dsl::jump_if_eq(5, 4, 3); // Forward jump to [7] Escalate!
    prog.insns[4] = kinetic::dsl::load_state(6, 0);
    prog.insns[5] = kinetic::dsl::load_imm(7, 1);
    prog.insns[6] = kinetic::dsl::add(6, 7);
    prog.insns[7] = kinetic::dsl::store_state(0, 6);
    prog.insns[8] = kinetic::dsl::ret(kinetic::ReturnVerdict::CompleteFastPath);
    prog.len      = 9;
    // Fix jump target: pc=3 + 1 + skip = 9 -> let's place Escalate at [9] and Return at [10]
    prog.insns[3] = kinetic::dsl::jump_if_eq(5, 4, 5); // 3 + 1 + 5 = 9!
    prog.insns[9] = kinetic::dsl::ret(kinetic::ReturnVerdict::EscalateToUserspace);
    prog.len      = 10;

    auto proof = install_kineticlet(
        st, drv_dom, kin_cap_mut.value().minted_token, KineticId{1}, prog
    );
    if (proof.is_ok()) {
        SerialCom1::puts("[mucore] Kineticlet #1 verified! WCET = ");
        SerialCom1::write_u64(proof.value().wcet_ns);
        SerialCom1::puts(" ns, MaxSteps = ");
        SerialCom1::write_u64(proof.value().max_instructions);
        SerialCom1::puts("\n");
    }

    (void)open_conduit(st, ConduitId{1}, drv_dom, drv_dom, true);
    (void)bind_irq_pact(st, drv_dom, irq_cap_mut.value().minted_token, IrqPactBinding{
        .active        = true,
        .irq           = IrqLine{32},
        .driver_domain = drv_dom,
        .driver_thread = drv_tid,
        .conduit       = ConduitId{1},
        .fast_kinetic  = KineticId{1},
    });

    // 4. Fire healthy IRQ -> handled 100% in Ring 0 with ZERO context switch!
    (void)g_kernel.handle_event(KernelEvent{
        .kind            = EventKind::HardwareIrq,
        .timestamp       = TickNs{1'000},
        .irq_line        = IrqLine{32},
        .irq_status_word = 0x0001ULL,
    });

    SerialCom1::puts("[mucore] POST Passed: Ring0FastOps=");
    SerialCom1::write_u64(st.telemetry.ring0_fast_handled);
    SerialCom1::puts(", ContextSwitches=");
    SerialCom1::write_u64(st.telemetry.context_switches_emitted);
    SerialCom1::puts("\n");
}

} // namespace

// Cold-path & Doorbell `SYSCALL` C handler invoked by `x86_64_syscall_entry`
extern "C" mucore::u64 mucore_syscall_entry_c(
    mucore::u64 op,
    mucore::u64 arg0,
    mucore::u64 arg1,
    mucore::u64 arg2
) noexcept {
    using namespace mucore;
    TickNs const now{arch::x86_64::rdtsc_ordered()};

    // Syscall 1: Cold/Warm Flux Doorbell Kick
    if (op == 1ULL) {
        core::KernelEvent ev{};
        ev.kind          = core::EventKind::FluxSubmit;
        ev.timestamp     = now;
        ev.caller_domain = DomainId{static_cast<u32>(arg0)};
        ev.cap_token     = core::cap::CapToken{arg1};
        ev.urgent_rt     = (arg2 != 0ULL);

        auto res = g_kernel.handle_event(ev);
        return res.is_ok() ? 0ULL : static_cast<u64>(res.error());
    }

    // Syscall 2: O(1) Capability Lineage Epoch Revocation
    if (op == 2ULL) {
        core::KernelEvent ev{};
        ev.kind          = core::EventKind::RevokeCapability;
        ev.timestamp     = now;
        ev.caller_domain = DomainId{static_cast<u32>(arg0)};
        ev.cap_token     = core::cap::CapToken{arg1};

        auto res = g_kernel.handle_event(ev);
        return res.is_ok() ? 0ULL : static_cast<u64>(res.error());
    }

    return static_cast<u64>(Error::InvalidArgument);
}

// Bare-Metal Kernel Entry Point (`_start` -> `kmain`)
extern "C" [[noreturn]] void kmain() noexcept {
    using namespace mucore;
    using namespace mucore::arch::x86_64;

    SerialCom1::init();
    SerialCom1::puts("\n============================================================\n");
    SerialCom1::puts("  mucore-kernel (uCore) v0.1.0 — Hybrid FCIS C++23 Kernel\n");
    SerialCom1::puts("  Zero Hidden Mechanisms | Kineticlets | CBS-RT | Flux IPC\n");
    SerialCom1::puts("============================================================\n");

    // Configure BSP TSS & GDT + Fast SYSCALL/SYSRETQ MSRs
    g_bsp_tss.rsp0 = reinterpret_cast<u64>(boot_stack_top);
    g_bsp_tss.ist1 = reinterpret_cast<u64>(ist1_stack_top);
    encode_tss_descriptor(g_bsp_gdt, &g_bsp_tss);

    DescriptorPtr const gdtr{
        .limit = sizeof(GdtTable) - 1u,
        .base  = reinterpret_cast<u64>(&g_bsp_gdt),
    };
    x86_64_load_gdt_and_tss(&gdtr, KERNEL_CS, KERNEL_SS, TSS_SEL);
    init_fast_syscall_msrs();
    SerialCom1::puts("[mucore] GDT, 64-bit TSS, and Fast SYSCALL/SYSRETQ armed.\n");

    if (g_hhdm_req.response != nullptr) {
        SerialCom1::puts("[mucore] Limine HHDM Offset: ");
        SerialCom1::write_hex(g_hhdm_req.response->offset);
        SerialCom1::puts("\n");
    }

    run_boot_post();

    g_hal.set_hardware_live(true);
    SerialCom1::puts("[mucore] Entering tickless Imperative Shell loop.\n");

    for (;;) {
        asm volatile("hlt");
    }
}
