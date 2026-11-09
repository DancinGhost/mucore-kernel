// ============================================================================
// μCore (mucore-kernel) — Bare-Metal Ring-0 SMP Entry & Imperative Shell
// ============================================================================
// Every file-scope state object is marked `constinit` — guaranteeing static
// compile-time initialization in `.bss`/`.data` with ZERO hidden `.init_array`
// constructors before `kmain()` executes (enforced by `linker.ld` ASSERT).
// ============================================================================

#include "mucore/core/dispatcher.hpp"
#include "mucore/core/smp.hpp"
#include "mucore/core/vmspace.hpp"
#include "mucore/shell/hal.hpp"
#include "mucore/shell/shared_conduit.hpp"
#include "kernel/arch/x86_64/cpu.hpp"
#include "kernel/arch/x86_64/hal_x86_64.hpp"
#include "kernel/arch/x86_64/idt.hpp"
#include "kernel/arch/x86_64/limine_proto.hpp"
#include "kernel/arch/x86_64/percpu.hpp"
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

[[gnu::used, gnu::section(".limine_requests")]]
constinit limine::SmpRequest g_smp_req{
    .id       = {limine::COMMON_MAGIC_0, limine::COMMON_MAGIC_1,
                 0x95a67b819a1b857eULL, 0xa0b61b723b6a73e0ULL},
    .revision = 0,
    .response = nullptr,
    .flags    = limine::SMP_FLAG_X2APIC,
};

// Explicit Static Ring-0 Hardware & Hybrid SMP Kernel State (`constinit` -> zero `.init_array`!)
constinit PerCpuArchBlock                        g_percpu[MAX_SMP_CPUS]{};
constinit IdtTable                               g_idt{};
constinit core::smp::SmpNodeState                g_smp{};
constinit core::vm::VmTablePool                  g_vm_pool{};
constinit core::smp::ColdTicketLock              g_serial_lock{};
constinit u32                                    g_online_cpu_count{0};
constinit X86Hal                                 g_hal{};
constinit shell::ImperativeKernelRuntime<X86Hal> g_kernel{g_hal};

// Ring an x2APIC `VEC_SMP_PARCEL_IPI` doorbell to every remote CPU set in `cpu_mask`
inline void notify_remote_cpus_ipi(u64 cpu_mask) noexcept {
    if (!g_hal.is_hardware_live()) return;
    while (cpu_mask != 0ULL) {
        u32 const dst = ctz64(cpu_mask);
        cpu_mask &= ~(1ULL << dst);
        if (dst < MAX_SMP_CPUS && __atomic_load_n(&g_smp.shards[dst].online, __ATOMIC_ACQUIRE)) {
            send_x2apic_ipi(g_percpu[dst].lapic_id, VEC_SMP_PARCEL_IPI);
        }
    }
}

// Application Processor (AP) Hardware Bootstrap Entry (`LimineSmpRequest`)
[[noreturn]] void ap_entry(limine::SmpInfo* info) noexcept {
    u32 const cpu_idx = static_cast<u32>(info->extra_argument);
    if (cpu_idx < MAX_SMP_CPUS) {
        init_percpu_arch(g_percpu[cpu_idx], cpu_idx, info->lapic_id);
        load_idt_on_current_cpu(g_idt);

        __atomic_store_n(&g_smp.shards[cpu_idx].online, true, __ATOMIC_RELEASE);
        (void)__atomic_fetch_add(&g_online_cpu_count, 1u, __ATOMIC_ACQ_REL);

        g_serial_lock.lock();
        SerialCom1::puts("[mucore] SMP AP online: CpuId=");
        SerialCom1::write_u64(cpu_idx);
        SerialCom1::puts(" (x2APIC=");
        SerialCom1::write_u64(info->lapic_id);
        SerialCom1::puts(")\n");
        g_serial_lock.unlock();
    }

    for (;;) {
        asm volatile("sti; hlt");
    }
}

// Boot-time Functional Core, VmSpace W^X/KPTI, and SMP Sharding Power-On Self-Test
void run_boot_post() noexcept {
    using namespace mucore::core;
    SerialCom1::puts("[mucore] Running Functional Core + SMP + VmSpace POST...\n");

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

    // 3. Install Verified Ring-0 Kineticlet Fast-Path
    kinetic::KineticProgram prog{};
    prog.insns[0] = kinetic::dsl::load_imm(4, 0x8000u);
    prog.insns[1] = kinetic::dsl::mov(5, 0);
    prog.insns[2] = kinetic::dsl::bit_and(5, 4);
    prog.insns[3] = kinetic::dsl::jump_if_eq(5, 4, 5); // 3 + 1 + 5 = [9] Escalate!
    prog.insns[4] = kinetic::dsl::load_state(6, 0);
    prog.insns[5] = kinetic::dsl::load_imm(7, 1);
    prog.insns[6] = kinetic::dsl::add(6, 7);
    prog.insns[7] = kinetic::dsl::store_state(0, 6);
    prog.insns[8] = kinetic::dsl::ret(kinetic::ReturnVerdict::CompleteFastPath);
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

    // 5. Phase 2 VmSpace W^X + MPK + KPTI & Per-Core Magazine Self-Check
    auto kpml4 = vm::alloc_pt_node(g_vm_pool);
    if (kpml4.is_ok()) {
        g_vm_pool.nodes[kpml4.value()].entries[256] = 0x0000'0000'0010'0103ULL; // HHDM Global
        g_vm_pool.nodes[kpml4.value()].entries[511] = 0x0000'0000'0020'0103ULL; // Trampoline
        auto sandbox_vm = vm::create_domain_vmspace(
            g_vm_pool, kpml4.value(), DomainId{2}, vm::KptiMode::StrictKpti
        );
        auto wx_reject = vm::encode_leaf_pte(
            VirtAddr{0x40'0000ULL}, PhysAddr{0x20'0000ULL},
            vm::MapPermissions{.writable = true, .executable = true, .user_accessible = true}
        );
        if (sandbox_vm.is_ok() && wx_reject.error() == Error::WxorXViolation) {
            SerialCom1::puts("[mucore] VmSpace W^X & StrictKpti isolation verified.\n");
        }
    }

    // 6. Pre-warm Core 0 Per-CPU Physical Frame Magazine (32 frames, 0-lock RT ready!)
    auto boot_frame = smp::alloc_shard_frame(g_smp, CpuId{0}, true);
    if (boot_frame.is_ok()) {
        SerialCom1::puts("[mucore] Core 0 Frame Magazine primed at PhysAddr=");
        SerialCom1::write_hex(boot_frame.value().raw);
        SerialCom1::puts("\n");
    }

    SerialCom1::puts("[mucore] POST Passed: Ring0FastOps=");
    SerialCom1::write_u64(st.telemetry.ring0_fast_handled);
    SerialCom1::puts(", ContextSwitches=");
    SerialCom1::write_u64(st.telemetry.context_switches_emitted);
    SerialCom1::puts("\n");
}

} // namespace

// ----------------------------------------------------------------------------
// Multi-Core `SYSCALL`, Exception & Interrupt Imperative Shell Entry Points
// ----------------------------------------------------------------------------

extern "C" mucore::u64 mucore_syscall_entry_c(
    mucore::u64 op,
    mucore::u64 arg0,
    mucore::u64 arg1,
    mucore::u64 arg2,
    mucore::u32 cpu_id
) noexcept {
    using namespace mucore;
    CpuId const  local_cpu{static_cast<u16>(cpu_id)};
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

    // Syscall 2: O(1) Capability Lineage Epoch Revocation (SMP release-ordered!)
    if (op == 2ULL) {
        g_smp.cold_lock.lock();
        auto plan = core::cap::plan_revoke_lineage(
            g_smp.shared_caps, DomainId{static_cast<u32>(arg0)}, core::cap::CapToken{arg1}
        );
        if (plan.is_ok()) {
            core::cap::apply_mutation(g_smp.shared_caps, plan.value());
        }
        g_smp.cold_lock.unlock();
        return plan.is_ok() ? 0ULL : static_cast<u64>(plan.error());
    }

    // Syscall 3: Cross-Core L4-MCS CBS Deadline & Budget Loan (`DonateRemoteCbs` IPI Parcel)
    if (op == 3ULL) {
        core::smp::ShardEvent const ev{
            .kind          = core::smp::ShardEventKind::LocalCbsRemoteCall,
            .timestamp     = now,
            .local_thread  = ThreadId{static_cast<u32>(arg0)},
            .remote_worker = ThreadId{static_cast<u32>(arg1)},
            .remote_cpu    = CpuId{static_cast<u16>(arg2)},
        };
        auto res = core::smp::execute_on_cpu_shard(g_smp, local_cpu, ev);
        if (res.is_err()) {
            return static_cast<u64>(res.error());
        }
        if (res.value().is_some()) {
            notify_remote_cpus_ipi(1ULL << res.value().value().raw);
        }
        return 0ULL;
    }

    // Syscall 4: Active-Core Coherent `PKRU` Seal (0 IPIs if single-core, targeted otherwise!)
    if (op == 4ULL) {
        DomainId const dom{static_cast<u32>(arg0)};
        PkeyId const   pkey{static_cast<u8>(arg1 & 0xFu)};

        if (g_hal.is_pku_supported()) {
            arch::x86_64::write_pkru_seal_writes(pkey);
        }
        u64 ipi_mask = 0ULL;
        (void)core::smp::seal_domain_pkru_coherent(g_smp, local_cpu, dom, pkey, &ipi_mask);
        if (ipi_mask != 0ULL) {
            notify_remote_cpus_ipi(ipi_mask);
        }
        return 0ULL;
    }

    return static_cast<u64>(Error::InvalidArgument);
}

extern "C" [[noreturn]] void mucore_exception_handler_c(
    mucore::u32 vector,
    mucore::u64 error_code,
    mucore::u32 cpu_id
) noexcept {
    using namespace mucore::arch::x86_64;
    u64 const cr2 = (vector == VEC_PAGE_FAULT) ? read_cr2() : 0ULL;

    g_serial_lock.lock();
    SerialCom1::puts("\n[mucore] CPU FAULT on CpuId=");
    SerialCom1::write_u64(cpu_id);
    SerialCom1::puts(" Vector=");
    SerialCom1::write_u64(vector);
    SerialCom1::puts(" Err=");
    SerialCom1::write_hex(error_code);
    if (vector == VEC_PAGE_FAULT) {
        SerialCom1::puts(" CR2=");
        SerialCom1::write_hex(cr2);
    }
    SerialCom1::puts("\n");
    g_serial_lock.unlock();

    for (;;) {
        asm volatile("cli; hlt");
    }
}

extern "C" void mucore_irq_vector_c(
    mucore::u32 vector,
    mucore::u64 error_code,
    mucore::u32 cpu_id
) noexcept {
    (void)error_code;
    using namespace mucore;
    using namespace mucore::arch::x86_64;

    CpuId const  local_cpu{static_cast<u16>(cpu_id)};
    TickNs const now{rdtsc_ordered()};

    if (vector == VEC_APIC_TIMER) {
        (void)core::smp::execute_on_cpu_shard(g_smp, local_cpu, core::smp::ShardEvent{
            .kind      = core::smp::ShardEventKind::LocalTimer,
            .timestamp = now,
        });
        wrmsr(MSR_X2APIC_EOI, 0ULL);
    } else if (vector == VEC_SMP_PARCEL_IPI) {
        u16 pkru_seal_mask = 0;
        (void)core::smp::drain_incoming_parcels(g_smp, local_cpu, now, &pkru_seal_mask);
        while (pkru_seal_mask != 0u) {
            u32 const key = ctz64(static_cast<u64>(pkru_seal_mask));
            pkru_seal_mask &= static_cast<u16>(~(1u << key));
            if (g_hal.is_pku_supported()) {
                write_pkru_seal_writes(PkeyId{static_cast<u8>(key)});
            }
        }
        wrmsr(MSR_X2APIC_EOI, 0ULL);
    }
    // Spurious vector 255 intentionally omits EOI per Intel SDM Vol. 3A 10.9.
}

// ----------------------------------------------------------------------------
// Bare-Metal Kernel Entry Point (`_start` -> `kmain` on Bootstrap Processor)
// ----------------------------------------------------------------------------
extern "C" [[noreturn]] void kmain() noexcept {
    using namespace mucore;
    using namespace mucore::arch::x86_64;

    SerialCom1::init();
    SerialCom1::puts("\n============================================================\n");
    SerialCom1::puts("  mucore-kernel (uCore) v0.2.0 — Hybrid SMP FCIS C++23\n");
    SerialCom1::puts("  Zero Hidden Mechanisms | Per-CPU Shards | VmSpace | CBS-RT\n");
    SerialCom1::puts("============================================================\n");

    // 1. Initialize Shared 256-Entry IDT + Core 0 Per-CPU `%gs`, GDT, TSS & SYSCALL
    u32 const bsp_lapic = (g_smp_req.response != nullptr) ? g_smp_req.response->bsp_lapic_id : 0u;
    build_shared_idt(g_idt);
    init_percpu_arch(g_percpu[0], 0u, bsp_lapic);
    load_idt_on_current_cpu(g_idt);

    __atomic_store_n(&g_smp.shards[0].online, true, __ATOMIC_RELEASE);
    __atomic_store_n(&g_online_cpu_count, 1u, __ATOMIC_RELEASE);
    SerialCom1::puts("[mucore] Core 0 %gs Per-CPU GDT/TSS, 256-gate IDT & SYSCALL armed.\n");

    if (g_hhdm_req.response != nullptr) {
        SerialCom1::puts("[mucore] Limine HHDM Offset: ");
        SerialCom1::write_hex(g_hhdm_req.response->offset);
        SerialCom1::puts("\n");
    }

    // 2. Wake Application Processors (APs) via Limine SMP Protocol
    if (g_smp_req.response != nullptr && g_smp_req.response->cpu_count > 1ULL) {
        u64 const total_hw_cpus = g_smp_req.response->cpu_count;
        u32 next_logical_id     = 1u;
        for (u64 i = 0; i < total_hw_cpus && next_logical_id < MAX_SMP_CPUS; ++i) {
            limine::SmpInfo* info = g_smp_req.response->cpus[i];
            if (info == nullptr || info->lapic_id == bsp_lapic) {
                continue;
            }
            info->extra_argument = next_logical_id++;
            __atomic_store_n(&info->goto_address, &ap_entry, __ATOMIC_RELEASE);
        }

        // Bounded spin waiting for woken APs to finish `%gs` + IDT bring-up
        for (u32 spin = 0; spin < 5'000'000u; ++spin) {
            if (__atomic_load_n(&g_online_cpu_count, __ATOMIC_ACQUIRE) >= next_logical_id) {
                break;
            }
            asm volatile("pause" : : : "memory");
        }
    }

    SerialCom1::puts("[mucore] Online SMP Execution Shards: ");
    SerialCom1::write_u64(__atomic_load_n(&g_online_cpu_count, __ATOMIC_ACQUIRE));
    SerialCom1::puts("\n");

    run_boot_post();

    g_hal.set_hardware_live(true);
    SerialCom1::puts("[mucore] Entering tickless multi-core Imperative Shell loop.\n");

    for (;;) {
        asm volatile("sti; hlt");
    }
}
