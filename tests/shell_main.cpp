// ============================================================================
// μCore (mucore-kernel) — Host Interactive Shell Runner
// ============================================================================
// Runs μCore's Functional Core & Imperative Shell directly on the host console.
// Supports interactive typing (with line editing) or piped input scripts.
// ============================================================================

#include <stdio.h>
#include <string.h>
#include "mucore/core/init.hpp"
#include "mucore/core/kinetic.hpp"
#include "mucore/core/smp.hpp"
#include "mucore/shell/cli.hpp"
#include "mucore/shell/hal.hpp"
#include "kernel/boot_manifest.hpp"

namespace {

using namespace mucore;

struct HostHal {
    u64 cr3_switches{0};
    u64 thread_switches{0};
    u64 timer_arms{0};
    u64 idle_waits{0};
    u64 fast_irq_acks{0};
    u64 ring3_driver_upcalls{0};
    u64 doorbells_rung{0};
    u64 mpk_seals{0};
    u64 iommu_quarantines{0};

    void switch_address_space(DomainId) noexcept { ++cr3_switches; }
    void switch_thread_context(DomainId, ThreadId) noexcept { ++thread_switches; }
    void arm_oneshot_timer(TickNs) noexcept { ++timer_arms; }
    void cpu_idle_wait() noexcept { ++idle_waits; }
    void ack_irq_fast(IrqLine, u64) noexcept { ++fast_irq_acks; }
    void escalate_irq_to_userspace(DomainId, ThreadId, ConduitId, IrqLine) noexcept {
        ++ring3_driver_upcalls;
    }
    void notify_conduit_doorbell(DomainId, ConduitId, core::flux::DoorbellAction) noexcept {
        ++doorbells_rung;
    }
    void update_protection_key(DomainId, PkeyId) noexcept { ++mpk_seals; }
    void quarantine_iommu_domain(DomainId, u64 count) noexcept { iommu_quarantines += count; }
};

static_assert(shell::HalPlatform<HostHal>, "HostHal must satisfy HalPlatform");

} // namespace

int main(int argc, char* argv[]) {
    HostHal                                hal{};
    shell::ImperativeKernelRuntime<HostHal> rt{hal};
    core::init::InitState                  init{};
    core::smp::SmpNodeState                smp{};

    TickNs const boot_time{1'000'000ULL};
    auto report = core::init::boot_services(rt.state(), init, boot::PLAN, boot_time);
    if (report.is_err()) {
        fprintf(stderr, "Failed to boot services: %s\n", error_name(report.error()));
        return 1;
    }

    // Install Verified NVMe Kineticlet fast-path DAG
    core::init::PlannedService const& nvme = boot::PLAN.services[boot::NVME];
    DomainId const      drv_dom = nvme.domain;
    ThreadId const      drv_tid = nvme.thread;
    core::cap::CapToken const kin_cap = init.services[boot::NVME].grant_caps[boot::NVME_GRANT_KINETIC];
    core::cap::CapToken const irq_cap = init.services[boot::NVME].grant_caps[boot::NVME_GRANT_IRQ];

    core::kinetic::KineticProgram prog{};
    prog.insns[0] = core::kinetic::dsl::load_imm(4, 0x8000u);
    prog.insns[1] = core::kinetic::dsl::mov(5, 0);
    prog.insns[2] = core::kinetic::dsl::bit_and(5, 4);
    prog.insns[3] = core::kinetic::dsl::jump_if_eq(5, 4, 5); // Jump to [9] Escalate!
    prog.insns[4] = core::kinetic::dsl::load_state(6, 0);
    prog.insns[5] = core::kinetic::dsl::load_imm(7, 1);
    prog.insns[6] = core::kinetic::dsl::add(6, 7);
    prog.insns[7] = core::kinetic::dsl::store_state(0, 6);
    prog.insns[8] = core::kinetic::dsl::ret(core::kinetic::ReturnVerdict::CompleteFastPath);
    prog.insns[9] = core::kinetic::dsl::ret(core::kinetic::ReturnVerdict::EscalateToUserspace);
    prog.len      = 10;

    (void)core::install_kineticlet(
        rt.state(), drv_dom, kin_cap, KineticId{static_cast<u32>(boot::NVME_KINETIC_SLOT)}, prog
    );
    (void)core::open_conduit(rt.state(), ConduitId{1}, drv_dom, drv_dom, true);
    (void)core::bind_irq_pact(rt.state(), drv_dom, irq_cap, core::IrqPactBinding{
        .active        = true,
        .irq           = IrqLine{static_cast<u16>(boot::NVME_IRQ_LINE)},
        .driver_domain = drv_dom,
        .driver_thread = drv_tid,
        .conduit       = ConduitId{1},
        .fast_kinetic  = KineticId{static_cast<u32>(boot::NVME_KINETIC_SLOT)},
    });

    // Bring up Core 0 and Core 1 SMP shards
    smp.shards[0].online = true;
    smp.shards[0].cpu_id = CpuId{0};
    (void)core::smp::alloc_shard_frame(smp, CpuId{0}, true);

    smp.shards[1].online = true;
    smp.shards[1].cpu_id = CpuId{1};

    shell::CommandShell<HostHal> cmd_shell{rt, init, boot::PLAN, &smp};

    auto out = shell::IOutput{
        .putc_fn = [](void*, char c) noexcept { fputc(c, stdout); },
        .puts_fn = [](void*, const char* s) noexcept { fputs(s, stdout); fflush(stdout); },
        .ctx     = nullptr,
    };

    // If arguments were passed, run them directly
    if (argc > 1) {
        char arg_line[256]{};
        usize offset = 0;
        for (int i = 1; i < argc && offset + 1 < sizeof(arg_line); ++i) {
            usize const len = strlen(argv[i]);
            if (offset + len + 2 > sizeof(arg_line)) break;
            memcpy(&arg_line[offset], argv[i], len);
            offset += len;
            arg_line[offset++] = ' ';
        }
        arg_line[offset] = '\0';
        cmd_shell.execute_line(arg_line, out);
        return 0;
    }

    cmd_shell.print_banner(out);
    cmd_shell.print_prompt(out);

    char line_buf[256];
    while (fgets(line_buf, sizeof(line_buf), stdin) != nullptr) {
        // Strip trailing newline
        usize len = strlen(line_buf);
        while (len > 0 && (line_buf[len - 1] == '\n' || line_buf[len - 1] == '\r')) {
            line_buf[--len] = '\0';
        }

        if (core::init::cstr_equal(line_buf, "exit") || core::init::cstr_equal(line_buf, "quit")) {
            break;
        }

        cmd_shell.execute_line(line_buf, out);
        cmd_shell.print_prompt(out);
    }

    return 0;
}
