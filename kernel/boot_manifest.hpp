#pragma once
// ============================================================================
// μCore (mucore-kernel) — Boot Service Manifest
// ============================================================================
// The services init brings up on the bootstrap processor, in any order: the
// planner sorts them. `compile_manifest` runs inside the compiler, so an invalid
// entry here (import cycle, rights escalation, RT over-commit, ...) fails the
// build and the kernel image carries only the resolved `PLAN`.
//
// Until Phase 3 provides a Ring-3 ELF host these domains have no code of their
// own: init creates their threads, capabilities, conduits and namespaces, and
// the Ring-0 POST drives the `nvme` fast path on the driver's behalf.
// ============================================================================

#include "mucore/core/init.hpp"

namespace mucore::boot {

namespace Rights = core::cap::CapRights;

inline constexpr u64 NVME_IRQ_LINE     = 32;
inline constexpr u64 NVME_KINETIC_SLOT = 1;

inline constexpr core::init::ServiceSpec SERVICES[] = {
    {
        .name        = "nvme",
        .domain      = DomainId{2},
        .thread      = ThreadId{2},
        .sched_class = core::sched::SchedClass::IsochronousRt,
        .rt          = {.wcet_ns = 100'000ULL, .period_ns = 1'000'000ULL}, // 10% CBS
        .critical    = true,
        .grants      = {
            {.kind      = core::cap::CapObjectKind::KineticSlot,
             .rights    = Rights::ExecuteRing0 | Rights::Read | Rights::Write,
             .object_id = NVME_KINETIC_SLOT},
            {.kind      = core::cap::CapObjectKind::IrqHook,
             .rights    = Rights::Read | Rights::Write,
             .object_id = NVME_IRQ_LINE},
        },
        .exports     = {{
            .path          = "/dev/nvme0",
            .client_rights = Rights::Read | Rights::Write | Rights::UrgentRt | Rights::FastPromote,
            .pinned_hot    = true,
        }},
    },
    {
        .name    = "vfs",
        .domain  = DomainId{3},
        .thread  = ThreadId{3},
        .exports = {{.path = "/srv/vfs"}},
        .imports = {{
            .path   = "/dev/nvme0",
            .rights = Rights::Read | Rights::Write | Rights::UrgentRt | Rights::FastPromote,
        }},
    },
    {
        .name    = "shell",
        .domain  = DomainId{4},
        .thread  = ThreadId{4},
        .imports = {{.path = "/srv/vfs", .mount_at = "/n/root"}},
    },
};

inline constexpr core::init::BootPlan PLAN = core::init::compile_manifest(SERVICES);

// Positions the Ring-0 POST relies on.
inline constexpr usize NVME               = 0;
inline constexpr usize VFS                = 1;
inline constexpr usize NVME_GRANT_KINETIC = 0;
inline constexpr usize NVME_GRANT_IRQ     = 1;

static_assert(core::init::cstr_equal(PLAN.services[NVME].name, "nvme") &&
              core::init::cstr_equal(PLAN.services[VFS].name, "vfs") &&
              PLAN.services[NVME].grants[NVME_GRANT_KINETIC].kind ==
                  core::cap::CapObjectKind::KineticSlot &&
              PLAN.services[NVME].grants[NVME_GRANT_IRQ].kind ==
                  core::cap::CapObjectKind::IrqHook,
              "kmain's POST indexes the nvme service and its grants by position");

// Proof, checked on every build: on a pristine kernel this exact plan starts every service.
consteval bool plan_boots_on_pristine_kernel() {
    core::KernelState     st{};
    core::init::InitState ini{};
    auto report = core::init::boot_services(st, ini, PLAN, TickNs{0});
    return report.is_ok() && report.value().started == PLAN.count;
}
static_assert(plan_boots_on_pristine_kernel(),
              "The boot manifest does not fit the kernel's static tables");

} // namespace mucore::boot
