#pragma once
// ============================================================================
// μCore (mucore-kernel) — Init Test Manifest (shared by proofs and host suite)
// ============================================================================
// A four-service storage stack, listed clients-first on purpose so the planner
// has to reorder it:
//
//   shell ──/n/root──▶ vfs ──/dev/nvme0 (Before)──▶ blktrace ──▶ nvme
//                       └────/dev/nvme0 (After) ─────────────────▶ nvme
//
// `vfs` reaches the disk through the `blktrace` interposer and keeps the direct
// `nvme` endpoint as a union fallback at the same path.
// ============================================================================

#include "mucore/core/init.hpp"

namespace mucore::fixture {

using core::cap::CapObjectKind;
namespace Rights = core::cap::CapRights;

inline constexpr usize SHELL    = 0;
inline constexpr usize VFS      = 1;
inline constexpr usize BLKTRACE = 2;
inline constexpr usize NVME     = 3;

inline constexpr DomainId SHELL_DOM{13};
inline constexpr DomainId VFS_DOM{12};
inline constexpr DomainId BLKTRACE_DOM{11};
inline constexpr DomainId NVME_DOM{10};

inline constexpr ThreadId NVME_TID{10};
inline constexpr ThreadId BLKTRACE_TID{11};

inline constexpr u64 NVME_WCET_NS   = 100'000ULL;
inline constexpr u64 NVME_PERIOD_NS = 1'000'000ULL;
inline constexpr u64 NVME_IRQ       = 48ULL;

inline constexpr core::init::ServiceSpec SERVICES[] = {
    {
        .name    = "shell",
        .domain  = SHELL_DOM,
        .thread  = ThreadId{13},
        .restart = core::init::RestartPolicy::Never,
        .imports = {{.path = "/srv/vfs", .mount_at = "/n/root"}},
    },
    {
        .name    = "vfs",
        .domain  = VFS_DOM,
        .thread  = ThreadId{12},
        .exports = {{.path = "/srv/vfs"}},
        .imports = {
            {.path     = "/srv/blktrace",
             .mount_at = "/dev/nvme0",
             .order    = core::ns::MountOrder::Before},
            {.path   = "/dev/nvme0",
             .rights = Rights::Read | Rights::Write | Rights::UrgentRt | Rights::FastPromote,
             .order  = core::ns::MountOrder::After},
        },
    },
    {
        .name         = "blktrace",
        .domain       = BLKTRACE_DOM,
        .thread       = BLKTRACE_TID,
        .max_restarts = 1,
        .exports      = {{.path = "/srv/blktrace"}},
        .imports      = {{.path = "/dev/nvme0"}},
    },
    {
        .name         = "nvme",
        .domain       = NVME_DOM,
        .thread       = NVME_TID,
        .sched_class  = core::sched::SchedClass::IsochronousRt,
        .rt           = {.wcet_ns = NVME_WCET_NS, .period_ns = NVME_PERIOD_NS},
        .max_restarts = 1,
        .critical     = true,
        .grants       = {
            {.kind      = CapObjectKind::KineticSlot,
             .rights    = Rights::ExecuteRing0 | Rights::Read | Rights::Write,
             .object_id = 1},
            {.kind      = CapObjectKind::IrqHook,
             .rights    = Rights::Read | Rights::Write,
             .object_id = NVME_IRQ},
        },
        .exports      = {{
            .path          = "/dev/nvme0",
            .client_rights = Rights::Read | Rights::Write | Rights::UrgentRt | Rights::FastPromote,
            .pinned_hot    = true,
        }},
    },
};

inline constexpr core::init::BootPlan PLAN = core::init::compile_manifest(SERVICES);

// Conduits are numbered in manifest order, one per import.
inline constexpr ConduitId SHELL_TO_VFS{core::init::INIT_CONDUIT_BASE + 0};
inline constexpr ConduitId VFS_TO_BLKTRACE{core::init::INIT_CONDUIT_BASE + 1};
inline constexpr ConduitId VFS_TO_NVME{core::init::INIT_CONDUIT_BASE + 2};
inline constexpr ConduitId BLKTRACE_TO_NVME{core::init::INIT_CONDUIT_BASE + 3};

} // namespace mucore::fixture
