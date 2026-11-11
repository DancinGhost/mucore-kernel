#pragma once
// ============================================================================
// μCore Functional Core — Init: Compile-Time Service Manifest & Supervisor
// ============================================================================
// Init is the first holder of authority. It turns a static description of the
// system's services into live kernel objects, then restarts services whose
// domain exits. It is layered ABOVE `dispatch_event`: the dispatcher and
// `KernelState` carry no init fields and no init branches.
//
//   1. Compile-Time Manifest (`plan_boot` / `compile_manifest`):
//      A `ServiceSpec[]` table is validated and lowered to a `BootPlan` inside
//      the compiler. Import paths are matched to exports, rights attenuation,
//      RT admission (sum of C_i/T_i <= 85%), identity uniqueness and dependency
//      acyclicity are all checked, and the boot order is topologically sorted
//      there. A bad manifest does not build; the kernel image carries only the
//      resolved plan in `.rodata` and does no parsing, sorting or path matching.
//
//   2. Wiring (`boot_services`):
//      Each service gets a thread, its private grants, one `FluxPort` if it
//      exports anything, and one dedicated SPSC conduit per import, bound into
//      its private Plan-9 namespace. Every capability a service holds lives in
//      a revocation group owned by the service that backs it.
//
//   3. Supervision (`supervise_domain_exit`), cold path only:
//      Init holds one `DomainControl` capability per service. Revoking that
//      lineage invalidates, in one epoch bump, everything the service held and
//      every capability its clients held on it. Restart is immediate and
//      bounded by `max_restarts`; a restarted Tier-0 thread stays throttled
//      until its next CBS period. Clients keep running and are re-wired with
//      fresh conduits; requests in flight on the old conduits are lost.
//
// Costs that remain at run time: `InitState` (88 bytes per service) and work
// proportional to the service's wiring when a domain exits.
// ============================================================================

#include "mucore/core/dispatcher.hpp"

namespace mucore::core::init {

inline constexpr usize MAX_SERVICES            = 16;
inline constexpr usize MAX_GRANTS_PER_SERVICE  = 4;
inline constexpr usize MAX_EXPORTS_PER_SERVICE = 2;
inline constexpr usize MAX_IMPORTS_PER_SERVICE = 4;

// Init's own protection domain: owner of every `DomainControl` capability.
inline constexpr DomainId INIT_DOMAIN{1};

// Identifier ranges reserved for objects that init creates.
inline constexpr u16 INIT_GROUP_BASE   = 48;      // RevocationGroupId = base + service index
inline constexpr u32 INIT_CONDUIT_BASE = 0x1000;  // ConduitId = base + import edge index
inline constexpr u32 INIT_PORT_BASE    = 0x1000;  // PortId    = base + service index

// A manifest that passes `plan_boot` always fits the kernel's static tables.
static_assert(MAX_SERVICES <= 16, "service sets are tracked in u16 bitmasks");
static_assert(INIT_GROUP_BASE + MAX_SERVICES <= cap::MAX_REVOCATION_GROUPS);
static_assert(MAX_SERVICES <= sched::MAX_THREADS);
static_assert(MAX_SERVICES <= port::MAX_PORTS);
static_assert(MAX_SERVICES <= ns::MAX_NAMESPACE_DOMAINS);
static_assert(MAX_IMPORTS_PER_SERVICE <= ns::MAX_MOUNTS_PER_DOMAIN);
static_assert(MAX_CONDUITS <= port::MAX_BOUND_PER_PORT);
static_assert(MAX_SERVICES * (2 + MAX_GRANTS_PER_SERVICE + MAX_IMPORTS_PER_SERVICE)
              < cap::MAX_CAP_SLOTS);

// ============================================================================
// MANIFEST (authored as a `constexpr ServiceSpec[]`; unused array slots end a list)
// ============================================================================

enum class RestartPolicy : u8 {
    Never  = 0, // An exit is final
    Always = 1, // Restart on exit until `max_restarts` is used up
};

// A private kernel object handed to the service (IRQ line, Kineticlet slot, MMIO, ...).
struct GrantSpec {
    cap::CapObjectKind kind{cap::CapObjectKind::None};
    u16                rights{cap::CapRights::None};
    u64                object_id{0};
};

// An endpoint the service serves. `client_rights` is the most any importer may receive.
struct ExportSpec {
    const char* path{nullptr};
    u16         client_rights{cap::CapRights::Read | cap::CapRights::Write};
    bool        pinned_hot{false};
};

// An endpoint the service consumes, mounted in its namespace at `mount_at` (default: `path`).
// Mounts that share a prefix form a union: use `Before` / `After`, not `Replace`.
struct ImportSpec {
    const char*    path{nullptr};
    const char*    mount_at{nullptr};
    u16            rights{cap::CapRights::Read | cap::CapRights::Write};
    ns::MountOrder order{ns::MountOrder::Replace};
};

struct ServiceSpec {
    const char*       name{nullptr};
    DomainId          domain{};
    ThreadId          thread{};
    sched::SchedClass sched_class{sched::SchedClass::AsyncThroughput};
    sched::RtParams   rt{};
    RestartPolicy     restart{RestartPolicy::Always};
    u8                max_restarts{3};
    bool              critical{false}; // Unrecoverable failure halts the system
    GrantSpec         grants[MAX_GRANTS_PER_SERVICE]{};
    ExportSpec        exports[MAX_EXPORTS_PER_SERVICE]{};
    ImportSpec        imports[MAX_IMPORTS_PER_SERVICE]{};
};

// ============================================================================
// BOOT PLAN (the manifest after compile-time validation and resolution)
// ============================================================================

enum class PlanError : u8 {
    None = 0,
    TooManyServices,
    MissingIdentity,         // Name, domain or thread left empty
    ReservedDomain,          // Uses `INIT_DOMAIN`
    DuplicateIdentity,       // Name, domain or thread already used by an earlier service
    BadSchedParams,          // `Idle` class, or RT with WCET == 0 / WCET > period
    RtOverCommitted,         // Sum of RT utilization exceeds `sched::MAX_RT_UTIL_PPM`
    BadGrant,                // Kind init does not hand out, no rights, or `Revoke`
    DuplicateExclusiveGrant, // Same IRQ line / Kineticlet slot / MMIO region granted twice
    BadPath,                 // Not absolute or longer than `ns::MAX_PATH_BYTES`
    BadExportRights,         // `client_rights` lacks `Read` or contains `Revoke`
    DuplicateExportPath,
    UnresolvedImport,        // No service exports the path
    SelfImport,
    BadImportRights,         // Lacks `Read` (needed to mount) or contains `Revoke`
    ImportExceedsExport,     // Asks for a right the export does not offer
    TooManyConduits,         // More import edges than `MAX_CONDUITS`
    DependencyCycle,
};

[[nodiscard]] constexpr const char* plan_error_name(PlanError err) noexcept {
    switch (err) {
        case PlanError::None:                    return "None";
        case PlanError::TooManyServices:         return "TooManyServices";
        case PlanError::MissingIdentity:         return "MissingIdentity";
        case PlanError::ReservedDomain:          return "ReservedDomain";
        case PlanError::DuplicateIdentity:       return "DuplicateIdentity";
        case PlanError::BadSchedParams:          return "BadSchedParams";
        case PlanError::RtOverCommitted:         return "RtOverCommitted";
        case PlanError::BadGrant:                return "BadGrant";
        case PlanError::DuplicateExclusiveGrant: return "DuplicateExclusiveGrant";
        case PlanError::BadPath:                 return "BadPath";
        case PlanError::BadExportRights:         return "BadExportRights";
        case PlanError::DuplicateExportPath:     return "DuplicateExportPath";
        case PlanError::UnresolvedImport:        return "UnresolvedImport";
        case PlanError::SelfImport:              return "SelfImport";
        case PlanError::BadImportRights:         return "BadImportRights";
        case PlanError::ImportExceedsExport:     return "ImportExceedsExport";
        case PlanError::TooManyConduits:         return "TooManyConduits";
        case PlanError::DependencyCycle:         return "DependencyCycle";
    }
    return "UnknownPlanError";
}

// One import edge, fully resolved: no string matching is left for run time.
struct PlannedImport {
    u8             provider{0};   // Index of the exporting service in `BootPlan::services`
    u8             export_idx{0}; // Which of the provider's exports
    ConduitId      conduit{};     // Dedicated client -> provider SPSC conduit
    u16            rights{cap::CapRights::None};
    bool           pinned_hot{false};
    ns::MountOrder order{ns::MountOrder::Replace};
    const char*    mount_at{nullptr};
};

struct PlannedService {
    const char*            name{nullptr};
    DomainId               domain{};
    ThreadId               thread{};
    sched::SchedClass      sched_class{sched::SchedClass::AsyncThroughput};
    sched::RtParams        rt{};
    RestartPolicy          restart{RestartPolicy::Never};
    u8                     max_restarts{0};
    bool                   critical{false};
    cap::RevocationGroupId group{};  // Epoch that backs everything this service provides
    PortId                 port{};   // Non-zero iff the service exports at least one endpoint
    u16                    needs{0};   // Bitmask of services this one imports from
    u16                    clients{0}; // Bitmask of services that import from this one
    u8                     grant_count{0};
    u8                     export_count{0};
    u8                     import_count{0};
    GrantSpec              grants[MAX_GRANTS_PER_SERVICE]{};
    PlannedImport          imports[MAX_IMPORTS_PER_SERVICE]{};
};

struct BootPlan {
    PlannedService services[MAX_SERVICES]{};
    u8             order[MAX_SERVICES]{}; // Service indices, providers before their clients
    u8             count{0};
    u8             conduit_count{0};
    u64            rt_util_ppm{0};

    constexpr BootPlan() noexcept = default;
    BootPlan(BootPlan const&)            = delete;
    BootPlan& operator=(BootPlan const&) = delete;
    constexpr BootPlan(BootPlan&&) noexcept            = default;
    constexpr BootPlan& operator=(BootPlan&&) noexcept = default;
};

struct PlanResult {
    PlanError error{PlanError::None};
    u8        offender{0}; // Index of the manifest entry the error refers to
    BootPlan  plan{};
};

[[nodiscard]] constexpr bool cstr_equal(const char* a, const char* b) noexcept {
    if (a == nullptr || b == nullptr) return false;
    usize i = 0;
    while (a[i] != '\0' && a[i] == b[i]) {
        ++i;
    }
    return a[i] == b[i];
}

// Kinds init hands out as private grants. Conduits and ports come from imports/exports,
// and `DomainControl` stays with init.
[[nodiscard]] constexpr bool is_grantable_kind(cap::CapObjectKind kind) noexcept {
    return kind == cap::CapObjectKind::GrantArena || kind == cap::CapObjectKind::MmioRegion ||
           kind == cap::CapObjectKind::IrqHook    || kind == cap::CapObjectKind::KineticSlot ||
           kind == cap::CapObjectKind::RtBudget;
}

// Kinds whose object can have only one owner.
[[nodiscard]] constexpr bool is_exclusive_kind(cap::CapObjectKind kind) noexcept {
    return kind == cap::CapObjectKind::MmioRegion || kind == cap::CapObjectKind::IrqHook ||
           kind == cap::CapObjectKind::KineticSlot;
}

[[nodiscard]] constexpr PlanResult rejected(PlanError why, usize service) noexcept {
    PlanResult out{};
    out.error    = why;
    out.offender = static_cast<u8>(service);
    return out;
}

// Validate a manifest and lower it to a `BootPlan`. Pure; meant to run in the compiler
// (see `compile_manifest`), but callable at run time too, e.g. to test rejections.
template <usize N>
[[nodiscard]] constexpr PlanResult plan_boot(ServiceSpec const (&specs)[N]) noexcept {
    if (N > MAX_SERVICES) {
        return rejected(PlanError::TooManyServices, MAX_SERVICES);
    }

    PlanResult out{};
    BootPlan&  plan = out.plan;
    plan.count      = static_cast<u8>(N);

    // Pass 1: identity, scheduling, grants and exports of each service.
    for (usize i = 0; i < N; ++i) {
        ServiceSpec const& spec = specs[i];
        PlannedService&    svc  = plan.services[i];

        if (spec.name == nullptr || spec.name[0] == '\0' || !spec.domain || !spec.thread) {
            return rejected(PlanError::MissingIdentity, i);
        }
        if (spec.domain == INIT_DOMAIN) {
            return rejected(PlanError::ReservedDomain, i);
        }
        for (usize j = 0; j < i; ++j) {
            if (specs[j].domain == spec.domain || specs[j].thread == spec.thread ||
                cstr_equal(specs[j].name, spec.name)) {
                return rejected(PlanError::DuplicateIdentity, i);
            }
        }

        if (spec.sched_class == sched::SchedClass::Idle) {
            return rejected(PlanError::BadSchedParams, i);
        }
        if (spec.sched_class == sched::SchedClass::IsochronousRt) {
            auto util = sched::compute_rt_utilization_ppm(spec.rt);
            if (util.is_err()) {
                return rejected(PlanError::BadSchedParams, i);
            }
            plan.rt_util_ppm += util.value();
            if (plan.rt_util_ppm > sched::MAX_RT_UTIL_PPM) {
                return rejected(PlanError::RtOverCommitted, i);
            }
        }

        svc.name         = spec.name;
        svc.domain       = spec.domain;
        svc.thread       = spec.thread;
        svc.sched_class  = spec.sched_class;
        svc.rt           = spec.rt;
        svc.restart      = spec.restart;
        svc.max_restarts = spec.max_restarts;
        svc.critical     = spec.critical;
        svc.group        = cap::RevocationGroupId{static_cast<u16>(INIT_GROUP_BASE + i)};

        for (usize g = 0; g < MAX_GRANTS_PER_SERVICE; ++g) {
            GrantSpec const& grant = spec.grants[g];
            if (grant.kind == cap::CapObjectKind::None) break;

            if (!is_grantable_kind(grant.kind) || grant.rights == cap::CapRights::None ||
                (grant.rights & cap::CapRights::Revoke) != 0) {
                return rejected(PlanError::BadGrant, i);
            }
            if (is_exclusive_kind(grant.kind)) {
                for (usize j = 0; j <= i; ++j) {
                    PlannedService const& other = plan.services[j];
                    for (usize og = 0; og < other.grant_count; ++og) {
                        if (other.grants[og].kind == grant.kind &&
                            other.grants[og].object_id == grant.object_id) {
                            return rejected(PlanError::DuplicateExclusiveGrant, i);
                        }
                    }
                }
            }
            svc.grants[svc.grant_count++] = grant;
        }

        for (usize e = 0; e < MAX_EXPORTS_PER_SERVICE; ++e) {
            ExportSpec const& exp = spec.exports[e];
            if (exp.path == nullptr) break;

            if (ns::PathString::from_cstr(exp.path).is_err()) {
                return rejected(PlanError::BadPath, i);
            }
            if ((exp.client_rights & cap::CapRights::Read) == 0 ||
                (exp.client_rights & cap::CapRights::Revoke) != 0) {
                return rejected(PlanError::BadExportRights, i);
            }
            for (usize j = 0; j <= i; ++j) {
                usize const limit = (j == i) ? e : MAX_EXPORTS_PER_SERVICE;
                for (usize oe = 0; oe < limit && specs[j].exports[oe].path != nullptr; ++oe) {
                    if (cstr_equal(specs[j].exports[oe].path, exp.path)) {
                        return rejected(PlanError::DuplicateExportPath, i);
                    }
                }
            }
            svc.export_count += 1;
        }
        if (svc.export_count > 0) {
            svc.port = PortId{static_cast<u32>(INIT_PORT_BASE + i)};
        }
    }

    // Pass 2: resolve every import to (provider, export) and give it a conduit.
    u32 edges = 0;
    for (usize i = 0; i < N; ++i) {
        ServiceSpec const& spec = specs[i];
        PlannedService&    svc  = plan.services[i];

        for (usize k = 0; k < MAX_IMPORTS_PER_SERVICE; ++k) {
            ImportSpec const& imp = spec.imports[k];
            if (imp.path == nullptr) break;

            usize provider   = N;
            usize export_idx = 0;
            for (usize j = 0; j < N && provider == N; ++j) {
                for (usize e = 0; e < MAX_EXPORTS_PER_SERVICE; ++e) {
                    if (specs[j].exports[e].path == nullptr) break;
                    if (cstr_equal(specs[j].exports[e].path, imp.path)) {
                        provider   = j;
                        export_idx = e;
                        break;
                    }
                }
            }
            if (provider == N) {
                return rejected(PlanError::UnresolvedImport, i);
            }
            if (provider == i) {
                return rejected(PlanError::SelfImport, i);
            }

            ExportSpec const& exp = specs[provider].exports[export_idx];
            if ((imp.rights & cap::CapRights::Read) == 0 ||
                (imp.rights & cap::CapRights::Revoke) != 0) {
                return rejected(PlanError::BadImportRights, i);
            }
            if ((imp.rights & ~exp.client_rights) != 0) {
                return rejected(PlanError::ImportExceedsExport, i);
            }

            const char* const mount_at = (imp.mount_at != nullptr) ? imp.mount_at : imp.path;
            if (ns::PathString::from_cstr(mount_at).is_err()) {
                return rejected(PlanError::BadPath, i);
            }
            if (edges >= MAX_CONDUITS) {
                return rejected(PlanError::TooManyConduits, i);
            }

            svc.imports[svc.import_count++] = PlannedImport{
                .provider   = static_cast<u8>(provider),
                .export_idx = static_cast<u8>(export_idx),
                .conduit    = ConduitId{INIT_CONDUIT_BASE + edges},
                .rights     = imp.rights,
                .pinned_hot = exp.pinned_hot,
                .order      = imp.order,
                .mount_at   = mount_at,
            };
            svc.needs = static_cast<u16>(svc.needs | (1u << provider));
            plan.services[provider].clients =
                static_cast<u16>(plan.services[provider].clients | (1u << i));
            ++edges;
        }
    }
    plan.conduit_count = static_cast<u8>(edges);

    // Pass 3: boot order. Repeatedly take the lowest-numbered service whose providers are
    // all placed; if none qualifies while services remain, the imports form a cycle.
    u16 placed = 0;
    for (usize n = 0; n < N; ++n) {
        usize pick      = N;
        usize unplaced  = N;
        for (usize i = 0; i < N; ++i) {
            if ((placed & (1u << i)) != 0) continue;
            if (unplaced == N) unplaced = i;
            if ((plan.services[i].needs & ~placed) == 0) {
                pick = i;
                break;
            }
        }
        if (pick == N) {
            return rejected(PlanError::DependencyCycle, unplaced);
        }
        plan.order[n] = static_cast<u8>(pick);
        placed        = static_cast<u16>(placed | (1u << pick));
    }

    return out;
}

// Deliberately neither `constexpr` nor defined: reaching this call during constant
// evaluation is what turns an invalid manifest into a compile error. To see which rule
// failed, `static_assert(plan_boot(MANIFEST).error == PlanError::None)` prints the code.
void manifest_rejected(PlanError why, usize offending_service);

template <usize N>
[[nodiscard]] consteval BootPlan compile_manifest(ServiceSpec const (&specs)[N]) {
    PlanResult result = plan_boot(specs);
    if (result.error != PlanError::None) {
        manifest_rejected(result.error, result.offender);
    }
    return mucore::move(result.plan);
}

[[nodiscard]] constexpr Option<usize> find_service_by_domain(
    BootPlan const& plan,
    DomainId        domain
) noexcept {
    if (!domain) return Option<usize>::none();
    for (usize i = 0; i < plan.count; ++i) {
        if (plan.services[i].domain == domain) {
            return Option<usize>::some(i);
        }
    }
    return Option<usize>::none();
}

[[nodiscard]] constexpr Option<usize> find_service_by_name(
    BootPlan const& plan,
    const char*     name
) noexcept {
    for (usize i = 0; i < plan.count; ++i) {
        if (cstr_equal(plan.services[i].name, name)) {
            return Option<usize>::some(i);
        }
    }
    return Option<usize>::none();
}

// ============================================================================
// RUN-TIME STATE (the only memory init occupies after boot)
// ============================================================================

enum class ServiceState : u8 {
    Stopped = 0,
    Running = 1,
    Failed  = 2, // Restart budget used up, policy `Never`, or a (re)start failed
};

struct ServiceRuntime {
    ServiceState  state{ServiceState::Stopped};
    u8            restarts{0};
    cap::CapToken control_cap{}; // Held by init: `Revoke` authority over the service's group
    cap::CapToken port_cap{};    // Held by the service: its receive `FluxPort`
    cap::CapToken grant_caps[MAX_GRANTS_PER_SERVICE]{};  // Held by the service, manifest order
    cap::CapToken import_caps[MAX_IMPORTS_PER_SERVICE]{}; // Held by the service; 0 = not wired
};

struct InitState {
    ServiceRuntime services[MAX_SERVICES]{};
    bool           booted{false};
    u32            exits_handled{0};
    u32            restarts{0};
    u32            failures{0};
    u32            wiring_failures{0}; // Imports that could not be re-established

    constexpr InitState() noexcept = default;
    InitState(InitState const&)            = delete;
    InitState& operator=(InitState const&) = delete;
    constexpr InitState(InitState&&) noexcept            = default;
    constexpr InitState& operator=(InitState&&) noexcept = default;
};

struct BootReport {
    u8 started{0};
    u8 failed{0};
};

enum class Verdict : u8 {
    Unmanaged  = 0, // Not an init service, or not running: nothing done
    Restarted  = 1,
    GaveUp     = 2, // Service is now `Failed`; the rest of the system continues
    HaltSystem = 3, // A critical service is now `Failed`
};

struct SuperviseOutcome {
    Verdict verdict{Verdict::Unmanaged};
    u8      service{0};
    u8      restarts{0};
    Error   start_error{Error::None}; // Why a restart attempt failed, if one was made
};

// ============================================================================
// WIRING ENGINE (pure transitions over `KernelState` + `InitState`)
// ============================================================================

// Cookie the provider reads from its `FluxPort` to tell which client and endpoint is ready.
[[nodiscard]] constexpr u64 port_user_key(usize client_service, u8 export_idx) noexcept {
    return (static_cast<u64>(client_service) << 8) | export_idx;
}

[[nodiscard]] constexpr Result<cap::CapToken, Error> mint_cap(
    KernelState&           st,
    DomainId               owner,
    cap::CapObjectKind     kind,
    u16                    rights,
    u64                    object_id,
    cap::RevocationGroupId group
) noexcept {
    auto mut = cap::plan_mint_root(st.caps, owner, kind, rights, object_id, group);
    if (mut.is_err()) {
        return Result<cap::CapToken, Error>::err(mut.error());
    }
    cap::apply_mutation(st.caps, mut.value());
    return Result<cap::CapToken, Error>::ok(mut.value().minted_token);
}

// Connect import `k` of `client` to its (running) provider: open the conduit, attach it to
// the provider's port, mint the client's capability in the PROVIDER's revocation group and
// mount it. Leaves nothing behind on failure.
[[nodiscard]] constexpr Result<Unit, Error> wire_import(
    KernelState&    st,
    InitState&      init,
    BootPlan const& plan,
    usize           client,
    usize           k
) noexcept {
    PlannedService const& svc  = plan.services[client];
    PlannedImport const&  imp  = svc.imports[k];
    PlannedService const& prov = plan.services[imp.provider];

    auto opened = open_conduit(
        st, imp.conduit, svc.domain, prov.domain, imp.pinned_hot, prov.thread
    );
    if (opened.is_err()) {
        return Result<Unit, Error>::err(opened.error());
    }

    auto attached = attach_conduit_to_port(
        st, imp.conduit, prov.port, port_user_key(client, imp.export_idx)
    );
    if (attached.is_err()) {
        (void)close_conduit(st, imp.conduit);
        return attached;
    }

    auto tok = mint_cap(
        st, svc.domain, cap::CapObjectKind::FluxConduit, imp.rights, imp.conduit.raw, prov.group
    );
    if (tok.is_err()) {
        (void)close_conduit(st, imp.conduit);
        return Result<Unit, Error>::err(tok.error());
    }

    auto bound = ns::bind_capability_path(
        st.namespaces, st.caps, svc.domain, imp.mount_at, tok.value(), imp.order
    );
    if (bound.is_err()) {
        auto undo = cap::plan_revoke_single(
            st.caps, INIT_DOMAIN, init.services[imp.provider].control_cap,
            tok.value().slot_index()
        );
        if (undo.is_ok()) {
            cap::apply_mutation(st.caps, undo.value());
        }
        (void)close_conduit(st, imp.conduit);
        return bound;
    }

    init.services[client].import_caps[k] = tok.value();
    return Result<Unit, Error>::ok(Unit{});
}

// Remove every kernel object and capability belonging to service `idx`. Idempotent.
constexpr void teardown_service(
    KernelState&    st,
    InitState&      init,
    BootPlan const& plan,
    usize           idx
) noexcept {
    PlannedService const& svc = plan.services[idx];
    ServiceRuntime&       rt  = init.services[idx];

    // Capabilities this service held on its providers live in the providers' groups, so
    // they go one slot at a time. The token is re-validated first: if the provider was torn
    // down in between, the slot may already belong to an unrelated capability.
    for (usize k = 0; k < svc.import_count; ++k) {
        cap::CapToken const tok = rt.import_caps[k];
        rt.import_caps[k]       = cap::CapToken{};
        if (!tok) continue;

        auto still_ours = cap::validate_capability(
            st.caps, svc.domain, tok, cap::CapObjectKind::FluxConduit, cap::CapRights::None
        );
        if (still_ours.is_err()) continue;

        auto revoke = cap::plan_revoke_single(
            st.caps, INIT_DOMAIN, init.services[svc.imports[k].provider].control_cap,
            tok.slot_index()
        );
        if (revoke.is_ok()) {
            cap::apply_mutation(st.caps, revoke.value());
        }
    }

    // One epoch bump: the control capability, the grants, the port capability and every
    // capability clients held on this service all become invalid.
    if (rt.control_cap) {
        auto revoke = cap::plan_revoke_lineage(st.caps, INIT_DOMAIN, rt.control_cap);
        if (revoke.is_ok()) {
            cap::apply_mutation(st.caps, revoke.value());
        }
    }
    rt.control_cap = cap::CapToken{};
    rt.port_cap    = cap::CapToken{};
    for (usize g = 0; g < MAX_GRANTS_PER_SERVICE; ++g) {
        rt.grant_caps[g] = cap::CapToken{};
    }

    (void)sched::reap_domain_threads(st.sched, svc.domain);
    (void)close_domain_conduits(st, svc.domain);
    if (svc.port) {
        (void)destroy_flux_port(st, svc.port);
    }
    (void)release_domain_fast_paths(st, svc.domain);
    (void)ns::drop_domain_namespace(st.namespaces, svc.domain);

    // Clients keep running: forget the tokens that just died and free their mount slots,
    // so union mounts fall through to the remaining providers until this one is back.
    for (usize c = 0; c < plan.count; ++c) {
        if (((svc.clients >> c) & 1u) == 0) continue;
        PlannedService const& client = plan.services[c];
        for (usize k = 0; k < client.import_count; ++k) {
            if (client.imports[k].provider == idx) {
                init.services[c].import_caps[k] = cap::CapToken{};
            }
        }
        (void)ns::prune_revoked_mounts(st.namespaces, st.caps, client.domain);
    }

    rt.state = ServiceState::Stopped;
}

[[nodiscard]] constexpr Result<Unit, Error> bring_up_service(
    KernelState&    st,
    InitState&      init,
    BootPlan const& plan,
    usize           idx,
    TickNs          now,
    bool            after_crash
) noexcept {
    PlannedService const& svc = plan.services[idx];
    ServiceRuntime&       rt  = init.services[idx];

    // Minted first, so a failure anywhere below can still be undone by one lineage revoke.
    auto control = mint_cap(
        st, INIT_DOMAIN, cap::CapObjectKind::DomainControl, cap::CapRights::Revoke,
        svc.domain.raw, svc.group
    );
    if (control.is_err()) {
        return Result<Unit, Error>::err(control.error());
    }
    rt.control_cap = control.value();

    auto spawned = sched::spawn_thread(
        st.sched, svc.thread, svc.domain, svc.sched_class, svc.rt, now
    );
    if (spawned.is_err()) {
        return Result<Unit, Error>::err(spawned.error());
    }
    if (after_crash && svc.sched_class == sched::SchedClass::IsochronousRt) {
        auto deferred = sched::defer_budget_to_next_period(st.sched, svc.thread);
        if (deferred.is_err()) {
            return deferred;
        }
    }

    for (usize g = 0; g < svc.grant_count; ++g) {
        GrantSpec const& grant = svc.grants[g];
        auto tok = mint_cap(st, svc.domain, grant.kind, grant.rights, grant.object_id, svc.group);
        if (tok.is_err()) {
            return Result<Unit, Error>::err(tok.error());
        }
        rt.grant_caps[g] = tok.value();
    }

    if (svc.port) {
        auto port_res = create_flux_port(st, svc.port, svc.domain, svc.thread);
        if (port_res.is_err()) {
            return Result<Unit, Error>::err(port_res.error());
        }
        auto tok = mint_cap(
            st, svc.domain, cap::CapObjectKind::FluxPort, cap::CapRights::Read,
            svc.port.raw, svc.group
        );
        if (tok.is_err()) {
            return Result<Unit, Error>::err(tok.error());
        }
        rt.port_cap = tok.value();
    }

    // Imports from providers that are down stay unwired; they are connected when (if) the
    // provider comes back.
    for (usize k = 0; k < svc.import_count; ++k) {
        if (init.services[svc.imports[k].provider].state != ServiceState::Running) continue;
        auto wired = wire_import(st, init, plan, idx, k);
        if (wired.is_err()) {
            return wired;
        }
    }

    rt.state = ServiceState::Running;

    // Give running clients fresh conduits to this (re)started provider. Empty at first
    // boot, because clients are ordered after their providers.
    for (usize c = 0; c < plan.count; ++c) {
        if (((svc.clients >> c) & 1u) == 0) continue;
        if (init.services[c].state != ServiceState::Running) continue;
        PlannedService const& client = plan.services[c];
        for (usize k = 0; k < client.import_count; ++k) {
            if (client.imports[k].provider != idx) continue;
            if (wire_import(st, init, plan, c, k).is_err()) {
                init.wiring_failures += 1;
            }
        }
    }

    return Result<Unit, Error>::ok(Unit{});
}

// Start one service. On failure everything it had acquired is released again and the
// service is left `Failed`.
[[nodiscard]] constexpr Result<Unit, Error> start_service(
    KernelState&    st,
    InitState&      init,
    BootPlan const& plan,
    usize           idx,
    TickNs          now,
    bool            after_crash = false
) noexcept {
    if (idx >= plan.count) {
        return Result<Unit, Error>::err(Error::OutOfBounds);
    }
    if (init.services[idx].state == ServiceState::Running) {
        return Result<Unit, Error>::err(Error::InvalidState);
    }

    auto res = bring_up_service(st, init, plan, idx, now, after_crash);
    if (res.is_err()) {
        teardown_service(st, init, plan, idx);
        init.services[idx].state = ServiceState::Failed;
        init.failures += 1;
    }
    return res;
}

// Bring up every service in plan order. A non-critical service that fails to start is
// left `Failed` and boot continues; a critical one aborts boot with its error.
[[nodiscard]] constexpr Result<BootReport, Error> boot_services(
    KernelState&    st,
    InitState&      init,
    BootPlan const& plan,
    TickNs          now
) noexcept {
    if (init.booted) {
        return Result<BootReport, Error>::err(Error::InvalidState);
    }
    init.booted = true;

    BootReport report{};
    for (usize n = 0; n < plan.count; ++n) {
        usize const idx = plan.order[n];
        auto res = start_service(st, init, plan, idx, now);
        if (res.is_ok()) {
            report.started += 1;
            continue;
        }
        report.failed += 1;
        if (plan.services[idx].critical) {
            return Result<BootReport, Error>::err(res.error());
        }
    }
    return Result<BootReport, Error>::ok(report);
}

// ============================================================================
// SUPERVISION (cold path: runs only when a protection domain exits)
// ============================================================================

// React to the exit of `domain`. Call this after the kernel's own `DomainCrashTeardown`
// event has been dispatched (that event quarantines the domain's in-flight DMA arenas).
[[nodiscard]] constexpr SuperviseOutcome supervise_domain_exit(
    KernelState&    st,
    InitState&      init,
    BootPlan const& plan,
    DomainId        domain,
    TickNs          now
) noexcept {
    auto found = find_service_by_domain(plan, domain);
    if (found.is_none() || init.services[found.value()].state != ServiceState::Running) {
        return SuperviseOutcome{};
    }

    usize const           idx = found.value();
    PlannedService const& svc = plan.services[idx];
    ServiceRuntime&       rt  = init.services[idx];

    init.exits_handled += 1;
    teardown_service(st, init, plan, idx);

    SuperviseOutcome out{};
    out.service = static_cast<u8>(idx);

    if (svc.restart == RestartPolicy::Always && rt.restarts < svc.max_restarts) {
        rt.restarts += 1;
        auto res = start_service(st, init, plan, idx, now, true);
        if (res.is_ok()) {
            init.restarts += 1;
            out.verdict  = Verdict::Restarted;
            out.restarts = rt.restarts;
            return out;
        }
        out.start_error = res.error(); // `start_service` already marked it `Failed`
    } else {
        rt.state = ServiceState::Failed;
        init.failures += 1;
    }

    out.verdict  = svc.critical ? Verdict::HaltSystem : Verdict::GaveUp;
    out.restarts = rt.restarts;
    return out;
}

// The supervision half of one kernel step: call it for every event the dispatcher
// accepted. Live shells and trace replay both go through here, so they cannot diverge.
[[nodiscard]] constexpr SuperviseOutcome supervise_after_event(
    KernelState&       st,
    InitState&         init,
    BootPlan const&    plan,
    KernelEvent const& ev
) noexcept {
    if (ev.kind != EventKind::DomainCrashTeardown) {
        return SuperviseOutcome{};
    }
    return supervise_domain_exit(st, init, plan, ev.caller_domain, ev.timestamp);
}

// Replay a recorded event trace into a state that was booted from the same plan,
// re-running supervision after each accepted event exactly as the live shell does.
// `Trace` is `shell::TraceRing` (kept generic so the core does not include the shell).
template <typename Trace>
[[nodiscard]] constexpr Result<u64, Error> replay_supervised(
    Trace const&    trace,
    KernelState&    fresh_state,
    InitState&      fresh_init,
    BootPlan const& plan
) noexcept {
    usize const count = trace.available();
    for (usize i = 0; i < count; ++i) {
        auto rec = trace.get_recent(count - 1 - i);
        if (rec.is_none()) {
            return Result<u64, Error>::err(Error::InvalidState);
        }
        auto res = dispatch_event(fresh_state, rec.value().event);
        if (res.is_err()) {
            if (rec.value().status == Error::None) {
                return Result<u64, Error>::err(res.error());
            }
            continue;
        }
        (void)supervise_after_event(fresh_state, fresh_init, plan, rec.value().event);
    }
    return Result<u64, Error>::ok(static_cast<u64>(count));
}

} // namespace mucore::core::init
