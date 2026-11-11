#pragma once
// ============================================================================
// μCore Functional Core — Plan 9 Per-Domain Capability Namespaces ("9P-over-Flux")
// ============================================================================
// Synthesizes Plan 9 Composability + Zircon Capability Purity + Zero-Switch Rings:
//   - Zero Global Root `/` in Ring 0: processes possess ONLY the capability
//     conduits bound into their private `DomainNamespace` mount table.
//   - Plan 9 Union Mounts (`Replace`, `Before`, `After`):
//     Supervisors, shells, or sandboxes can transparently interpose tracing
//     filters, quotas, or remote network proxies via `MountOrder::Before`
//     without modifying a single line of client code!
//   - "Plan 9 Cold, Zero-Switch Hot":
//     Lookup (`resolve_path`) happens once on the cold `open()` path, returning
//     the target `CapToken`, relative subpath, and `can_promote_hot` (true iff
//     the bound capability holds `CapRights::FastPromote`). Direct Pacts upgrade
//     immediately to zero-syscall `Hot` rings; interposed Pacts stay observable!
// ============================================================================

#include "mucore/result.hpp"
#include "mucore/types.hpp"
#include "mucore/core/capability.hpp"

namespace mucore::core::ns {

inline constexpr usize MAX_PATH_BYTES        = 48;
inline constexpr usize MAX_MOUNTS_PER_DOMAIN = 12;
inline constexpr usize MAX_NAMESPACE_DOMAINS = 16;

enum class MountOrder : u8 {
    Replace = 0, // Plan 9 `bind` default: replaces existing bindings at same prefix
    Before  = 1, // Plan 9 `bind -b`: prepends to union (enables transparent interposition!)
    After   = 2, // Plan 9 `bind -a`: appends fallback behind existing union entries
};

struct PathString {
    char  bytes[MAX_PATH_BYTES]{};
    usize len{0};

    [[nodiscard]] static constexpr Result<PathString, Error> from_cstr(const char* s) noexcept {
        if (s == nullptr || s[0] != '/') {
            return Result<PathString, Error>::err(Error::InvalidArgument);
        }
        PathString out{};
        usize i = 0;
        while (s[i] != '\0') {
            if (i >= MAX_PATH_BYTES - 1) {
                return Result<PathString, Error>::err(Error::OutOfBounds);
            }
            out.bytes[i] = s[i];
            ++i;
        }
        // Strip trailing slash unless root "/"
        if (i > 1 && out.bytes[i - 1] == '/') {
            --i;
        }
        out.bytes[i] = '\0';
        out.len      = i;
        return Result<PathString, Error>::ok(out);
    }

    constexpr bool operator==(PathString const& o) const noexcept {
        if (len != o.len) return false;
        for (usize i = 0; i < len; ++i) {
            if (bytes[i] != o.bytes[i]) return false;
        }
        return true;
    }
};

struct MountEntry {
    bool          active{false};
    PathString    prefix{};
    cap::CapToken conduit_cap{};
    ConduitId     conduit_id{};
    bool          allow_hot_promote{false};
};

struct ResolvedPath {
    cap::CapToken conduit_cap{};
    ConduitId     conduit_id{};
    PathString    rel_subpath{};     // Remaining path sent over 9P-over-Flux walk/open
    bool          can_promote_hot{false};
    u8            union_alternatives{0}; // Count of additional union fallback mounts!
};

struct DomainNamespace {
    bool       initialized{false};
    DomainId   domain{};
    MountEntry mounts[MAX_MOUNTS_PER_DOMAIN]{};
    usize      count{0};
};

struct NamespaceTable {
    DomainNamespace domains[MAX_NAMESPACE_DOMAINS]{};

    constexpr NamespaceTable() noexcept = default;
    NamespaceTable(NamespaceTable const&)            = delete;
    NamespaceTable& operator=(NamespaceTable const&) = delete;
    constexpr NamespaceTable(NamespaceTable&&) noexcept            = default;
    constexpr NamespaceTable& operator=(NamespaceTable&&) noexcept = default;
};

// ============================================================================
// PURE FUNCTIONAL NAMESPACE BINDING & PREFIX RESOLUTION
// ============================================================================

// True iff `prefix` is a proper path-component prefix of `full_path`
[[nodiscard]] constexpr bool matches_path_prefix(
    PathString const& prefix,
    PathString const& full_path
) noexcept {
    if (prefix.len == 1 && prefix.bytes[0] == '/') {
        return full_path.len >= 1 && full_path.bytes[0] == '/';
    }
    if (full_path.len < prefix.len) {
        return false;
    }
    for (usize i = 0; i < prefix.len; ++i) {
        if (full_path.bytes[i] != prefix.bytes[i]) {
            return false;
        }
    }
    // Must match either exact path or a '/' directory boundary!
    return (full_path.len == prefix.len) || (full_path.bytes[prefix.len] == '/');
}

[[nodiscard]] constexpr PathString extract_subpath(
    PathString const& prefix,
    PathString const& full_path
) noexcept {
    PathString sub{};
    if (full_path.len == prefix.len) {
        sub.bytes[0] = '/';
        sub.bytes[1] = '\0';
        sub.len      = 1;
        return sub;
    }
    usize const offset = (prefix.len == 1 && prefix.bytes[0] == '/') ? 0 : prefix.len;
    usize out_i = 0;
    for (usize i = offset; i < full_path.len && out_i < MAX_PATH_BYTES - 1; ++i) {
        sub.bytes[out_i++] = full_path.bytes[i];
    }
    sub.bytes[out_i] = '\0';
    sub.len          = out_i;
    return sub;
}

// Capability-verified Plan 9 `bind`: attaches `conduit_cap` at `prefix_cstr`
[[nodiscard]] constexpr Result<Unit, Error> bind_capability_path(
    NamespaceTable&   ns_table,
    cap::CapTable const& cap_table,
    DomainId          target_domain,
    const char*       prefix_cstr,
    cap::CapToken     conduit_cap,
    MountOrder        order
) noexcept {
    if (!target_domain) {
        return Result<Unit, Error>::err(Error::InvalidArgument);
    }

    auto path_res = PathString::from_cstr(prefix_cstr);
    if (path_res.is_err()) {
        return Result<Unit, Error>::err(path_res.error());
    }

    // Verify `target_domain` actually holds valid Read rights on `conduit_cap`!
    auto cap_res = cap::validate_capability(
        cap_table,
        target_domain,
        conduit_cap,
        cap::CapObjectKind::FluxConduit,
        cap::CapRights::Read
    );
    if (cap_res.is_err()) {
        return Result<Unit, Error>::err(cap_res.error());
    }

    cap::CapEntry const& ce = cap_res.value();
    bool const hot_allowed = (ce.rights & cap::CapRights::FastPromote) != 0;

    // Locate or allocate `DomainNamespace`
    Option<usize> dom_idx = Option<usize>::none();
    for (usize i = 0; i < MAX_NAMESPACE_DOMAINS; ++i) {
        if (ns_table.domains[i].initialized && ns_table.domains[i].domain == target_domain) {
            dom_idx = Option<usize>::some(i);
            break;
        }
    }
    if (dom_idx.is_none()) {
        for (usize i = 0; i < MAX_NAMESPACE_DOMAINS; ++i) {
            if (!ns_table.domains[i].initialized) {
                ns_table.domains[i].initialized = true;
                ns_table.domains[i].domain      = target_domain;
                dom_idx = Option<usize>::some(i);
                break;
            }
        }
    }
    if (dom_idx.is_none()) {
        return Result<Unit, Error>::err(Error::TableFull);
    }

    DomainNamespace& dns = ns_table.domains[dom_idx.value()];
    MountEntry const new_mount{
        .active            = true,
        .prefix            = path_res.value(),
        .conduit_cap       = conduit_cap,
        .conduit_id        = ConduitId{static_cast<u32>(ce.object_id)},
        .allow_hot_promote = hot_allowed,
    };

    if (order == MountOrder::Replace) {
        // Compact out any existing mounts with identical prefix, then append
        usize write_pos = 0;
        for (usize i = 0; i < dns.count; ++i) {
            if (!(dns.mounts[i].prefix == new_mount.prefix)) {
                dns.mounts[write_pos++] = dns.mounts[i];
            }
        }
        dns.count = write_pos;
        if (dns.count >= MAX_MOUNTS_PER_DOMAIN) {
            return Result<Unit, Error>::err(Error::TableFull);
        }
        dns.mounts[dns.count++] = new_mount;
        return Result<Unit, Error>::ok(Unit{});
    }

    if (dns.count >= MAX_MOUNTS_PER_DOMAIN) {
        return Result<Unit, Error>::err(Error::TableFull);
    }

    if (order == MountOrder::Before) {
        // Shift entries right so `new_mount` wins union priority at index 0!
        for (usize i = dns.count; i > 0; --i) {
            dns.mounts[i] = dns.mounts[i - 1];
        }
        dns.mounts[0] = new_mount;
        dns.count += 1;
        return Result<Unit, Error>::ok(Unit{});
    }

    // MountOrder::After
    dns.mounts[dns.count++] = new_mount;
    return Result<Unit, Error>::ok(Unit{});
}

// Compact out every mount of `domain` whose capability is no longer valid. `resolve_path`
// already skips such mounts; pruning returns their table slots so the path can be re-bound.
constexpr u32 prune_revoked_mounts(
    NamespaceTable&      ns_table,
    cap::CapTable const& cap_table,
    DomainId             domain
) noexcept {
    for (usize d = 0; d < MAX_NAMESPACE_DOMAINS; ++d) {
        DomainNamespace& dns = ns_table.domains[d];
        if (!dns.initialized || !(dns.domain == domain)) continue;

        usize write_pos = 0;
        for (usize i = 0; i < dns.count; ++i) {
            auto valid = cap::validate_capability(
                cap_table, domain, dns.mounts[i].conduit_cap,
                cap::CapObjectKind::FluxConduit, cap::CapRights::Read
            );
            if (valid.is_ok()) {
                dns.mounts[write_pos++] = dns.mounts[i];
            }
        }
        u32 const pruned = static_cast<u32>(dns.count - write_pos);
        for (usize i = write_pos; i < dns.count; ++i) {
            dns.mounts[i] = MountEntry{};
        }
        dns.count = write_pos;
        return pruned;
    }
    return 0;
}

// Discard the whole private namespace of an exited domain.
constexpr bool drop_domain_namespace(NamespaceTable& ns_table, DomainId domain) noexcept {
    for (usize d = 0; d < MAX_NAMESPACE_DOMAINS; ++d) {
        if (ns_table.domains[d].initialized && ns_table.domains[d].domain == domain) {
            ns_table.domains[d] = DomainNamespace{};
            return true;
        }
    }
    return false;
}

// Resolve a human-readable path inside `caller`'s private namespace:
//   - Longest matching prefix wins.
//   - Among equal-length union prefixes, earlier mount order (`Before` > `After`) wins!
//   - Automatically skips any mount whose capability has been revoked!
[[nodiscard]] constexpr Result<ResolvedPath, Error> resolve_path(
    NamespaceTable const& ns_table,
    cap::CapTable const&  cap_table,
    DomainId              caller,
    const char*           full_path_cstr
) noexcept {
    auto query_res = PathString::from_cstr(full_path_cstr);
    if (query_res.is_err()) {
        return Result<ResolvedPath, Error>::err(query_res.error());
    }
    PathString const& query = query_res.value();

    for (usize d = 0; d < MAX_NAMESPACE_DOMAINS; ++d) {
        DomainNamespace const& dns = ns_table.domains[d];
        if (!dns.initialized || !(dns.domain == caller)) continue;

        Option<usize> best_idx = Option<usize>::none();
        usize         best_len = 0;
        u8            union_alts = 0;

        for (usize m = 0; m < dns.count; ++m) {
            MountEntry const& me = dns.mounts[m];
            if (!me.active || !matches_path_prefix(me.prefix, query)) continue;

            // Live capability check ensures revoked mounts silently fall through union!
            auto valid = cap::validate_capability(
                cap_table, caller, me.conduit_cap, cap::CapObjectKind::FluxConduit, cap::CapRights::Read
            );
            if (valid.is_err()) continue;

            if (best_idx.is_none() || me.prefix.len > best_len) {
                best_idx   = Option<usize>::some(m);
                best_len   = me.prefix.len;
                union_alts = 0;
            } else if (me.prefix.len == best_len) {
                union_alts += 1;
            }
        }

        if (best_idx.is_some()) {
            MountEntry const& winner = dns.mounts[best_idx.value()];
            return Result<ResolvedPath, Error>::ok(ResolvedPath{
                .conduit_cap        = winner.conduit_cap,
                .conduit_id         = winner.conduit_id,
                .rel_subpath        = extract_subpath(winner.prefix, query),
                .can_promote_hot    = winner.allow_hot_promote,
                .union_alternatives = union_alts,
            });
        }
        return Result<ResolvedPath, Error>::err(Error::NamespaceNotFound);
    }

    return Result<ResolvedPath, Error>::err(Error::NamespaceNotFound);
}

} // namespace mucore::core::ns
