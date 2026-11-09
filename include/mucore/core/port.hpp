#pragma once
// ============================================================================
// μCore Functional Core — `FluxPort` O(1) Readiness Aggregator (Zircon / NT)
// ============================================================================
// Solves the SPSC Fan-In Polling Bottleneck:
//   When 1 Userspace Driver or Compositor serves N isolated clients over
//   Wait-Free SPSC `FluxConduit`s, polling all N rings degrades to O(N) cache
//   thrashing. Inspired by Zircon's `zx_port` and Windows NT's `IOCP`:
//     - Conduits bind to a `FluxPort` slot (`0..63` per port).
//     - Signaling sets a bit in `urgent_ready_bitmap` or `normal_ready_bitmap`
//       (idempotent O(1) bitwise OR — immune to notification queue overflow!).
//     - `pop_ready_event()` uses `ctz64` to wake & service ONLY active conduits
//       in exact O(1) time, strictly prioritizing Urgent Real-Time events!
// ============================================================================

#include "mucore/result.hpp"
#include "mucore/types.hpp"

namespace mucore::core::port {

inline constexpr usize MAX_PORTS              = 16;
inline constexpr usize MAX_BOUND_PER_PORT     = 64; // Matches 64-bit ctz64 word!

struct PortBinding {
    bool      bound{false};
    ConduitId conduit{};
    u64       user_key{0}; // Server-assigned correlation cookie (like epoll/zx_port key)
};

struct PortNotification {
    ConduitId conduit{};
    u64       user_key{0};
    bool      is_urgent_rt{false};
};

struct FluxPortState {
    bool        active{false};
    PortId      id{};
    DomainId    owner{};
    ThreadId    waiting_server_thread{};
    PortBinding bindings[MAX_BOUND_PER_PORT]{};
    u64         urgent_ready_bitmap{0}; // Tier-0 Hard-RT conduits ready
    u64         normal_ready_bitmap{0}; // Tier-1 Bulk Async conduits ready
    u64         total_notifications{0};
};

[[nodiscard]] constexpr Result<u8, Error> bind_conduit_to_port(
    FluxPortState& port,
    ConduitId      conduit,
    u64            user_key
) noexcept {
    if (!port.active || !conduit) {
        return Result<u8, Error>::err(Error::InvalidArgument);
    }

    // Reject duplicate binding of same conduit on same port
    for (usize i = 0; i < MAX_BOUND_PER_PORT; ++i) {
        if (port.bindings[i].bound && port.bindings[i].conduit == conduit) {
            return Result<u8, Error>::err(Error::InvalidState);
        }
    }

    for (u8 i = 0; i < MAX_BOUND_PER_PORT; ++i) {
        if (!port.bindings[i].bound) {
            port.bindings[i] = PortBinding{
                .bound    = true,
                .conduit  = conduit,
                .user_key = user_key,
            };
            return Result<u8, Error>::ok(i);
        }
    }
    return Result<u8, Error>::err(Error::TableFull);
}

// O(1) idempotent readiness signal (zero overflow risk under burst floods!)
[[nodiscard]] constexpr Result<Unit, Error> signal_port_slot(
    FluxPortState& port,
    u8             bind_slot,
    bool           urgent_rt
) noexcept {
    if (!port.active || bind_slot >= MAX_BOUND_PER_PORT || !port.bindings[bind_slot].bound) {
        return Result<Unit, Error>::err(Error::InvalidArgument);
    }

    u64 const bit = (1ULL << bind_slot);
    if (urgent_rt) {
        port.urgent_ready_bitmap |= bit;
    } else {
        port.normal_ready_bitmap |= bit;
    }
    port.total_notifications += 1;
    return Result<Unit, Error>::ok(Unit{});
}

// Exact O(1) active conduit extraction (`ctz64`): Urgent RT strictly preempts Normal!
[[nodiscard]] constexpr Option<PortNotification> pop_ready_conduit(
    FluxPortState& port
) noexcept {
    if (!port.active) {
        return Option<PortNotification>::none();
    }

    if (port.urgent_ready_bitmap != 0ULL) {
        u32 const slot = ctz64(port.urgent_ready_bitmap);
        port.urgent_ready_bitmap &= ~(1ULL << slot);
        PortBinding const& b = port.bindings[slot];
        return Option<PortNotification>::some(PortNotification{
            .conduit      = b.conduit,
            .user_key     = b.user_key,
            .is_urgent_rt = true,
        });
    }

    if (port.normal_ready_bitmap != 0ULL) {
        u32 const slot = ctz64(port.normal_ready_bitmap);
        port.normal_ready_bitmap &= ~(1ULL << slot);
        PortBinding const& b = port.bindings[slot];
        return Option<PortNotification>::some(PortNotification{
            .conduit      = b.conduit,
            .user_key     = b.user_key,
            .is_urgent_rt = false,
        });
    }

    return Option<PortNotification>::none();
}

[[nodiscard]] constexpr bool has_pending(FluxPortState const& port) noexcept {
    return port.active && ((port.urgent_ready_bitmap | port.normal_ready_bitmap) != 0ULL);
}

} // namespace mucore::core::port
