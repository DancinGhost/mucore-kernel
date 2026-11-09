#pragma once
// ============================================================================
// μCore Imperative Shell — Cache-Aligned Wait-Free Shared-Memory SPSC Ring
// ============================================================================
// Mapped directly across Ring-0 / Ring-3 or Client / Userspace-Driver pages:
//   - Wait-Free (NOT merely lock-free!): exact O(1) instruction bound with
//     zero Compare-And-Swap (CAS) retry loops — preserving Hard Real-Time WCET.
//   - False-Sharing Immune: `head_` and `tail_` sit on separate 64-byte cache
//     lines so simultaneous Ring-3 production and Ring-0/Driver consumption
//     incur zero L1d MESI invalidation ping-pong.
//   - Freestanding Acquire/Release Atomics: uses compiler `__atomic_*` intrinsics
//     directly — zero dependency on hosted `<atomic>`.
// ============================================================================

#include "mucore/result.hpp"
#include "mucore/types.hpp"

namespace mucore::shell {

template <typename T, u32 CapacityPow2>
class SharedSpscRing {
    static_assert((CapacityPow2 >= 2) && ((CapacityPow2 & (CapacityPow2 - 1)) == 0),
                  "SharedSpscRing capacity must be a power of two");

public:
    constexpr SharedSpscRing() noexcept = default;
    SharedSpscRing(SharedSpscRing const&)            = delete;
    SharedSpscRing& operator=(SharedSpscRing const&) = delete;

    // Producer-only: O(1) wait-free enqueue
    [[nodiscard]] Result<Unit, Error> try_push(T const& item) noexcept {
        u32 const head = __atomic_load_n(&head_, __ATOMIC_RELAXED);
        u32 const tail = __atomic_load_n(&tail_, __ATOMIC_ACQUIRE);

        if ((head - tail) >= CapacityPow2) {
            return Result<Unit, Error>::err(Error::RingFull);
        }

        slots_[head & (CapacityPow2 - 1)] = item;
        __atomic_store_n(&head_, head + 1u, __ATOMIC_RELEASE);
        return Result<Unit, Error>::ok(Unit{});
    }

    // Consumer-only: O(1) wait-free dequeue
    [[nodiscard]] Option<T> try_pop() noexcept {
        u32 const tail = __atomic_load_n(&tail_, __ATOMIC_RELAXED);
        u32 const head = __atomic_load_n(&head_, __ATOMIC_ACQUIRE);

        if (tail == head) {
            return Option<T>::none();
        }

        T const out = slots_[tail & (CapacityPow2 - 1)];
        __atomic_store_n(&tail_, tail + 1u, __ATOMIC_RELEASE);
        return Option<T>::some(out);
    }

    [[nodiscard]] u32 approx_depth() const noexcept {
        u32 const h = __atomic_load_n(&head_, __ATOMIC_ACQUIRE);
        u32 const t = __atomic_load_n(&tail_, __ATOMIC_ACQUIRE);
        return h - t;
    }

private:
    alignas(CACHE_LINE_BYTES) u32 head_{0};
    u8 pad_head_[CACHE_LINE_BYTES - sizeof(u32)]{};

    alignas(CACHE_LINE_BYTES) u32 tail_{0};
    u8 pad_tail_[CACHE_LINE_BYTES - sizeof(u32)]{};

    alignas(CACHE_LINE_BYTES) T slots_[CapacityPow2]{};
};

} // namespace mucore::shell
