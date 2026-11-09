#pragma once
// ============================================================================
// μCore Imperative Shell — Deterministic Flight Recorder (TraceRing)
// ============================================================================
// An emergent superpower of Functional Core / Imperative Shell in Ring 0:
//   Because `core::dispatch_event` is 100% deterministic and free of hidden
//   hardware reads, recording the stream of `KernelEvent` values allows exact
//   bit-for-bit time-travel replay of kernel execution in host unit tests!
// ============================================================================

#include "mucore/core/dispatcher.hpp"

namespace mucore::shell {

inline constexpr usize TRACE_CAPACITY = 128; // Power of two

struct TraceRecord {
    u64               seq_no{0};
    core::KernelEvent event{};
    Error             status{Error::None};
    u8                effect_count{0};
};

class TraceRing {
public:
    constexpr TraceRing() noexcept = default;
    TraceRing(TraceRing const&)            = delete;
    TraceRing& operator=(TraceRing const&) = delete;

    constexpr void record(
        core::KernelEvent const& ev,
        Error                    status,
        usize                    num_effects
    ) noexcept {
        usize const slot = static_cast<usize>(write_seq_ & (TRACE_CAPACITY - 1));
        entries_[slot] = TraceRecord{
            .seq_no       = write_seq_,
            .event        = ev,
            .status       = status,
            .effect_count = static_cast<u8>(num_effects),
        };
        write_seq_ += 1;
    }

    [[nodiscard]] constexpr u64 total_recorded() const noexcept { return write_seq_; }

    [[nodiscard]] constexpr usize available() const noexcept {
        return (write_seq_ < TRACE_CAPACITY) ? static_cast<usize>(write_seq_) : TRACE_CAPACITY;
    }

    [[nodiscard]] constexpr Option<TraceRecord> get_recent(usize age_from_newest) const noexcept {
        usize const avail = available();
        if (age_from_newest >= avail) {
            return Option<TraceRecord>::none();
        }
        u64 const target_seq = write_seq_ - 1ULL - age_from_newest;
        return Option<TraceRecord>::some(entries_[target_seq & (TRACE_CAPACITY - 1)]);
    }

    // Deterministically replay all buffered events into a fresh `core::KernelState`!
    [[nodiscard]] constexpr Result<u64, Error> replay_into(core::KernelState& fresh_state) const noexcept {
        usize const count = available();
        u64 const start_seq = (write_seq_ > TRACE_CAPACITY) ? (write_seq_ - TRACE_CAPACITY) : 0ULL;

        for (usize i = 0; i < count; ++i) {
            TraceRecord const& rec = entries_[(start_seq + i) & (TRACE_CAPACITY - 1)];
            auto res = core::dispatch_event(fresh_state, rec.event);
            if (rec.status == Error::None && res.is_err()) {
                return Result<u64, Error>::err(res.error());
            }
        }
        return Result<u64, Error>::ok(static_cast<u64>(count));
    }

private:
    TraceRecord entries_[TRACE_CAPACITY]{};
    u64         write_seq_{0};
};

} // namespace mucore::shell
