#pragma once
// ============================================================================
// μCore Functional Core — Dual-Horizon Scheduler + L4 MCS Context Donation
// ============================================================================
// Architecture:
//   - Tier 0 (Isochronous Hard/Firm Real-Time):
//       Earliest Deadline First (EDF) policed by Constant Bandwidth Server (CBS)
//       with ceiling fixed-point utilization (`MAX_RT_UTIL_PPM = 850,000`).
//   - Tier 1 (Async / Interactive Throughput):
//       Weighted virtual-runtime (`vruntime_ns`) fair scheduling.
//   - L4-MCS Scheduling Context Donation Over Async Conduits:
//       Solves asynchronous priority inversion! When an Urgent-RT client thread
//       submits work to a Userspace Driver / Server worker (even a Tier-1 non-RT
//       worker or throttled driver!), `donate_cbs_context()` atomically loans
//       the client's `abs_deadline` and `remaining_budget_ns` to the worker.
//       Total system CBS budget is strictly conserved (zero double-spending!),
//       and `return_cbs_context()` restores leftover budget on completion.
// ============================================================================

#include "mucore/result.hpp"
#include "mucore/types.hpp"

namespace mucore::core::sched {

inline constexpr usize MAX_THREADS             = 64;
inline constexpr u64   PPM_SCALE               = 1'000'000ULL;
inline constexpr u64   MAX_RT_UTIL_PPM         = 850'000ULL;   // 85.0% max hard-RT cap
inline constexpr u64   DEFAULT_ASYNC_SLICE_NS  = 2'000'000ULL; // 2ms tickless slice

enum class SchedClass : u8 {
    Idle            = 0,
    AsyncThroughput = 1, // Tier 1: Virtual-runtime fair / async worker threads
    IsochronousRt   = 2, // Tier 0: Hard/Firm Real-Time CBS + EDF
};

enum class ThreadState : u8 {
    Unused    = 0,
    Ready     = 1,
    Running   = 2,
    Blocked   = 3, // Waiting on cold doorbell / explicit sleep / loaned RT call
    Throttled = 4, // CBS budget exhausted; awaits `replenish_at`
};

struct RtParams {
    u64 wcet_ns{0};   // C_i: Worst-Case Execution Time budget per period
    u64 period_ns{0}; // T_i: Minimum inter-arrival / replenishment period
};

struct ThreadControlBlock {
    bool        occupied{false};
    ThreadId    id{};
    DomainId    domain{};
    SchedClass  sched_class{SchedClass::AsyncThroughput};
    ThreadState state{ThreadState::Unused};

    // Tier-0 CBS/EDF state
    RtParams    rt{};
    u64         util_ppm{0};
    u64         remaining_budget_ns{0};
    TickNs      abs_deadline{};
    TickNs      replenish_at{};
    u32         budget_overruns{0};

    // L4-MCS Scheduling Context Loan tracking (strict conservation of CBS budget!)
    ThreadId    loaned_to{};        // Non-zero while this RT thread's budget is loaned out
    ThreadId    borrowed_from{};    // Non-zero while executing on a client's CBS loan
    CpuId       borrowed_from_cpu{};
    bool        has_remote_loan{false};
    SchedClass  saved_class{SchedClass::AsyncThroughput};
    u64         saved_budget_ns{0};
    TickNs      saved_deadline{};

    // Tier-1 Async/Fair state
    u32         weight{1024};
    u64         vruntime_ns{0};

    // Accounting
    u64         total_runtime_ns{0};
    u64         context_switches{0};
};

struct SchedTable {
    ThreadControlBlock threads[MAX_THREADS]{};
    ThreadId           current_thread{};
    TickNs             last_accounted_at{};
    u64                reserved_rt_ppm{0};

    constexpr SchedTable() noexcept = default;
    SchedTable(SchedTable const&)            = delete;
    SchedTable& operator=(SchedTable const&) = delete;
    constexpr SchedTable(SchedTable&&) noexcept            = default;
    constexpr SchedTable& operator=(SchedTable&&) noexcept = default;
};

struct SchedDecision {
    ThreadId next_thread{};
    DomainId next_domain{};
    bool     requires_context_switch{false};
    bool     requires_address_space_switch{false};
    TickNs   next_timer_deadline{};
};

// ============================================================================
// PURE FUNCTIONAL CORE ADMISSION, MCS DONATION & SCHEDULING EQUATIONS
// ============================================================================

[[nodiscard]] constexpr Result<u64, Error> compute_rt_utilization_ppm(RtParams params) noexcept {
    if (params.wcet_ns == 0 || params.period_ns == 0 || params.wcet_ns > params.period_ns) {
        return Result<u64, Error>::err(Error::InvalidArgument);
    }
    u64 const numer = params.wcet_ns * PPM_SCALE + (params.period_ns - 1ULL);
    u64 const ppm   = numer / params.period_ns;
    return Result<u64, Error>::ok(ppm);
}

[[nodiscard]] constexpr Result<u64, Error> check_rt_admission(
    SchedTable const& table,
    RtParams          candidate
) noexcept {
    auto ppm_res = compute_rt_utilization_ppm(candidate);
    if (ppm_res.is_err()) {
        return Result<u64, Error>::err(ppm_res.error());
    }
    u64 const req_ppm = ppm_res.value();
    if (table.reserved_rt_ppm + req_ppm > MAX_RT_UTIL_PPM) {
        return Result<u64, Error>::err(Error::AdmissionRejected);
    }
    return Result<u64, Error>::ok(req_ppm);
}

[[nodiscard]] constexpr Option<u32> find_thread_slot(
    SchedTable const& table,
    ThreadId          tid
) noexcept {
    if (!tid) return Option<u32>::none();
    for (u32 i = 0; i < MAX_THREADS; ++i) {
        if (table.threads[i].occupied && table.threads[i].id == tid) {
            return Option<u32>::some(i);
        }
    }
    return Option<u32>::none();
}

[[nodiscard]] constexpr Result<ThreadId, Error> spawn_thread(
    SchedTable& table,
    ThreadId    desired_id,
    DomainId    domain,
    SchedClass  sclass,
    RtParams    rt_params,
    TickNs      now
) noexcept {
    if (!desired_id || !domain || find_thread_slot(table, desired_id).is_some()) {
        return Result<ThreadId, Error>::err(Error::InvalidArgument);
    }

    u64 admitted_ppm = 0;
    if (sclass == SchedClass::IsochronousRt) {
        auto adm = check_rt_admission(table, rt_params);
        if (adm.is_err()) {
            return Result<ThreadId, Error>::err(adm.error());
        }
        admitted_ppm = adm.value();
    }

    for (u32 i = 0; i < MAX_THREADS; ++i) {
        if (!table.threads[i].occupied) {
            ThreadControlBlock tcb{};
            tcb.occupied    = true;
            tcb.id          = desired_id;
            tcb.domain      = domain;
            tcb.sched_class = sclass;
            tcb.state       = ThreadState::Ready;

            if (sclass == SchedClass::IsochronousRt) {
                tcb.rt                  = rt_params;
                tcb.util_ppm            = admitted_ppm;
                tcb.remaining_budget_ns = rt_params.wcet_ns;
                tcb.abs_deadline        = TickNs{now.raw + rt_params.period_ns};
                tcb.replenish_at        = TickNs{now.raw + rt_params.period_ns};
                table.reserved_rt_ppm  += admitted_ppm;
            }

            table.threads[i] = tcb;
            return Result<ThreadId, Error>::ok(desired_id);
        }
    }
    return Result<ThreadId, Error>::err(Error::TableFull);
}

// Hold a freshly spawned Tier-0 thread back until its first replenishment boundary.
// A supervisor restarting a crashed RT thread uses this so the new incarnation cannot
// spend a second budget inside the period its predecessor already ran in; the existing
// `schedule_at` replenishment step releases it at `replenish_at` (spawn time + period).
[[nodiscard]] constexpr Result<Unit, Error> defer_budget_to_next_period(
    SchedTable& table,
    ThreadId    tid
) noexcept {
    auto slot = find_thread_slot(table, tid);
    if (slot.is_none()) {
        return Result<Unit, Error>::err(Error::NotFound);
    }
    ThreadControlBlock& tcb = table.threads[slot.value()];
    if (tcb.sched_class != SchedClass::IsochronousRt || tcb.borrowed_from) {
        return Result<Unit, Error>::err(Error::InvalidState);
    }
    tcb.remaining_budget_ns = 0;
    tcb.state               = ThreadState::Throttled;
    return Result<Unit, Error>::ok(Unit{});
}

// L4-MCS Scheduling Context Donation:
//   Atomically transfers `donor_tid`'s CBS deadline & remaining budget to `worker_tid`
//   so a Userspace Driver / Server executes Urgent-RT requests with zero priority inversion!
[[nodiscard]] constexpr Result<Unit, Error> donate_cbs_context(
    SchedTable& table,
    ThreadId    donor_tid,
    ThreadId    worker_tid
) noexcept {
    if (!donor_tid || !worker_tid || donor_tid == worker_tid) {
        return Result<Unit, Error>::err(Error::InvalidArgument);
    }

    auto d_slot = find_thread_slot(table, donor_tid);
    auto w_slot = find_thread_slot(table, worker_tid);
    if (d_slot.is_none() || w_slot.is_none()) {
        return Result<Unit, Error>::err(Error::NotFound);
    }

    ThreadControlBlock& donor  = table.threads[d_slot.value()];
    ThreadControlBlock& worker = table.threads[w_slot.value()];

    if (donor.sched_class != SchedClass::IsochronousRt || donor.remaining_budget_ns == 0) {
        return Result<Unit, Error>::err(Error::InsufficientRights);
    }
    if (donor.loaned_to || worker.borrowed_from) {
        return Result<Unit, Error>::err(Error::LoanActive);
    }

    // Snapshot worker's baseline scheduling parameters
    worker.saved_class     = worker.sched_class;
    worker.saved_budget_ns = worker.remaining_budget_ns;
    worker.saved_deadline  = worker.abs_deadline;

    // Conservation of CBS bandwidth: move remaining budget from donor -> worker!
    worker.sched_class         = SchedClass::IsochronousRt;
    worker.remaining_budget_ns = donor.remaining_budget_ns;
    worker.abs_deadline        = donor.abs_deadline;
    worker.borrowed_from       = donor.id;
    if (worker.state == ThreadState::Blocked || worker.state == ThreadState::Throttled) {
        worker.state = ThreadState::Ready;
    }

    donor.remaining_budget_ns = 0;
    donor.loaned_to           = worker.id;
    donor.state               = ThreadState::Blocked;

    return Result<Unit, Error>::ok(Unit{});
}

// L4-MCS Context Return: restores worker's baseline class & returns unused budget to donor!
[[nodiscard]] constexpr Result<ThreadId, Error> return_cbs_context(
    SchedTable& table,
    ThreadId    worker_tid
) noexcept {
    auto w_slot = find_thread_slot(table, worker_tid);
    if (w_slot.is_none()) {
        return Result<ThreadId, Error>::err(Error::NotFound);
    }

    ThreadControlBlock& worker = table.threads[w_slot.value()];
    if (!worker.borrowed_from) {
        return Result<ThreadId, Error>::err(Error::InvalidState);
    }

    ThreadId const donor_id = worker.borrowed_from;
    u64 const leftover_ns   = worker.remaining_budget_ns;

    // Restore worker's original scheduling parameters
    worker.sched_class         = worker.saved_class;
    worker.remaining_budget_ns = worker.saved_budget_ns;
    worker.abs_deadline        = worker.saved_deadline;
    worker.borrowed_from       = ThreadId{0};
    if (worker.sched_class == SchedClass::IsochronousRt && worker.remaining_budget_ns == 0) {
        worker.state = ThreadState::Throttled;
    }

    auto d_slot = find_thread_slot(table, donor_id);
    if (d_slot.is_some()) {
        ThreadControlBlock& donor = table.threads[d_slot.value()];
        donor.loaned_to            = ThreadId{0};
        donor.remaining_budget_ns += leftover_ns;
        donor.state                = (donor.remaining_budget_ns > 0)
                                       ? ThreadState::Ready
                                       : ThreadState::Throttled;
    }

    return Result<ThreadId, Error>::ok(donor_id);
}

// Remove every thread of an exited domain and settle its CPU-time claims:
//   - a dying worker running on a borrowed CBS context returns the unspent budget to its donor,
//   - a dying donor's outstanding loan is recalled so the worker drops back to its own class,
//   - admitted Tier-0 bandwidth is released for re-admission.
// A loan taken from another core cannot be refunded here: that needs a `RefundRemoteCbs`
// parcel, which only the SMP shard layer can send.
constexpr u32 reap_domain_threads(SchedTable& table, DomainId domain) noexcept {
    if (!domain) return 0;

    u32 reaped = 0;
    for (u32 i = 0; i < MAX_THREADS; ++i) {
        ThreadControlBlock& tcb = table.threads[i];
        if (!tcb.occupied || !(tcb.domain == domain)) continue;

        if (tcb.borrowed_from && !tcb.has_remote_loan) {
            (void)return_cbs_context(table, tcb.id);
        }
        if (tcb.loaned_to) {
            auto w_slot = find_thread_slot(table, tcb.loaned_to);
            if (w_slot.is_some() && table.threads[w_slot.value()].borrowed_from == tcb.id) {
                (void)return_cbs_context(table, tcb.loaned_to);
            }
        }

        table.reserved_rt_ppm -= (tcb.util_ppm <= table.reserved_rt_ppm)
                                     ? tcb.util_ppm
                                     : table.reserved_rt_ppm;
        if (table.current_thread == tcb.id) {
            table.current_thread = ThreadId{0};
        }
        tcb = ThreadControlBlock{};
        ++reaped;
    }
    return reaped;
}

// ============================================================================
// LOCK-FREE CROSS-CORE SMP PARCEL SCHEDULING PRIMITIVES
// ============================================================================

struct RemoteCbsLoan {
    ThreadId donor_tid{};
    CpuId    donor_cpu{};
    ThreadId worker_tid{};
    u64      donated_budget_ns{0};
    TickNs   donated_deadline{};
};

struct RemoteCbsRefund {
    ThreadId donor_tid{};
    CpuId    donor_cpu{};
    u64      leftover_budget_ns{0};
};

// Source Core: deducts `donor_tid`'s CBS budget locally (0 cross-core locks!)
[[nodiscard]] constexpr Result<RemoteCbsLoan, Error> extract_cbs_loan_for_remote(
    SchedTable& local_sched,
    CpuId       local_cpu,
    ThreadId    donor_tid,
    ThreadId    remote_worker_tid
) noexcept {
    auto d_slot = find_thread_slot(local_sched, donor_tid);
    if (d_slot.is_none()) {
        return Result<RemoteCbsLoan, Error>::err(Error::NotFound);
    }
    ThreadControlBlock& donor = local_sched.threads[d_slot.value()];
    if (donor.sched_class != SchedClass::IsochronousRt || donor.remaining_budget_ns == 0) {
        return Result<RemoteCbsLoan, Error>::err(Error::InsufficientRights);
    }
    if (donor.loaned_to) {
        return Result<RemoteCbsLoan, Error>::err(Error::LoanActive);
    }

    RemoteCbsLoan loan{
        .donor_tid         = donor_tid,
        .donor_cpu         = local_cpu,
        .worker_tid        = remote_worker_tid,
        .donated_budget_ns = donor.remaining_budget_ns,
        .donated_deadline  = donor.abs_deadline,
    };

    donor.remaining_budget_ns = 0;
    donor.loaned_to           = remote_worker_tid;
    donor.state               = ThreadState::Blocked;
    return Result<RemoteCbsLoan, Error>::ok(loan);
}

// Target Core: installs incoming `RemoteCbsLoan` parcel onto local `worker_tid`
[[nodiscard]] constexpr Result<Unit, Error> apply_remote_cbs_loan(
    SchedTable&          target_sched,
    RemoteCbsLoan const& loan
) noexcept {
    auto w_slot = find_thread_slot(target_sched, loan.worker_tid);
    if (w_slot.is_none()) {
        return Result<Unit, Error>::err(Error::NotFound);
    }
    ThreadControlBlock& worker = target_sched.threads[w_slot.value()];
    if (worker.borrowed_from) {
        return Result<Unit, Error>::err(Error::LoanActive);
    }

    worker.saved_class         = worker.sched_class;
    worker.saved_budget_ns     = worker.remaining_budget_ns;
    worker.saved_deadline      = worker.abs_deadline;

    worker.sched_class         = SchedClass::IsochronousRt;
    worker.remaining_budget_ns = loan.donated_budget_ns;
    worker.abs_deadline        = loan.donated_deadline;
    worker.borrowed_from       = loan.donor_tid;
    worker.borrowed_from_cpu   = loan.donor_cpu;
    worker.has_remote_loan     = true;
    if (worker.state == ThreadState::Blocked || worker.state == ThreadState::Throttled) {
        worker.state = ThreadState::Ready;
    }
    return Result<Unit, Error>::ok(Unit{});
}

// Target Core: completes remote CBS work & packages leftover nanoseconds for `RefundRemoteCbs`
[[nodiscard]] constexpr Result<RemoteCbsRefund, Error> finish_remote_cbs_loan(
    SchedTable& target_sched,
    ThreadId    worker_tid
) noexcept {
    auto w_slot = find_thread_slot(target_sched, worker_tid);
    if (w_slot.is_none()) {
        return Result<RemoteCbsRefund, Error>::err(Error::NotFound);
    }
    ThreadControlBlock& worker = target_sched.threads[w_slot.value()];
    if (!worker.has_remote_loan || !worker.borrowed_from) {
        return Result<RemoteCbsRefund, Error>::err(Error::InvalidState);
    }

    RemoteCbsRefund refund{
        .donor_tid          = worker.borrowed_from,
        .donor_cpu          = worker.borrowed_from_cpu,
        .leftover_budget_ns = worker.remaining_budget_ns,
    };

    worker.sched_class         = worker.saved_class;
    worker.remaining_budget_ns = worker.saved_budget_ns;
    worker.abs_deadline        = worker.saved_deadline;
    worker.borrowed_from       = ThreadId{0};
    worker.borrowed_from_cpu   = CpuId{0};
    worker.has_remote_loan     = false;
    if (worker.sched_class == SchedClass::IsochronousRt && worker.remaining_budget_ns == 0) {
        worker.state = ThreadState::Throttled;
    }
    return Result<RemoteCbsRefund, Error>::ok(refund);
}

// Source Core: receives `RemoteCbsRefund` parcel & wakes Hard-RT donor with exact unspent budget!
[[nodiscard]] constexpr Result<Unit, Error> receive_remote_cbs_refund(
    SchedTable&            local_sched,
    RemoteCbsRefund const& refund
) noexcept {
    auto d_slot = find_thread_slot(local_sched, refund.donor_tid);
    if (d_slot.is_none()) {
        return Result<Unit, Error>::err(Error::NotFound);
    }
    ThreadControlBlock& donor = local_sched.threads[d_slot.value()];
    donor.loaned_to            = ThreadId{0};
    donor.remaining_budget_ns += refund.leftover_budget_ns;
    donor.state                = (donor.remaining_budget_ns > 0)
                                   ? ThreadState::Ready
                                   : ThreadState::Throttled;
    return Result<Unit, Error>::ok(Unit{});
}

// Tier-1 Only Rebalancing: extracts a Ready `AsyncThroughput` TCB for cross-core migration
// (Tier-0 `IsochronousRt` threads are strictly rejected to preserve per-core 85% CBS admission!)
[[nodiscard]] constexpr Result<ThreadControlBlock, Error> extract_async_thread_for_migration(
    SchedTable& local_sched,
    ThreadId    tid
) noexcept {
    auto slot_opt = find_thread_slot(local_sched, tid);
    if (slot_opt.is_none()) {
        return Result<ThreadControlBlock, Error>::err(Error::NotFound);
    }
    ThreadControlBlock& tcb = local_sched.threads[slot_opt.value()];
    if (tcb.sched_class != SchedClass::AsyncThroughput || tcb.state != ThreadState::Ready) {
        return Result<ThreadControlBlock, Error>::err(Error::InvalidState);
    }
    ThreadControlBlock snapshot = tcb;
    tcb = ThreadControlBlock{};
    return Result<ThreadControlBlock, Error>::ok(snapshot);
}

// Charge Ring-0 Kineticlet / IRQ execution time directly to owning RT thread's CBS budget
constexpr void charge_external_wcet(
    SchedTable& table,
    ThreadId    owner_tid,
    u64         cost_ns
) noexcept {
    auto slot_opt = find_thread_slot(table, owner_tid);
    if (slot_opt.is_none()) return;

    ThreadControlBlock& tcb = table.threads[slot_opt.value()];
    tcb.total_runtime_ns += cost_ns;

    if (tcb.sched_class == SchedClass::IsochronousRt) {
        if (cost_ns >= tcb.remaining_budget_ns) {
            tcb.remaining_budget_ns = 0;
            tcb.budget_overruns += 1;
            if (tcb.state == ThreadState::Ready || tcb.state == ThreadState::Running) {
                tcb.state = ThreadState::Throttled;
            }
        } else {
            tcb.remaining_budget_ns -= cost_ns;
        }
    } else {
        tcb.vruntime_ns += cost_ns;
    }
}

[[nodiscard]] constexpr SchedDecision schedule_at(
    SchedTable& table,
    TickNs      now
) noexcept {
    u64 const elapsed = (now.raw > table.last_accounted_at.raw)
                            ? (now.raw - table.last_accounted_at.raw)
                            : 0ULL;
    table.last_accounted_at = now;

    DomainId prev_domain{};
    auto cur_slot_opt = find_thread_slot(table, table.current_thread);
    if (cur_slot_opt.is_some()) {
        ThreadControlBlock& cur = table.threads[cur_slot_opt.value()];
        prev_domain = cur.domain;

        if (cur.state == ThreadState::Running && elapsed > 0) {
            cur.total_runtime_ns += elapsed;

            if (cur.sched_class == SchedClass::IsochronousRt) {
                if (elapsed >= cur.remaining_budget_ns) {
                    cur.remaining_budget_ns = 0;
                    cur.budget_overruns += 1;
                    cur.state = ThreadState::Throttled;
                } else {
                    cur.remaining_budget_ns -= elapsed;
                    cur.state = ThreadState::Ready;
                }
            } else if (cur.sched_class == SchedClass::AsyncThroughput) {
                u64 const scaled = (elapsed * 1024ULL) / (cur.weight ? cur.weight : 1024ULL);
                cur.vruntime_ns += scaled;
                cur.state = ThreadState::Ready;
            } else {
                cur.state = ThreadState::Ready;
            }
        } else if (cur.state == ThreadState::Running) {
            cur.state = ThreadState::Ready;
        }
    }

    // Step 1: Replenish native Isochronous RT tasks whose CBS period boundary has arrived
    TickNs earliest_replenish{0};
    for (u32 i = 0; i < MAX_THREADS; ++i) {
        ThreadControlBlock& tcb = table.threads[i];
        if (!tcb.occupied) continue;
        // Borrowed contexts belong to the donor's period, not `tcb.rt.period_ns`!
        if (tcb.borrowed_from || tcb.rt.period_ns == 0) continue;
        if (tcb.sched_class != SchedClass::IsochronousRt) continue;

        if (now >= tcb.replenish_at) {
            u64 const periods = 1ULL + ((now.raw - tcb.replenish_at.raw) / tcb.rt.period_ns);
            tcb.replenish_at = TickNs{tcb.replenish_at.raw + periods * tcb.rt.period_ns};
            tcb.abs_deadline = tcb.replenish_at;
            if (!tcb.loaned_to) {
                tcb.remaining_budget_ns = tcb.rt.wcet_ns;
                if (tcb.state == ThreadState::Throttled) {
                    tcb.state = ThreadState::Ready;
                }
            }
        }

        if (tcb.state == ThreadState::Throttled) {
            if (earliest_replenish.raw == 0 || tcb.replenish_at < earliest_replenish) {
                earliest_replenish = tcb.replenish_at;
            }
        }
    }

    // Step 2: Tier-0 Selection — Pick Ready IsochronousRt thread with Earliest Deadline (EDF)
    Option<u32> chosen_idx = Option<u32>::none();
    for (u32 i = 0; i < MAX_THREADS; ++i) {
        ThreadControlBlock const& tcb = table.threads[i];
        if (!tcb.occupied || tcb.state != ThreadState::Ready) continue;
        if (tcb.sched_class != SchedClass::IsochronousRt || tcb.remaining_budget_ns == 0) continue;

        if (chosen_idx.is_none() ||
            tcb.abs_deadline < table.threads[chosen_idx.value()].abs_deadline) {
            chosen_idx = Option<u32>::some(i);
        }
    }

    // Step 3: Tier-1 Fallback — Pick Ready AsyncThroughput thread with minimal `vruntime_ns`
    if (chosen_idx.is_none()) {
        for (u32 i = 0; i < MAX_THREADS; ++i) {
            ThreadControlBlock const& tcb = table.threads[i];
            if (!tcb.occupied || tcb.state != ThreadState::Ready) continue;
            if (tcb.sched_class != SchedClass::AsyncThroughput) continue;

            if (chosen_idx.is_none() ||
                tcb.vruntime_ns < table.threads[chosen_idx.value()].vruntime_ns) {
                chosen_idx = Option<u32>::some(i);
            }
        }
    }

    SchedDecision decision{};
    if (chosen_idx.is_none()) {
        table.current_thread             = ThreadId{0};
        decision.next_thread             = ThreadId{0};
        decision.next_domain             = DomainId{0};
        decision.requires_context_switch = (prev_domain.raw != 0);
        decision.next_timer_deadline     = earliest_replenish;
        return decision;
    }

    ThreadControlBlock& winner = table.threads[chosen_idx.value()];
    winner.state = ThreadState::Running;

    bool const switched_thread = !(winner.id == table.current_thread);
    if (switched_thread) {
        winner.context_switches += 1;
    }
    table.current_thread = winner.id;

    TickNs slice_end{};
    if (winner.sched_class == SchedClass::IsochronousRt) {
        slice_end = TickNs{now.raw + winner.remaining_budget_ns};
    } else {
        slice_end = TickNs{now.raw + DEFAULT_ASYNC_SLICE_NS};
    }
    if (earliest_replenish.raw != 0 && earliest_replenish < slice_end) {
        slice_end = earliest_replenish;
    }

    decision.next_thread                   = winner.id;
    decision.next_domain                   = winner.domain;
    decision.requires_context_switch       = switched_thread;
    decision.requires_address_space_switch = switched_thread && !(winner.domain == prev_domain);
    decision.next_timer_deadline           = slice_end;
    return decision;
}

} // namespace mucore::core::sched
