#pragma once
// ============================================================================
// μCore Functional Core & SMP Fabric — Hybrid Per-Core Shards & IPI Parcels
// ============================================================================
// Implements the Locked-In Phase 2 SMP Specification:
//   1. Share-Nothing Hot Execution Shards (`CpuShard`):
//      Each CPU core owns an isolated, cache-line-aligned `SchedTable`
//      (Partitioned CBS/EDF + VRuntime), 64-frame `LocalFrameMagazine` (with
//      8-frame Hard-RT reserve), and private `ShardTraceRing` flight recorder.
//   2. Wait-Free Cross-Core Parcel Matrix (`SmpMailMatrix`):
//      N x N `SharedSpscRing<CrossCoreParcel, 16>` mailboxes paired with a
//      per-core 64-bit atomic `incoming_sender_bitmap` scanned in O(1) via
//      `ctz64` — ZERO spinlocks on cross-core wakeups or L4-MCS CBS loans!
//   3. Active-Core Bitmask + Targeted `PKRU` Coherence:
//      Tracks `domain_active_cpus[domain]`. Sealing a `GrantArena` when 1 core
//      runs the domain executes local `WRPKRU` with 0 IPIs; when >1 cores run
//      sibling threads, sends `SyncPkruSeal` ONLY to those sibling cores!
//   4. Per-Core Deterministic Time-Travel Replay:
//      Cross-core parcels are recorded as `ShardEventKind::IncomingParcel` in
//      each core's private `ShardTraceRing`, allowing bit-exact single-core
//      replay even after chaotic multi-threaded SMP execution!
// ============================================================================

#include "mucore/array_vec.hpp"
#include "mucore/core/capability.hpp"
#include "mucore/core/memory.hpp"
#include "mucore/core/namespace_p9.hpp"
#include "mucore/core/scheduler.hpp"
#include "mucore/shell/shared_conduit.hpp"

namespace mucore::core::smp {

inline constexpr usize MAX_TRACKED_DOMAINS = 64;
inline constexpr u32   PARCEL_RING_CAP     = 16; // Power of two per (src_cpu, dst_cpu) pair
inline constexpr usize SHARD_TRACE_CAP     = 128;

enum class ParcelKind : u8 {
    None               = 0,
    WakeRemoteThread   = 1,
    DonateRemoteCbs    = 2, // Cross-core L4-MCS CBS deadline & budget transfer
    RefundRemoteCbs    = 3, // Returns unspent nanoseconds to donor's home core
    MigrateAsyncThread = 4, // Tier-1 `AsyncThroughput` load-balancing handoff
    SyncPkruSeal       = 5, // Targeted cross-core `WRPKRU` write-seal shootdown
};

struct CrossCoreParcel {
    ParcelKind           kind{ParcelKind::None};
    CpuId                src_cpu{};
    CpuId                dst_cpu{};
    DomainId             target_domain{};
    ThreadId             target_thread{};
    PkeyId               mpk_key{};
    u32                  async_weight{1024};
    u64                  async_vruntime{0};
    sched::RemoteCbsLoan cbs_loan{};
    sched::RemoteCbsRefund cbs_refund{};
};

enum class ShardEventKind : u8 {
    LocalTimer          = 0,
    LocalCbsRemoteCall  = 1, // Local RT donor initiates cross-core CBS loan
    LocalWorkerComplete = 2, // Local worker finishes borrowed remote CBS work
    IncomingParcel      = 3, // Parcel dequeued from SPSC cross-core mailbox!
};

struct ShardEvent {
    ShardEventKind  kind{ShardEventKind::LocalTimer};
    TickNs          timestamp{};
    ThreadId        local_thread{};
    ThreadId        remote_worker{};
    CpuId           remote_cpu{};
    CrossCoreParcel parcel{};
};

struct ShardTelemetry {
    u64 local_events{0};
    u64 parcels_sent{0};
    u64 parcels_received{0};
    u64 local_zero_ipi_seals{0};
    u64 targeted_pkru_ipis_sent{0};
    u64 pkru_seals_applied{0};
    u64 remote_cbs_loans_sent{0};
    u64 remote_cbs_refunds_rcvd{0};
};

// Per-Core Deterministic Flight Recorder (records local + incoming parcel events!)
class ShardTraceRing {
public:
    constexpr ShardTraceRing() noexcept = default;
    ShardTraceRing(ShardTraceRing const&)            = delete;
    ShardTraceRing& operator=(ShardTraceRing const&) = delete;

    constexpr void record(ShardEvent const& ev) noexcept {
        entries_[write_seq_ & (SHARD_TRACE_CAP - 1)] = ev;
        write_seq_ += 1;
    }

    [[nodiscard]] constexpr usize count() const noexcept {
        return (write_seq_ < SHARD_TRACE_CAP) ? static_cast<usize>(write_seq_) : SHARD_TRACE_CAP;
    }

    [[nodiscard]] constexpr ShardEvent const& at(usize idx) const noexcept {
        u64 const start = (write_seq_ > SHARD_TRACE_CAP) ? (write_seq_ - SHARD_TRACE_CAP) : 0ULL;
        return entries_[(start + idx) & (SHARD_TRACE_CAP - 1)];
    }

private:
    ShardEvent entries_[SHARD_TRACE_CAP]{};
    u64        write_seq_{0};
};

// Cache-Line Isolated Per-CPU Execution Shard (Zero Cross-Core Spinlocks!)
struct alignas(CACHE_LINE_BYTES) CpuShard {
    CpuId                  cpu_id{};
    bool                   online{false};
    DomainId               active_domain{};
    sched::SchedTable      sched{};
    mm::LocalFrameMagazine frame_mag{};
    ShardTraceRing         trace{};
    ShardTelemetry         telemetry{};

    constexpr CpuShard() noexcept = default;
    CpuShard(CpuShard const&)            = delete;
    CpuShard& operator=(CpuShard const&) = delete;
};

// Fair FIFO Ticket Spinlock — used EXCLUSIVELY on cold shared-pool / cap-mint paths!
class alignas(CACHE_LINE_BYTES) ColdTicketLock {
public:
    constexpr ColdTicketLock() noexcept = default;
    ColdTicketLock(ColdTicketLock const&)            = delete;
    ColdTicketLock& operator=(ColdTicketLock const&) = delete;

    void lock() noexcept {
        u32 const my_ticket = __atomic_fetch_add(&next_ticket_, 1u, __ATOMIC_RELAXED);
        while (__atomic_load_n(&now_serving_, __ATOMIC_ACQUIRE) != my_ticket) {
            #if defined(__x86_64__)
            asm volatile("pause" : : : "memory");
            #endif
        }
    }

    void unlock() noexcept {
        u32 const next = __atomic_load_n(&now_serving_, __ATOMIC_RELAXED) + 1u;
        __atomic_store_n(&now_serving_, next, __ATOMIC_RELEASE);
    }

private:
    u32 next_ticket_{0};
    u32 now_serving_{0};
};

struct alignas(CACHE_LINE_BYTES) AtomicSenderBitmap {
    u64 mask{0};
};

// Complete Multi-Core Hybrid Node State
struct SmpNodeState {
    CpuShard                                                  shards[MAX_SMP_CPUS]{};
    shell::SharedSpscRing<CrossCoreParcel, PARCEL_RING_CAP>   mailboxes[MAX_SMP_CPUS][MAX_SMP_CPUS]{};
    AtomicSenderBitmap                                        pending_senders[MAX_SMP_CPUS]{};
    u64                                                       domain_active_cpus[MAX_TRACKED_DOMAINS]{};

    // Read-lockless shared authority + cold-locked backing physical allocator
    cap::CapTable                                             shared_caps{};
    ns::NamespaceTable                                        shared_namespaces{};
    mm::MemoryTable                                           shared_mem{};
    ColdTicketLock                                            cold_lock{};

    constexpr SmpNodeState() noexcept {
        for (u16 c = 0; c < MAX_SMP_CPUS; ++c) {
            shards[c].cpu_id = CpuId{c};
        }
    }
    SmpNodeState(SmpNodeState const&)            = delete;
    SmpNodeState& operator=(SmpNodeState const&) = delete;
};

// ============================================================================
// PURE PER-SHARD STATE MACHINE TRANSITION (Used both Live & in Trace Replay!)
// ============================================================================

struct ShardStepOutput {
    sched::SchedDecision sched_dec{};
    Option<CrossCoreParcel> outbound_parcel{};
    Option<PkeyId>          local_pkru_seal{};
};

[[nodiscard]] constexpr Result<ShardStepOutput, Error> step_cpu_shard(
    CpuShard&         shard,
    ShardEvent const& ev
) noexcept {
    shard.telemetry.local_events += 1;
    ShardStepOutput out{};

    switch (ev.kind) {
        case ShardEventKind::LocalTimer: {
            out.sched_dec = sched::schedule_at(shard.sched, ev.timestamp);
            return Result<ShardStepOutput, Error>::ok(out);
        }

        case ShardEventKind::LocalCbsRemoteCall: {
            auto loan_res = sched::extract_cbs_loan_for_remote(
                shard.sched, shard.cpu_id, ev.local_thread, ev.remote_worker
            );
            if (loan_res.is_err()) {
                return Result<ShardStepOutput, Error>::err(loan_res.error());
            }
            shard.telemetry.remote_cbs_loans_sent += 1;
            out.outbound_parcel = Option<CrossCoreParcel>::some(CrossCoreParcel{
                .kind     = ParcelKind::DonateRemoteCbs,
                .src_cpu  = shard.cpu_id,
                .dst_cpu  = ev.remote_cpu,
                .cbs_loan = loan_res.value(),
            });
            out.sched_dec = sched::schedule_at(shard.sched, ev.timestamp);
            return Result<ShardStepOutput, Error>::ok(out);
        }

        case ShardEventKind::LocalWorkerComplete: {
            // Account elapsed worker runtime first so exact remaining budget is computed!
            (void)sched::schedule_at(shard.sched, ev.timestamp);
            auto ref_res = sched::finish_remote_cbs_loan(shard.sched, ev.local_thread);
            if (ref_res.is_err()) {
                return Result<ShardStepOutput, Error>::err(ref_res.error());
            }
            sched::RemoteCbsRefund const refund = ref_res.value();
            out.outbound_parcel = Option<CrossCoreParcel>::some(CrossCoreParcel{
                .kind       = ParcelKind::RefundRemoteCbs,
                .src_cpu    = shard.cpu_id,
                .dst_cpu    = refund.donor_cpu,
                .cbs_refund = refund,
            });
            out.sched_dec = sched::schedule_at(shard.sched, ev.timestamp);
            return Result<ShardStepOutput, Error>::ok(out);
        }

        case ShardEventKind::IncomingParcel: {
            shard.telemetry.parcels_received += 1;
            CrossCoreParcel const& p = ev.parcel;
            switch (p.kind) {
                case ParcelKind::None:
                    break;
                case ParcelKind::WakeRemoteThread: {
                    auto slot = sched::find_thread_slot(shard.sched, p.target_thread);
                    if (slot.is_some() &&
                        shard.sched.threads[slot.value()].state == sched::ThreadState::Blocked) {
                        shard.sched.threads[slot.value()].state = sched::ThreadState::Ready;
                    }
                    out.sched_dec = sched::schedule_at(shard.sched, ev.timestamp);
                    break;
                }
                case ParcelKind::DonateRemoteCbs: {
                    auto r = sched::apply_remote_cbs_loan(shard.sched, p.cbs_loan);
                    if (r.is_err()) return Result<ShardStepOutput, Error>::err(r.error());
                    out.sched_dec = sched::schedule_at(shard.sched, ev.timestamp);
                    break;
                }
                case ParcelKind::RefundRemoteCbs: {
                    auto r = sched::receive_remote_cbs_refund(shard.sched, p.cbs_refund);
                    if (r.is_err()) return Result<ShardStepOutput, Error>::err(r.error());
                    shard.telemetry.remote_cbs_refunds_rcvd += 1;
                    out.sched_dec = sched::schedule_at(shard.sched, ev.timestamp);
                    break;
                }
                case ParcelKind::MigrateAsyncThread: {
                    auto r = sched::spawn_thread(
                        shard.sched, p.target_thread, p.target_domain,
                        sched::SchedClass::AsyncThroughput, sched::RtParams{}, ev.timestamp
                    );
                    if (r.is_ok()) {
                        u32 const idx = sched::find_thread_slot(shard.sched, p.target_thread).value();
                        shard.sched.threads[idx].weight      = p.async_weight;
                        shard.sched.threads[idx].vruntime_ns = p.async_vruntime;
                    }
                    out.sched_dec = sched::schedule_at(shard.sched, ev.timestamp);
                    break;
                }
                case ParcelKind::SyncPkruSeal: {
                    shard.telemetry.pkru_seals_applied += 1;
                    out.local_pkru_seal = Option<PkeyId>::some(p.mpk_key);
                    break;
                }
            }
            return Result<ShardStepOutput, Error>::ok(out);
        }
    }

    return Result<ShardStepOutput, Error>::err(Error::InvalidArgument);
}

// Replay a single CPU shard's `ShardTraceRing` into a fresh `CpuShard` in complete isolation!
[[nodiscard]] constexpr Result<usize, Error> replay_shard_trace(
    ShardTraceRing const& recorded_trace,
    CpuShard&             fresh_shard
) noexcept {
    usize const n = recorded_trace.count();
    for (usize i = 0; i < n; ++i) {
        auto res = step_cpu_shard(fresh_shard, recorded_trace.at(i));
        if (res.is_err()) {
            return Result<usize, Error>::err(res.error());
        }
    }
    return Result<usize, Error>::ok(n);
}

// ============================================================================
// WAIT-FREE SMP MAILBOX FABRIC & ACTIVE-DOMAIN `PKRU` COHERENCE
// ============================================================================

inline void track_domain_enter_cpu(SmpNodeState& node, DomainId dom, CpuId cpu) noexcept {
    if (dom.raw < MAX_TRACKED_DOMAINS && cpu.raw < MAX_SMP_CPUS) {
        (void)__atomic_fetch_or(&node.domain_active_cpus[dom.raw], (1ULL << cpu.raw), __ATOMIC_ACQ_REL);
        node.shards[cpu.raw].active_domain = dom;
    }
}

inline void track_domain_leave_cpu(SmpNodeState& node, DomainId dom, CpuId cpu) noexcept {
    if (dom.raw < MAX_TRACKED_DOMAINS && cpu.raw < MAX_SMP_CPUS) {
        (void)__atomic_fetch_and(&node.domain_active_cpus[dom.raw], ~(1ULL << cpu.raw), __ATOMIC_ACQ_REL);
    }
}

// Enqueue a wait-free CrossCoreParcel `src -> dst` & set `dst`'s O(1) sender readiness bit!
[[nodiscard]] inline Result<Unit, Error> send_cross_core_parcel(
    SmpNodeState&          node,
    CrossCoreParcel const& parcel
) noexcept {
    if (parcel.src_cpu.raw >= MAX_SMP_CPUS || parcel.dst_cpu.raw >= MAX_SMP_CPUS) {
        return Result<Unit, Error>::err(Error::InvalidArgument);
    }
    auto push_res = node.mailboxes[parcel.src_cpu.raw][parcel.dst_cpu.raw].try_push(parcel);
    if (push_res.is_err()) {
        return push_res;
    }
    (void)__atomic_fetch_or(
        &node.pending_senders[parcel.dst_cpu.raw].mask,
        (1ULL << parcel.src_cpu.raw),
        __ATOMIC_RELEASE
    );
    node.shards[parcel.src_cpu.raw].telemetry.parcels_sent += 1;
    return Result<Unit, Error>::ok(Unit{});
}

// Drain all incoming parcels on `local_cpu` in O(active_senders) using `ctz64`!
inline usize drain_incoming_parcels(
    SmpNodeState& node,
    CpuId         local_cpu,
    TickNs        now,
    u16*          out_pkru_keys_mask = nullptr
) noexcept {
    if (local_cpu.raw >= MAX_SMP_CPUS) return 0;
    CpuShard& shard = node.shards[local_cpu.raw];
    usize processed = 0;

    u64 ready_mask = __atomic_exchange_n(
        &node.pending_senders[local_cpu.raw].mask, 0ULL, __ATOMIC_ACQUIRE
    );

    while (ready_mask != 0ULL) {
        u32 const src = ctz64(ready_mask);
        ready_mask &= ~(1ULL << src);

        if (src < MAX_SMP_CPUS) {
            while (true) {
                auto p_opt = node.mailboxes[src][local_cpu.raw].try_pop();
                if (p_opt.is_none()) break;

                ShardEvent const ev{
                    .kind      = ShardEventKind::IncomingParcel,
                    .timestamp = now,
                    .parcel    = p_opt.value(),
                };
                shard.trace.record(ev);
                auto step_res = step_cpu_shard(shard, ev);
                if (step_res.is_ok() && step_res.value().local_pkru_seal.is_some() &&
                    out_pkru_keys_mask != nullptr) {
                    u8 const k = step_res.value().local_pkru_seal.value().raw & 0xFu;
                    *out_pkru_keys_mask |= static_cast<u16>(1u << k);
                }
                ++processed;
            }
        }
    }
    return processed;
}

// Execute a local `ShardEvent` on `local_cpu`, record in local `ShardTraceRing`,
// and route any resulting `CrossCoreParcel` into the wait-free SPSC mailbox!
[[nodiscard]] inline Result<Option<CpuId>, Error> execute_on_cpu_shard(
    SmpNodeState&     node,
    CpuId             local_cpu,
    ShardEvent const& ev
) noexcept {
    if (local_cpu.raw >= MAX_SMP_CPUS) {
        return Result<Option<CpuId>, Error>::err(Error::InvalidArgument);
    }
    CpuShard& shard = node.shards[local_cpu.raw];
    shard.trace.record(ev);

    auto res = step_cpu_shard(shard, ev);
    if (res.is_err()) {
        return Result<Option<CpuId>, Error>::err(res.error());
    }

    ShardStepOutput const& out = res.value();
    if (out.outbound_parcel.is_some()) {
        CrossCoreParcel const& p = out.outbound_parcel.value();
        auto send_res = send_cross_core_parcel(node, p);
        if (send_res.is_err()) {
            return Result<Option<CpuId>, Error>::err(send_res.error());
        }
        return Result<Option<CpuId>, Error>::ok(Option<CpuId>::some(p.dst_cpu));
    }
    return Result<Option<CpuId>, Error>::ok(Option<CpuId>::none());
}

// Active-Core Bitmask + Targeted `PKRU` Coherence:
//   - Always seals local `PKRU`.
//   - If `popcount64(active_mask) == 1` (single-core domain): 0 IPIs sent!
//   - If `> 1` cores run sibling threads of `domain`: sends `SyncPkruSeal` ONLY to those cores!
[[nodiscard]] inline u32 seal_domain_pkru_coherent(
    SmpNodeState& node,
    CpuId         local_cpu,
    DomainId      domain,
    PkeyId        pkey,
    u64*          out_ipi_cpu_mask = nullptr
) noexcept {
    if (local_cpu.raw >= MAX_SMP_CPUS || domain.raw >= MAX_TRACKED_DOMAINS) {
        return 0;
    }

    CpuShard& shard = node.shards[local_cpu.raw];
    shard.telemetry.pkru_seals_applied += 1;

    u64 const active_mask  = __atomic_load_n(&node.domain_active_cpus[domain.raw], __ATOMIC_ACQUIRE);
    u64       sibling_mask = active_mask & ~(1ULL << local_cpu.raw);

    if (sibling_mask == 0ULL) {
        shard.telemetry.local_zero_ipi_seals += 1;
        return 0; // Fast path: 0 cross-core IPIs needed!
    }

    u32 ipis_sent = 0;
    while (sibling_mask != 0ULL) {
        u32 const dst = ctz64(sibling_mask);
        sibling_mask &= ~(1ULL << dst);
        if (dst < MAX_SMP_CPUS) {
            CrossCoreParcel const p{
                .kind          = ParcelKind::SyncPkruSeal,
                .src_cpu       = local_cpu,
                .dst_cpu       = CpuId{static_cast<u16>(dst)},
                .target_domain = domain,
                .mpk_key       = pkey,
            };
            if (send_cross_core_parcel(node, p).is_ok()) {
                shard.telemetry.targeted_pkru_ipis_sent += 1;
                if (out_ipi_cpu_mask != nullptr) {
                    *out_ipi_cpu_mask |= (1ULL << dst);
                }
                ++ipis_sent;
            }
        }
    }
    return ipis_sent;
}

// Allocate a 4 KiB frame on `local_cpu`: 0-lock fast pop from `frame_mag`,
// refilling a 32-frame batch under `cold_lock` ONLY when magazine hits watermark!
[[nodiscard]] inline Result<PhysAddr, Error> alloc_shard_frame(
    SmpNodeState& node,
    CpuId         local_cpu,
    bool          is_hard_rt
) noexcept {
    if (local_cpu.raw >= MAX_SMP_CPUS) {
        return Result<PhysAddr, Error>::err(Error::InvalidArgument);
    }
    CpuShard& shard = node.shards[local_cpu.raw];

    // Fast path: 0 locks, 0 atomics!
    auto fast = mm::alloc_from_magazine(shard.frame_mag, is_hard_rt);
    if (fast.is_ok()) {
        return fast;
    }

    // Slow cold path: refill 32 frames from shared backing pool under fair ticket lock
    node.cold_lock.lock();
    usize const refilled = mm::refill_magazine_batch(shard.frame_mag, node.shared_mem.pool);
    node.cold_lock.unlock();

    if (refilled == 0 && shard.frame_mag.count == 0) {
        return Result<PhysAddr, Error>::err(Error::OutOfMemory);
    }
    return mm::alloc_from_magazine(shard.frame_mag, is_hard_rt);
}

} // namespace mucore::core::smp
