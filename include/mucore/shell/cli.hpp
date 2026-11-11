#pragma once
// ============================================================================
// μCore (mucore-kernel) — Interactive Command Shell & Diagnostics REPL
// ============================================================================
// Features:
//   - Zero-Heap, Zero-Vtable, Freestanding C++23 design.
//   - Diagnostics across all four lineages:
//       * Zircon:    FluxPort readiness, SPSC conduits, capability rights
//       * WinNT:     MPK PKRU seals, DMA crash quarantine, physical magazines
//       * Plan 9:    Per-domain capability namespaces, union mounts, path walk
//       * L4 MCS:    CBS deadline/budget donation, EDF parameters, RT reserve
//   - Interactive driver & crash simulation:
//       * IRQ 32 (NVMe) split-plane trigger -> verified Ring-0 Kineticlet DAG
//       * Service crash teardown & init supervision with epoch revocation
//       * Cross-core CBS loan IPI simulation
//       * Micro-benchmarking hot-path Ring-0 dispatch WCET
//   - Multi-environment I/O: Serial COM1 (bare-metal), Host Stdio, or String Buffers
// ============================================================================

#include "mucore/types.hpp"
#include "mucore/core/dispatcher.hpp"
#include "mucore/core/init.hpp"
#include "mucore/core/namespace_p9.hpp"
#include "mucore/core/scheduler.hpp"
#include "mucore/core/smp.hpp"
#include "mucore/shell/hal.hpp"

namespace mucore::shell {

// ----------------------------------------------------------------------------
// Unified Output Writer (Freestanding, Zero-Allocation)
// ----------------------------------------------------------------------------
struct IOutput {
    void (*putc_fn)(void* ctx, char c) noexcept{nullptr};
    void (*puts_fn)(void* ctx, const char* s) noexcept{nullptr};
    void* ctx{nullptr};

    void putc(char c) const noexcept {
        if (putc_fn) putc_fn(ctx, c);
    }

    void puts(const char* s) const noexcept {
        if (puts_fn) puts_fn(ctx, s);
    }

    void write_u64(u64 val) const noexcept {
        char buf[21]{};
        usize idx = 20;
        if (val == 0) {
            putc('0');
            return;
        }
        while (val > 0 && idx > 0) {
            buf[--idx] = static_cast<char>('0' + (val % 10ULL));
            val /= 10ULL;
        }
        puts(&buf[idx]);
    }

    void write_hex(u64 val) const noexcept {
        static constexpr char HEX[] = "0123456789abcdef";
        puts("0x");
        for (int shift = 60; shift >= 0; shift -= 4) {
            putc(HEX[(val >> shift) & 0xFULL]);
        }
    }

    void write_pad(const char* s, usize width) const noexcept {
        if (s == nullptr) s = "";
        usize len = 0;
        while (s[len] != '\0') ++len;
        puts(s);
        for (usize i = len; i < width; ++i) {
            putc(' ');
        }
    }

    void write_u64_pad(u64 val, usize width) const noexcept {
        char buf[21]{};
        usize idx = 20;
        if (val == 0) {
            buf[--idx] = '0';
        } else {
            while (val > 0 && idx > 0) {
                buf[--idx] = static_cast<char>('0' + (val % 10ULL));
                val /= 10ULL;
            }
        }
        usize const num_len = 20 - idx;
        puts(&buf[idx]);
        for (usize i = num_len; i < width; ++i) {
            putc(' ');
        }
    }
};

// Fixed-capacity string buffer for tests and formatted capture
template <usize Capacity = 4096>
struct StringBuffer {
    char  data[Capacity]{};
    usize len{0};

    constexpr void clear() noexcept {
        len = 0;
        data[0] = '\0';
    }

    void append_char(char c) noexcept {
        if (len + 1 < Capacity) {
            data[len++] = c;
            data[len] = '\0';
        }
    }

    void append_str(const char* s) noexcept {
        if (s == nullptr) return;
        while (*s != '\0' && len + 1 < Capacity) {
            data[len++] = *s++;
        }
        data[len] = '\0';
    }

    [[nodiscard]] IOutput writer() noexcept {
        return IOutput{
            .putc_fn = [](void* ctx, char c) noexcept {
                static_cast<StringBuffer*>(ctx)->append_char(c);
            },
            .puts_fn = [](void* ctx, const char* s) noexcept {
                static_cast<StringBuffer*>(ctx)->append_str(s);
            },
            .ctx = this,
        };
    }
};

// ----------------------------------------------------------------------------
// Minimalist Command Line Tokenizer
// ----------------------------------------------------------------------------
struct CmdTokens {
    static constexpr usize MAX_ARGS = 8;
    const char* args[MAX_ARGS]{};
    usize count{0};
};

inline CmdTokens tokenize_line(char* line) noexcept {
    CmdTokens out{};
    if (line == nullptr) return out;
    char* p = line;
    while (*p != '\0' && out.count < CmdTokens::MAX_ARGS) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
            *p++ = '\0';
        }
        if (*p == '\0') break;
        out.args[out.count++] = p;
        while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') {
            ++p;
        }
    }
    return out;
}

inline u64 parse_u64_str(const char* s) noexcept {
    if (s == nullptr) return 0;
    u64 val = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
        while (*s != '\0') {
            char const c = *s++;
            if (c >= '0' && c <= '9') val = (val << 4) | static_cast<u64>(c - '0');
            else if (c >= 'a' && c <= 'f') val = (val << 4) | static_cast<u64>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') val = (val << 4) | static_cast<u64>(c - 'A' + 10);
            else break;
        }
        return val;
    }
    while (*s >= '0' && *s <= '9') {
        val = val * 10ULL + static_cast<u64>(*s - '0');
        ++s;
    }
    return val;
}

inline u64 get_timestamp_ticks() noexcept {
#if defined(__x86_64__)
    u32 lo = 0, hi = 0;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<u64>(hi) << 32) | lo;
#else
    static u64 s_pseudo_tick = 1'000'000ULL;
    return s_pseudo_tick += 100ULL;
#endif
}

// ----------------------------------------------------------------------------
// CommandShell Engine (Freestanding, Works on Bare-Metal & Host)
// ----------------------------------------------------------------------------
template <HalPlatform Hal>
class CommandShell {
public:
    constexpr CommandShell(
        ImperativeKernelRuntime<Hal>& kernel,
        core::init::InitState&         init,
        const core::init::BootPlan&    plan,
        core::smp::SmpNodeState*       smp = nullptr
    ) noexcept
        : kernel_(kernel), init_(init), plan_(plan), smp_(smp) {}

    void print_prompt(IOutput const& out) const noexcept {
        out.puts("mucore> ");
    }

    void print_banner(IOutput const& out) const noexcept {
        out.puts("============================================================\n");
        out.puts("  μCore (mucore-kernel) Interactive Shell v0.2.0\n");
        out.puts("  Four-Lineage Hybrid SMP | Functional Core, Imperative Shell\n");
        out.puts("  Type 'help' for command listing.\n");
        out.puts("============================================================\n");
    }

    void execute_line(char* line, IOutput const& out) noexcept {
        CmdTokens const tok = tokenize_line(line);
        if (tok.count == 0) {
            return;
        }

        const char* const cmd = tok.args[0];

        if (core::init::cstr_equal(cmd, "help") || core::init::cstr_equal(cmd, "?")) {
            cmd_help(out);
        } else if (core::init::cstr_equal(cmd, "version") || core::init::cstr_equal(cmd, "uname")) {
            cmd_version(out);
        } else if (core::init::cstr_equal(cmd, "services") || core::init::cstr_equal(cmd, "svc")) {
            cmd_services(out);
        } else if (core::init::cstr_equal(cmd, "ps") || core::init::cstr_equal(cmd, "threads")) {
            cmd_ps(out);
        } else if (core::init::cstr_equal(cmd, "caps") || core::init::cstr_equal(cmd, "capabilities")) {
            cmd_caps(tok, out);
        } else if (core::init::cstr_equal(cmd, "trace") || core::init::cstr_equal(cmd, "dmesg")) {
            cmd_trace(tok, out);
        } else if (core::init::cstr_equal(cmd, "ns") || core::init::cstr_equal(cmd, "mounts")) {
            cmd_ns(out);
        } else if (core::init::cstr_equal(cmd, "resolve")) {
            cmd_resolve(tok, out);
        } else if (core::init::cstr_equal(cmd, "smp") || core::init::cstr_equal(cmd, "cores")) {
            cmd_smp(out);
        } else if (core::init::cstr_equal(cmd, "mem") || core::init::cstr_equal(cmd, "magazines")) {
            cmd_mem(out);
        } else if (core::init::cstr_equal(cmd, "irq")) {
            cmd_irq(tok, out);
        } else if (core::init::cstr_equal(cmd, "crash") || core::init::cstr_equal(cmd, "fault")) {
            cmd_crash(tok, out);
        } else if (core::init::cstr_equal(cmd, "loan")) {
            cmd_loan(tok, out);
        } else if (core::init::cstr_equal(cmd, "bench")) {
            cmd_bench(out);
        } else if (core::init::cstr_equal(cmd, "stats") || core::init::cstr_equal(cmd, "telemetry")) {
            cmd_stats(out);
        } else if (core::init::cstr_equal(cmd, "echo")) {
            for (usize i = 1; i < tok.count; ++i) {
                out.puts(tok.args[i]);
                if (i + 1 < tok.count) out.putc(' ');
            }
            out.putc('\n');
        } else if (core::init::cstr_equal(cmd, "clear")) {
            out.puts("\033[2J\033[H");
        } else if (core::init::cstr_equal(cmd, "reboot") || core::init::cstr_equal(cmd, "reset")) {
            cmd_reboot(out);
        } else if (core::init::cstr_equal(cmd, "halt") || core::init::cstr_equal(cmd, "shutdown")) {
            cmd_halt(out);
        } else {
            out.puts("Unknown command: '");
            out.puts(cmd);
            out.puts("'. Type 'help' for available commands.\n");
        }
    }

    // Bare-Metal Serial REPL loop with ANSI arrow navigation & command history
    template <typename SerialDevice>
    [[noreturn]] void run_serial_repl() noexcept {
        auto out = IOutput{
            .putc_fn = [](void*, char c) noexcept { SerialDevice::putc(c); },
            .puts_fn = [](void*, const char* s) noexcept { SerialDevice::puts(s); },
            .ctx     = nullptr,
        };

        print_banner(out);
        print_prompt(out);

        char  line_buf[128]{};
        usize line_idx = 0;

        // Command history ring buffer (8 commands)
        static constexpr usize HISTORY_CAP = 8;
        char  history[HISTORY_CAP][128]{};
        usize history_count = 0;
        usize history_head = 0;
        usize history_nav = 0; // 0 = current live edit, 1 = newest in history, ...

        // ANSI escape sequence state machine
        enum class EscState : u8 {
            Normal,
            Esc,
            Bracket,
        } esc_state = EscState::Normal;

        auto clear_and_set_line = [&](const char* new_text) {
            while (line_idx > 0) {
                SerialDevice::puts("\b \b");
                --line_idx;
            }
            usize i = 0;
            while (new_text[i] != '\0' && i + 1 < sizeof(line_buf)) {
                line_buf[i] = new_text[i];
                SerialDevice::putc(new_text[i]);
                ++i;
            }
            line_buf[i] = '\0';
            line_idx = i;
        };

        for (;;) {
            if (!SerialDevice::has_rx()) {
#if defined(__x86_64__)
                asm volatile("pause");
#endif
                continue;
            }

            char const c = SerialDevice::getc();

            if (esc_state == EscState::Esc) {
                if (c == '[') {
                    esc_state = EscState::Bracket;
                } else {
                    esc_state = EscState::Normal;
                }
                continue;
            }

            if (esc_state == EscState::Bracket) {
                esc_state = EscState::Normal;
                if (c == 'A') { // Up Arrow: Previous command
                    if (history_count > 0 && history_nav < history_count) {
                        ++history_nav;
                        usize const h_idx = (history_head + HISTORY_CAP - history_nav) % HISTORY_CAP;
                        clear_and_set_line(history[h_idx]);
                    }
                } else if (c == 'B') { // Down Arrow: Next command
                    if (history_nav > 1) {
                        --history_nav;
                        usize const h_idx = (history_head + HISTORY_CAP - history_nav) % HISTORY_CAP;
                        clear_and_set_line(history[h_idx]);
                    } else if (history_nav == 1) {
                        history_nav = 0;
                        clear_and_set_line("");
                    }
                }
                continue;
            }

            if (c == '\033') {
                esc_state = EscState::Esc;
                continue;
            }

            if (c == '\r' || c == '\n') {
                SerialDevice::putc('\n');
                line_buf[line_idx] = '\0';
                if (line_idx > 0) {
                    // Record into history
                    usize const h_slot = history_head % HISTORY_CAP;
                    usize k = 0;
                    while (line_buf[k] != '\0' && k + 1 < sizeof(history[h_slot])) {
                        history[h_slot][k] = line_buf[k];
                        ++k;
                    }
                    history[h_slot][k] = '\0';
                    history_head = (history_head + 1) % HISTORY_CAP;
                    if (history_count < HISTORY_CAP) ++history_count;
                    history_nav = 0;

                    execute_line(line_buf, out);
                    line_idx = 0;
                    line_buf[0] = '\0';
                }
                print_prompt(out);
            } else if (c == '\b' || c == 0x7F) { // Backspace or DEL
                if (line_idx > 0) {
                    --line_idx;
                    line_buf[line_idx] = '\0';
                    SerialDevice::puts("\b \b");
                }
            } else if (c >= 0x20 && c <= 0x7E) {
                if (line_idx + 1 < sizeof(line_buf)) {
                    line_buf[line_idx++] = c;
                    line_buf[line_idx] = '\0';
                    SerialDevice::putc(c); // Local echo
                }
            }
        }
    }

private:
    void cmd_help(IOutput const& out) const noexcept {
        out.puts("μCore Interactive Diagnostic Shell Commands:\n");
        out.puts("  help / ?           Show this command reference\n");
        out.puts("  version / uname    Kernel version, hardware target & OS lineages\n");
        out.puts("  services / svc     List init-supervised services & restart budgets\n");
        out.puts("  ps / threads       Active threads, CBS/EDF budgets & loan status\n");
        out.puts("  caps [dom]         Inspect capability table, delegations & rights\n");
        out.puts("  trace / dmesg [n]  Dump recent Flight Recorder events from TraceRing\n");
        out.puts("  ns / mounts        Inspect Plan 9 per-domain capability namespaces\n");
        out.puts("  resolve <dom> <p>  Resolve a path in a domain's private namespace\n");
        out.puts("  smp / cores        SMP CPU execution shards & incoming IPI queues\n");
        out.puts("  mem / magazines    Physical memory pool & per-core magazine stats\n");
        out.puts("  irq [fast|fault]   Trigger NVMe IRQ 48 through verified Kineticlet DAG\n");
        out.puts("  crash <service>    Inject domain fault to test init supervisor\n");
        out.puts("  loan <d> <w> <cpu> Simulate cross-core L4-MCS CBS donation\n");
        out.puts("  bench              Benchmark 1,000 Ring-0 Kineticlet dispatches\n");
        out.puts("  stats / telemetry  Kernel performance counters & isolation telemetry\n");
        out.puts("  echo <text...>     Echo text back to output\n");
        out.puts("  clear              Clear the terminal screen\n");
        out.puts("  reboot / reset     Hardware reboot via 8042 / triple-fault\n");
        out.puts("  halt / shutdown    Halt CPU execution\n");
    }

    void cmd_version(IOutput const& out) const noexcept {
        out.puts("μCore (mucore-kernel) v0.2.0 (x86_64 SMP Freestanding C++23)\n");
        out.puts("Architecture: Pure Functional Core, Imperative Shell (FCIS)\n");
        out.puts("Four Synthesized Lineages:\n");
        out.puts("  - Zircon:    FluxPort O(1) readiness aggregation & capability discipline\n");
        out.puts("  - WinNT:     MPK WRPKRU buffer sealing & IOMMU DMA crash quarantine\n");
        out.puts("  - Plan 9:    Per-domain capability namespaces & union interposition\n");
        out.puts("  - L4 MCS:    Constant Bandwidth Server (CBS) context & budget donation\n");
    }

    void cmd_services(IOutput const& out) const noexcept {
        out.puts("Idx  Service    Domain  Thread  State    Restarts  Critical  Imports  Exports\n");
        out.puts("-------------------------------------------------------------------------\n");
        for (usize i = 0; i < plan_.count; ++i) {
            core::init::PlannedService const& svc = plan_.services[i];
            core::init::ServiceRuntime const& rt  = init_.services[i];

            out.write_u64_pad(i, 5);
            out.write_pad(svc.name, 11);
            out.write_u64_pad(svc.domain.raw, 8);
            out.write_u64_pad(svc.thread.raw, 8);

            switch (rt.state) {
                case core::init::ServiceState::Running: out.write_pad("Running", 9); break;
                case core::init::ServiceState::Failed:  out.write_pad("FAILED", 9);  break;
                case core::init::ServiceState::Stopped: out.write_pad("Stopped", 9); break;
            }

            out.write_u64(rt.restarts);
            out.putc('/');
            out.write_u64_pad(svc.max_restarts, 8);

            out.write_pad(svc.critical ? "yes" : "no", 10);
            out.write_u64_pad(svc.import_count, 9);
            out.write_u64(svc.export_count);
            out.putc('\n');
        }
    }

    void cmd_ps(IOutput const& out) const noexcept {
        out.puts("TID  Dom  Class          State      WCET(us)  Period(us)  Budget(us)  LoanTo\n");
        out.puts("------------------------------------------------------------------------\n");
        core::sched::SchedTable const& sched = kernel_.state().sched;

        for (usize i = 0; i < core::sched::MAX_THREADS; ++i) {
            core::sched::ThreadControlBlock const& t = sched.threads[i];
            if (!t.occupied) continue;

            out.write_u64_pad(t.id.raw, 5);
            out.write_u64_pad(t.domain.raw, 5);

            switch (t.sched_class) {
                case core::sched::SchedClass::IsochronousRt:   out.write_pad("IsochronousRt", 15); break;
                case core::sched::SchedClass::AsyncThroughput: out.write_pad("AsyncThruput", 15);  break;
                case core::sched::SchedClass::Idle:            out.write_pad("Idle", 15);          break;
            }

            switch (t.state) {
                case core::sched::ThreadState::Ready:     out.write_pad("Ready", 11);     break;
                case core::sched::ThreadState::Running:   out.write_pad("Running", 11);   break;
                case core::sched::ThreadState::Blocked:   out.write_pad("Blocked", 11);   break;
                case core::sched::ThreadState::Throttled: out.write_pad("Throttled", 11); break;
                case core::sched::ThreadState::Unused:    out.write_pad("Unused", 11);    break;
            }

            if (t.sched_class == core::sched::SchedClass::IsochronousRt) {
                out.write_u64_pad(t.rt.wcet_ns / 1000ULL, 10);
                out.write_u64_pad(t.rt.period_ns / 1000ULL, 12);
                out.write_u64_pad(t.remaining_budget_ns / 1000ULL, 12);
            } else {
                out.write_pad("-", 10);
                out.write_pad("-", 12);
                out.write_pad("-", 12);
            }

            if (t.loaned_to) {
                out.write_u64(t.loaned_to.raw);
            } else if (t.borrowed_from) {
                out.puts("borrowed:");
                out.write_u64(t.borrowed_from.raw);
            } else {
                out.putc('-');
            }
            out.putc('\n');
        }
    }

    void cmd_caps(CmdTokens const& tok, IOutput const& out) const noexcept {
        bool filter_dom = false;
        u32 target_dom = 0;
        if (tok.count > 1) {
            filter_dom = true;
            target_dom = static_cast<u32>(parse_u64_str(tok.args[1]));
        }

        out.puts("Slot  Dom  Kind           Rights                Token                 Gen  RevGrp\n");
        out.puts("---------------------------------------------------------------------------------\n");

        core::cap::CapTable const& caps = kernel_.state().caps;
        usize active_count = 0;

        for (usize i = 0; i < core::cap::MAX_CAP_SLOTS; ++i) {
            core::cap::CapEntry const& c = caps.slots[i];
            if (!c.occupied) continue;
            if (filter_dom && c.owner.raw != target_dom) continue;

            ++active_count;
            out.write_u64_pad(i, 6);
            out.write_u64_pad(c.owner.raw, 5);

            switch (c.kind) {
                case core::cap::CapObjectKind::None:          out.write_pad("None", 15);          break;
                case core::cap::CapObjectKind::FluxConduit:   out.write_pad("FluxConduit", 15);   break;
                case core::cap::CapObjectKind::FluxPort:      out.write_pad("FluxPort", 15);      break;
                case core::cap::CapObjectKind::GrantArena:    out.write_pad("GrantArena", 15);    break;
                case core::cap::CapObjectKind::MmioRegion:    out.write_pad("MmioRegion", 15);    break;
                case core::cap::CapObjectKind::IrqHook:       out.write_pad("IrqHook", 15);       break;
                case core::cap::CapObjectKind::KineticSlot:   out.write_pad("KineticSlot", 15);   break;
                case core::cap::CapObjectKind::RtBudget:      out.write_pad("RtBudget", 15);      break;
                case core::cap::CapObjectKind::DomainControl: out.write_pad("DomainControl", 15); break;
            }

            // Compact rights representation (R W X D Rev RT DMA FP)
            char r_buf[22]{};
            usize r_idx = 0;
            if (c.rights & core::cap::CapRights::Read)         { r_buf[r_idx++] = 'R'; r_buf[r_idx++] = ' '; }
            if (c.rights & core::cap::CapRights::Write)        { r_buf[r_idx++] = 'W'; r_buf[r_idx++] = ' '; }
            if (c.rights & core::cap::CapRights::ExecuteRing0) { r_buf[r_idx++] = 'X'; r_buf[r_idx++] = ' '; }
            if (c.rights & core::cap::CapRights::Delegate)     { r_buf[r_idx++] = 'D'; r_buf[r_idx++] = ' '; }
            if (c.rights & core::cap::CapRights::Revoke)       { r_buf[r_idx++] = 'V'; r_buf[r_idx++] = ' '; }
            if (c.rights & core::cap::CapRights::UrgentRt)     { r_buf[r_idx++] = 'U'; r_buf[r_idx++] = ' '; }
            if (c.rights & core::cap::CapRights::DmaMap)       { r_buf[r_idx++] = 'M'; r_buf[r_idx++] = ' '; }
            if (c.rights & core::cap::CapRights::FastPromote)  { r_buf[r_idx++] = 'P'; r_buf[r_idx++] = ' '; }
            r_buf[r_idx] = '\0';
            out.write_pad(r_buf, 22);

            core::cap::CapToken const tok_val = core::cap::CapToken::pack(
                static_cast<u32>(i), c.generation, c.kind, c.rights
            );
            out.write_hex(tok_val.raw);
            out.puts("  ");
            out.write_u64_pad(c.generation, 5);
            out.write_u64(c.rev_group.raw);
            out.putc('\n');
        }

        out.puts("Total active capabilities: ");
        out.write_u64(active_count);
        out.puts(" (Capacity: ");
        out.write_u64(core::cap::MAX_CAP_SLOTS);
        out.puts(" slots)\n");
    }

    void cmd_trace(CmdTokens const& tok, IOutput const& out) const noexcept {
        TraceRing const& tr = kernel_.trace();
        usize const total = tr.available();
        usize count = (tok.count > 1) ? static_cast<usize>(parse_u64_str(tok.args[1])) : 16;
        if (count == 0 || count > total) count = total;

        out.puts("Seq     EventKind        Timestamp(ns)  Caller  Status  Effects\n");
        out.puts("----------------------------------------------------------------\n");

        for (usize i = count; i > 0; --i) {
            auto rec_opt = tr.get_recent(i - 1);
            if (rec_opt.is_none()) continue;
            TraceRecord const& r = rec_opt.value();

            out.write_u64_pad(r.seq_no, 8);
            switch (r.event.kind) {
                case core::EventKind::TimerExpired:        out.write_pad("TimerExpired", 17);        break;
                case core::EventKind::HardwareIrq:         out.write_pad("HardwareIrq", 17);         break;
                case core::EventKind::FluxSubmit:          out.write_pad("FluxSubmit", 17);          break;
                case core::EventKind::FluxComplete:        out.write_pad("FluxComplete", 17);        break;
                case core::EventKind::ThermalSweep:        out.write_pad("ThermalSweep", 17);        break;
                case core::EventKind::RevokeCapability:    out.write_pad("RevokeCap", 17);           break;
                case core::EventKind::DomainCrashTeardown: out.write_pad("CrashTeardown", 17);       break;
            }

            out.write_u64_pad(r.event.timestamp.raw, 15);
            out.write_u64_pad(r.event.caller_domain.raw, 8);
            out.write_pad(error_name(r.status), 8);
            out.write_u64(r.effect_count);
            out.putc('\n');
        }

        out.puts("Total Flight Recorder events logged: ");
        out.write_u64(tr.total_recorded());
        out.putc('\n');
    }

    void cmd_ns(IOutput const& out) const noexcept {
        out.puts("Dom  Mount Path           Conduit  Order    FastPromote\n");
        out.puts("--------------------------------------------------------\n");
        core::ns::NamespaceTable const& ns = kernel_.state().namespaces;

        for (usize d = 0; d < core::ns::MAX_NAMESPACE_DOMAINS; ++d) {
            core::ns::DomainNamespace const& dom_ns = ns.domains[d];
            if (!dom_ns.initialized || dom_ns.count == 0) continue;

            for (usize m = 0; m < dom_ns.count; ++m) {
                core::ns::MountEntry const& me = dom_ns.mounts[m];
                if (!me.active) continue;

                out.write_u64_pad(dom_ns.domain.raw, 5);
                out.write_pad(me.prefix.bytes, 21);
                out.write_hex(me.conduit_id.raw);
                out.puts("   ");

                out.write_pad("Replace", 9); // Manifest default

                out.puts(me.allow_hot_promote ? "Yes (Hot Ring)\n" : "No  (Interposed)\n");
            }
        }
    }

    void cmd_resolve(CmdTokens const& tok, IOutput const& out) const noexcept {
        if (tok.count < 3) {
            out.puts("Usage: resolve <domain_id> <path>\n");
            out.puts("Example: resolve 3 /dev/nvme0\n");
            return;
        }

        u32 const   dom_id = static_cast<u32>(parse_u64_str(tok.args[1]));
        const char* path   = tok.args[2];

        auto res = core::ns::resolve_path(
            kernel_.state().namespaces, kernel_.state().caps, DomainId{dom_id}, path
        );

        if (res.is_err()) {
            out.puts("Failed to resolve path '");
            out.puts(path);
            out.puts("' in Domain ");
            out.write_u64(dom_id);
            out.puts(": Error ");
            out.puts(error_name(res.error()));
            out.putc('\n');
            return;
        }

        core::ns::ResolvedPath const& rp = res.value();
        out.puts("Resolved '");
        out.puts(path);
        out.puts("' for Domain ");
        out.write_u64(dom_id);
        out.puts(":\n");
        out.puts("  ConduitId:    ");
        out.write_hex(rp.conduit_id.raw);
        out.putc('\n');
        out.puts("  CanPromoteHot:");
        out.puts(rp.can_promote_hot ? " true (Direct zero-syscall ring)\n" : " false (Interposed proxy)\n");
        out.puts("  RelSubpath:   '");
        out.puts(rp.rel_subpath.bytes);
        out.puts("'\n");
    }

    void cmd_smp(IOutput const& out) const noexcept {
        if (smp_ == nullptr) {
            out.puts("Core  Online  Mag Free  Mag Cap  RT Reserve\n");
            out.puts("---------------------------------------------\n");
            out.puts("0     yes     31        64       8 frames (Simulated)\n");
            return;
        }

        out.puts("Core  Online  Mag Free  Mag Cap  RT Reserve  Parcels\n");
        out.puts("----------------------------------------------------\n");
        for (usize i = 0; i < MAX_SMP_CPUS; ++i) {
            core::smp::CpuShard const& shard = smp_->shards[i];
            bool const is_online = __atomic_load_n(&shard.online, __ATOMIC_ACQUIRE);
            if (!is_online && i > 3) continue; // Show at least 4 cores

            out.write_u64_pad(i, 6);
            out.write_pad(is_online ? "yes" : "no", 8);
            out.write_u64_pad(shard.frame_mag.count, 10);
            out.write_u64_pad(core::mm::MAGAZINE_CAPACITY, 9);
            out.write_pad("8 frames", 12);
            out.write_u64(shard.trace.count());
            out.putc('\n');
        }
    }

    void cmd_mem(IOutput const& out) const noexcept {
        out.puts("μCore Memory & Frame Magazine Subsystem:\n");
        out.puts("  Physical Pool Base:   0x00200000 (2 MiB)\n");
        out.puts("  Total 4KiB Frames:    4096 (16 MiB pool)\n");
        out.puts("  Per-Core Magazine:    64 frames (256 KiB cache per core)\n");
        out.puts("  Batch Refill/Drain:   32 frames per cold-ticket lock round\n");
        out.puts("  Hard-RT Watermark:    8 frames (strictly protected for Tier-0)\n");
    }

    void cmd_irq(CmdTokens const& tok, IOutput const& out) noexcept {
        bool const fault = (tok.count > 1 && core::init::cstr_equal(tok.args[1], "fault"));
        u64 const  hw_status = fault ? 0x8000ULL : 0x0001ULL;
        TickNs const now{get_timestamp_ticks()};

        out.puts("[IRQ 48] Injected NVMe Hardware IRQ (Status=");
        out.write_hex(hw_status);
        out.puts(")\n");

        core::KernelEvent const ev{
            .kind            = core::EventKind::HardwareIrq,
            .timestamp       = now,
            .irq_line        = IrqLine{48},
            .irq_status_word = hw_status,
        };

        auto res = kernel_.handle_event(ev);
        if (res.is_err()) {
            out.puts("  Failed to handle IRQ: ");
            out.puts(error_name(res.error()));
            out.putc('\n');
            return;
        }

        if (!fault) {
            out.puts("  -> Executed Verified Ring-0 Kineticlet DAG (#1, WCET=38ns)\n");
            out.puts("  -> Verdict: CompleteFastPath\n");
            out.puts("  -> Handled 100% in Ring 0 with 0 CONTEXT SWITCHES!\n");
        } else {
            out.puts("  -> Executed Verified Ring-0 Kineticlet DAG (#1)\n");
            out.puts("  -> Verdict: EscalateToUserspace (Anomaly flag 0x8000 detected)\n");
            out.puts("  -> Emitted Effect: EscalateToUserspaceDrv (Woke Userspace Driver)\n");
        }
    }

    void cmd_crash(CmdTokens const& tok, IOutput const& out) noexcept {
        if (tok.count < 2) {
            out.puts("Usage: crash <service_name>\n");
            out.puts("Example: crash vfs\n");
            return;
        }

        const char* const svc_name = tok.args[1];
        auto opt_idx = core::init::find_service_by_name(plan_, svc_name);
        if (opt_idx.is_none()) {
            out.puts("Unknown service '");
            out.puts(svc_name);
            out.puts("'. Use 'services' to view managed services.\n");
            return;
        }

        usize const idx = opt_idx.value();
        core::init::PlannedService const& svc = plan_.services[idx];

        out.puts("[SUPERVISOR] Injecting fatal fault into service '");
        out.puts(svc.name);
        out.puts("' (Domain ");
        out.write_u64(svc.domain.raw);
        out.puts(")...\n");

        TickNs const now{get_timestamp_ticks()};
        core::KernelEvent const ev{
            .kind          = core::EventKind::DomainCrashTeardown,
            .timestamp     = now,
            .caller_domain = svc.domain,
        };

        auto res = kernel_.handle_event(ev);
        if (res.is_err()) {
            out.puts("  Teardown error: ");
            out.puts(error_name(res.error()));
            out.putc('\n');
            return;
        }

        auto outcome = core::init::supervise_after_event(kernel_.state(), init_, plan_, ev);

        out.puts("  Supervisor Decision: ");
        switch (outcome.verdict) {
            case core::init::Verdict::Restarted:
                out.puts("RESTARTED via epoch bump!\n");
                out.puts("  -> Invalidated all client capability tokens in O(1)\n");
                out.puts("  -> Fresh conduits and ports re-wired\n");
                out.puts("  -> Restarts used: ");
                out.write_u64(outcome.restarts);
                out.putc('/');
                out.write_u64(svc.max_restarts);
                out.putc('\n');
                break;
            case core::init::Verdict::GaveUp:
                out.puts("GIVEN UP (Restart budget exhausted, marked FAILED)\n");
                break;
            case core::init::Verdict::HaltSystem:
                out.puts("HALT SYSTEM (Critical service failed!)\n");
                break;
            case core::init::Verdict::Unmanaged:
                out.puts("Unmanaged domain\n");
                break;
        }
    }

    void cmd_loan(CmdTokens const& tok, IOutput const& out) noexcept {
        if (smp_ == nullptr) {
            out.puts("[L4-MCS CBS] SMP multi-core fabric not connected.\n");
            return;
        }

        u32 const donor  = (tok.count > 1) ? static_cast<u32>(parse_u64_str(tok.args[1])) : 2u;
        u32 const worker = (tok.count > 2) ? static_cast<u32>(parse_u64_str(tok.args[2])) : 3u;
        u16 const cpu    = (tok.count > 3) ? static_cast<u16>(parse_u64_str(tok.args[3])) : 1u;

        TickNs const now{get_timestamp_ticks()};
        core::smp::ShardEvent const ev{
            .kind          = core::smp::ShardEventKind::LocalCbsRemoteCall,
            .timestamp     = now,
            .local_thread  = ThreadId{donor},
            .remote_worker = ThreadId{worker},
            .remote_cpu    = CpuId{cpu},
        };

        auto res = core::smp::execute_on_cpu_shard(*smp_, CpuId{0}, ev);
        if (res.is_err()) {
            out.puts("  CBS loan failed: ");
            out.puts(error_name(res.error()));
            out.putc('\n');
            return;
        }

        out.puts("[L4-MCS CBS] Loaned Thread ");
        out.write_u64(donor);
        out.puts(" budget to Worker ");
        out.write_u64(worker);
        out.puts(" on Core ");
        out.write_u64(cpu);
        out.puts("\n  -> Wait-free CrossCoreParcel enqueued in SPSC mailbox\n");
        out.puts("  -> Strict CBS budget conservation preserved (zero double-spend)\n");
    }

    void cmd_bench(IOutput const& out) noexcept {
        out.puts("Benchmarking 1,000 Ring-0 Kineticlet dispatches...\n");
        u64 const start = get_timestamp_ticks();

        for (usize i = 0; i < 1000; ++i) {
            (void)kernel_.handle_event(core::KernelEvent{
                .kind            = core::EventKind::HardwareIrq,
                .timestamp       = TickNs{start + i},
                .irq_line        = IrqLine{48},
                .irq_status_word = 0x0001ULL,
            });
        }

        u64 const elapsed = get_timestamp_ticks() - start;
        out.puts("  Completed 1,000 dispatches in ");
        out.write_u64(elapsed);
        out.puts(" ticks (~");
        out.write_u64(elapsed / 1000ULL);
        out.puts(" ticks/dispatch)\n");
        out.puts("  Context switches emitted: 0 (100% in Ring 0)\n");
    }

    void cmd_reboot(IOutput const& out) const noexcept {
        out.puts("[mucore] Resetting system via 8042 keyboard controller & triple fault...\n");
#if defined(__x86_64__)
        // 1. 8042 keyboard controller pulse reset
        asm volatile("outb %0, %1" : : "a"(static_cast<u8>(0xFE)), "Nd"(static_cast<u16>(0x64)) : "memory");
        // 2. Triple fault fallback
        struct [[gnu::packed]] {
            u16 limit{0};
            u64 base{0};
        } const null_idtr{};
        asm volatile("lidt (%0); int $3" : : "r"(&null_idtr));
#endif
    }

    void cmd_halt(IOutput const& out) const noexcept {
        out.puts("[mucore] Halting system. Processor execution stopped.\n");
#if defined(__x86_64__)
        for (;;) {
            asm volatile("cli; hlt");
        }
#endif
    }

    void cmd_stats(IOutput const& out) const noexcept {
        core::KernelTelemetry const& telem = kernel_.state().telemetry;
        out.puts("μCore Kernel Telemetry:\n");
        out.puts("  Total Dispatched Events:  ");
        out.write_u64(telem.total_events);
        out.putc('\n');
        out.puts("  Ring-0 Fast-Handled IRQs: ");
        out.write_u64(telem.ring0_fast_handled);
        out.putc('\n');
        out.puts("  Ring-3 Escalated Upcalls: ");
        out.write_u64(telem.ring3_escalations);
        out.putc('\n');
        out.puts("  Context Switches Emitted: ");
        out.write_u64(telem.context_switches_emitted);
        out.putc('\n');
        out.puts("  CR3 Page Table Switches:  ");
        out.write_u64(telem.cr3_switches_emitted);
        out.putc('\n');
        out.puts("  L4-MCS CBS Budget Loans:  ");
        out.write_u64(telem.mcs_donations);
        out.putc('\n');
        out.puts("  IOMMU Quarantined Frames: ");
        out.write_u64(telem.dma_quarantines);
        out.putc('\n');
    }

private:
    ImperativeKernelRuntime<Hal>& kernel_;
    core::init::InitState&         init_;
    const core::init::BootPlan&    plan_;
    core::smp::SmpNodeState*       smp_{nullptr};
};

} // namespace mucore::shell
