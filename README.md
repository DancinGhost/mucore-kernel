# μCore (`mucore-kernel`)

> **A Pragmatic Hybrid Real-Time C++23 Kernel Engineered Around *Functional Core, Imperative Shell*, Verified Ring-0 Fast-Paths (*Kineticlets*), Wait-Free *Flux* Conduits, and Anti-L4 Capability Ergonomics.**

[![Language](https://img.shields.io/badge/C%2B%2B-23%20Freestanding-blue.svg)](#the-no-hidden-mechanisms-c23-manifesto)
[![Architecture](https://img.shields.io/badge/Arch-x86__64%20Higher--Half-orange.svg)](#repository-structure)
[![Paradigm](https://img.shields.io/badge/Architecture-Functional%20Core%20%2F%20Imperative%20Shell-success.svg)](#1-functional-core-imperative-shell-fcis-in-ring-0)

---

## Why μCore Exists

For forty years, operating system design has been trapped between two extremes:

1. **Monolithic Kernels (Linux, Windows NT, XNU):** Fast because hot paths live in Ring 0, yet fragile because millions of lines of complex driver control-plane code share full hardware privilege.
2. **Dogmatic Microkernels (L4, seL4, Mach):** Mathematically elegant isolation, yet notoriously painful to build a usable OS atop—forcing developers to manually juggle capabilities for every 4 KiB page-table level and turning simple I/O operations into multi-hop context-switch storms.

**μCore (`mucore-kernel`)** refuses to go blindly in one ideological direction. Instead, it treats Ring 0 and Ring 3 not as a wall, but as a **thermally adaptive, capability-governed continuum**:

* **95% of code by volume** (device initialization, PCIe enumeration, error recovery, filesystem namespaces, policy daemons—executed *rarely*, where 90% of bugs hide) runs isolated in **unprivileged Ring 3**.
* **95% of executed instructions by frequency** (IRQ filtering/acknowledgement, descriptor ring advancement, cache hits, scheduler dispatch) runs in **Ring 0** or **zero-syscall shared-memory rings** with **zero context switches**.

---

## Resolving Fundamental Architectural Tensions (Design Audit)

Combining *Ring-0 hot paths*, *Userspace drivers*, *Minimal context switching*, *Async/non-blocking I/O*, *Capabilities*, *Hard Real-Time*, and *C++ Functional Core / Imperative Shell* introduces **five classical computer-science contradictions**. Rather than ignoring them, μCore's architecture is specifically engineered to resolve each tension:

### Tension 1: *"Hot Paths in Ring 0"* vs. *"Userspace Drivers"* vs. *"Minimal Context Switching"*
* **The Contradiction:** Device I/O and interrupt handling *are* the hottest paths in an OS. If drivers live strictly in Ring 3, every hardware interrupt and DMA completion forces a `Ring 0 -> Ring 3 -> Ring 0` trap, pipeline serialization, and Spectre/IBRS barrier—*maximizing* context switching. Conversely, compiling full C++ drivers into Ring 0 destroys fault isolation.
* **μCore's Resolution — Split-Plane Drivers & *Kineticlets*:** Every driver is split into a **Ring-3 Control Plane** (complex setup, resets, fault recovery) and a **Verified Ring-0 Data-Plane Graft (*Kineticlet*)**. A Kineticlet is a tiny, statically verified, deterministic DAG program installed into Ring 0 via capability. Common-case interrupts (`99%+`) are filtered, counted, and completed into shared rings **100% inside Ring 0 with zero context switches**; only genuine anomalies (`EscalateToUserspace`) wake the Ring-3 driver.

### Tension 2: *"Maximum Hardware Isolation"* vs. *"Zero Context Switching / Zero TLB Thrash"*
* **The Contradiction:** Hardware memory protection relies on separate MMU page tables (`CR3`). Switching address spaces flushes TLB entries or burns cycles, and traditional zero-copy IPC remaps page tables on every message (triggering expensive cross-core `invlpg` IPI shootdowns).
* **μCore's Resolution — Persistent *GrantArenas* + PCID `NOFLUSH`:** Cross-domain data travels through pre-negotiated, capability-gated **`GrantArena`** physical windows using `O(1)` logical **Lease Ownership Transfers** (`mm::transfer_arena_lease`)—zero `memcpy` and zero page-table shootdowns. When an actual domain switch is required, the x86_64 Imperative Shell pairs 12-bit **PCIDs** with `CR3_PCID_NOFLUSH` (bit 63) to preserve hot TLB entries.

### Tension 3: *"Asynchronous / Non-Blocking Everywhere"* vs. *"Hard Real-Time Determinism"*
* **The Contradiction:** Async event rings (`io_uring` style) optimize *amortized throughput* via batching and coalescing, which introduces queuing jitter and head-of-line priority inversion fatal to Hard Real-Time deadlines. Worse, standard "lock-free" MPMC queues rely on Compare-And-Swap (CAS) retry loops that can starve under contention (unbounded Worst-Case Execution Time!).
* **μCore's Resolution — Wait-Free SPSC Rings + Urgent RT Fast-Slots + CBS Charging:**
  1. `Flux` conduits use **Wait-Free** Single-Producer Single-Consumer (SPSC) rings (`O(1)` exact instruction count, zero CAS retry loops).
  2. Every conduit pairs its bulk FIFO ring with an out-of-band, capability-gated **`UrgentRt` Priority Slot** that bypasses bulk queues and triggers immediate scheduler preemption (`DoorbellAction::PreemptNow`).
  3. Every Ring-0 Kineticlet yields an **exact statically proven `wcet_ns`** charged directly against its owner's **Constant Bandwidth Server (CBS)** budget—preventing a noisy device's IRQ storm from starving sibling real-time tasks.

### Tension 4: *"C++23"* + *"Functional Core, Imperative Shell"* vs. *"No Hidden Mechanisms in Ring 0"*
* **The Contradiction:** Standard C++ hides control flow everywhere (exceptions, RTTI, implicit heap allocations in `std::function` / C++20 `co_await` coroutines, virtual vtable indirection, `.init_array` static constructors running before `main`, and implicit copy constructors causing multi-kilobyte `memcpy` spikes). Meanwhile, textbook Functional Core designs rely on garbage-collected persistent data structures unsuitable for Ring 0.
* **μCore's Resolution — Explicit Value-Transition FCIS:**
  * Exceptions, RTTI, thread-safe statics, vtables, heap coroutines, and `.init_array` global constructors are **banned by compiler flags and linker `ASSERT`s**.
  * Pure Core functions inspect `const&` state views and emit small, stack-allocated, move-only `CapMutation`, `SchedDecision`, and `EffectBatch` (`StaticVec<KernelEffect, 8>`) values—achieving 100% functional determinism with **zero heap allocation and zero hidden struct copies**.

### Tension 5: *"Capability Security"* vs. *"Avoiding the L4 Usability Trap"*
* **The Contradiction:** Pure capability microkernels (L4/seL4) require capabilities for every 4 KiB physical frame, page-table level, and multi-hop IPC endpoint, plus `O(N)` tree walks to revoke delegated capabilities (breaking Hard Real-Time latency bounds!).
* **μCore's Resolution — *"Ambient Inside, Capabilities Between"* + `O(1)` Epoch Revocation:** See the dedicated comparison below.

---

## Escaping the L4 Usability Trap

| Pain Point in Strict L4 / seL4 | μCore Hybrid Approach | Practical Impact |
| :--- | :--- | :--- |
| **Manual Page-Table Capabilities:** Userspace must manually `Retype` untyped memory into `PML4 -> PDPT -> PD -> PT` capability objects just to grow a heap. | **Ambient Intra-Domain Quotas (`AmbientProfile`):** Private anonymous virtual memory, local threads, and futexes are managed ergonomically inside a `ProtectionDomain` against quota; capabilities are reserved for *cross-domain authority, MMIO/DMA, RT budgets, and Ring-0 Kineticlets*. | Writing normal applications and services feels natural instead of fighting kernel bookkeeping. |
| **Multi-Hop Synchronous RPC Chains:** `App -> VFS -> Auth -> Net -> Driver` = 8+ context switches per I/O operation. | **Brokered Direct Pacts:** Cold-path brokers (`open()`) mint an attenuated **Direct `FluxConduit` + `GrantArena` Pact** straight between Client and Driver/Kineticlet. | Steady-state data plane runs in **0 hops** and **0 syscalls** when hot. |
| **`O(N)` Capability Derivation Tree (CDT) Revocation:** Revoking delegated rights walks pointer trees and must preempt/restart mid-syscall. | **`O(1)` Generational Lineage Epochs (`RevocationGroupId`):** Derived capabilities bind to a lineage epoch counter; bumping `group_epochs[g]` invalidates *all* transitive descendants in **1 integer increment**. | Strict `O(1)` Worst-Case Execution Time compatible with Hard Real-Time guarantees. |

---

## System Architecture

```mermaid
flowchart TB
    subgraph Ring3["Ring 3 — Isolated Protection Domains (95% of Code Volume)"]
        App["Latency-Critical / Async App"]
        DrvCtrl["Userspace Driver Control Plane<br/>(PCIe Init, Firmware, Fault Recovery)"]
    end

    subgraph SharedMem["Capability-Gated Zero-Copy Shared Memory (Zero Syscall Boundary)"]
        Flux["Wait-Free SPSC Flux Rings<br/>+ Urgent RT Preemption Slot"]
        Arena["GrantArena Physical Windows<br/>(O(1) Zero-Copy Lease Transfer)"]
    end

    subgraph Ring0["Ring 0 — μCore Hybrid Kernel (95% of Executed Hot Cycles)"]
        subgraph Core["Pure Functional Core (include/mucore/core/* — Zero ASM, constexpr Verified)"]
            Cap["Generational Cap Engine<br/>+ O(1) Epoch Revocation"]
            Kinetic["Kineticlet DAG Verifier<br/>& Ring-0 Fast Interpreter"]
            Sched["Dual-Horizon Scheduler<br/>Tier 0: Hard-RT CBS/EDF<br/>Tier 1: Async VRuntime"]
            Therm["Thermal Tiering Policy<br/>(Cold <-> Warm <-> Hot)"]
        end

        subgraph Shell["Thin Imperative Shell (include/mucore/shell/* & kernel/arch/*)"]
            Runtime["ImperativeKernelRuntime&lt;Hal&gt;<br/>(Concept Static Dispatch — Zero Vtables)"]
            Trace["TraceRing Flight Recorder<br/>(Deterministic Time-Travel Replay)"]
            HW["x86_64 Hardware Effector<br/>PCID CR3 | APIC TSC-Deadline | SYSCALL/SYSRET | x2APIC"]
        end
    end

    App <-->|"Zero-Syscall Hot Poll"| Flux
    App <-->|"Zero-Copy Lease"| Arena
    DrvCtrl <-->|"Cold Recovery Only"| Runtime
    DrvCtrl -.->|"Installs Verified DAG"| Kinetic
    HW -->|"KernelEvent (IRQ / Timer / Cold Trap)"| Runtime
    Runtime -->|"const& State + Event"| Core
    Core -->|"Explicit EffectBatch"| Runtime
    Runtime -->|"Records Transition"| Trace
    Runtime -->|"Executes Effects"| HW
    Kinetic <-->|"99% IRQs Handled in Ring 0 (0 Switches!)"| Arena
```

---

## Five Pillars & "Outside-the-Prompt" Innovations

### 1. Functional Core, Imperative Shell (FCIS) in Ring 0
Every decision engine in `include/mucore/core/` (`capability.hpp`, `flux.hpp`, `kinetic.hpp`, `scheduler.hpp`, `memory.hpp`, `dispatcher.hpp`) contains **zero inline assembly, zero hardware register accesses, zero locks, and zero dynamic memory allocations**.
* Hardware events enter as explicit `KernelEvent` values (`TimerExpired`, `HardwareIrq`, `FluxSubmit`, `ThermalSweep`, `RevokeCapability`).
* The Core computes state transitions deterministically and returns an explicit `EffectBatch` (`SwitchAddressSpace`, `SwitchThreadContext`, `ArmOneShotTimer`, `AckIrqFastPath`, `EscalateToUserspaceDrv`, `NotifyConduitDoorbell`, `CpuIdleWait`).
* The Imperative Shell (`ImperativeKernelRuntime<Hal>`) executes those effects via C++23 `concept HalPlatform` static dispatch—**zero virtual function tables**.

### 2. Verified Ring-0 *Kineticlets* with Static Real-Time WCET Proofs
Userspace drivers graft deterministic Ring-0 fast paths using a compact 64-bit register machine (`include/mucore/core/kinetic.hpp`). Before installation, `verify_program()` proves in **single-pass linear $O(N)$ time**:
1. **Guaranteed Termination:** Branches (`JumpIfEq`, `JumpIfGt`) are strictly forward-only (`imm >= 1`), forming a **Directed Acyclic Graph (DAG)**—impossible to infinite-loop in Ring 0 and immune to eBPF-style verifier path explosion.
2. **Memory & Register Safety:** All register indices (`0..7`), persistent Ring-0 state slots (`0..3`), and shared `GrantArena` offsets (`0..15`) are statically bounds-checked; raw pointer arithmetic does not exist.
3. **Static Capability Enforcement:** Exercising `LoadArena`, `StoreArena`, or `WakeUrgentRt` without holding `CapRights::Read`, `CapRights::Write`, or `CapRights::UrgentRt` rejects installation at verification time.
4. **Exact Longest-Path WCET Derivation:** Backward dynamic programming over the DAG computes the **exact worst-case nanosecond cost (`wcet_ns`)**, feeding directly into Hard Real-Time CBS budget accounting!

### 3. Adaptive Conduit *Thermal Tiering* (`Cold` $\leftrightarrow$ `Warm` $\leftrightarrow$ `Hot`)
`Flux` channels (`include/mucore/core/flux.hpp`) dynamically adapt their notification physics using deterministic hysteresis:
* **`Cold` Tier:** Quiescent channels sleep with **0% CPU overhead** and wake via explicit `SYSCALL` doorbells (`DoorbellAction::WakeNow`).
* **`Warm` Tier:** Moderate-traffic channels coalesce ring submissions (`DoorbellAction::BatchWake`), amortizing Ring transitions across batches.
* **`Hot` Tier:** High-throughput or RT-pinned channels suppress doorbell traps completely (`DoorbellAction::None`), running **100% syscall-free** via Ring-0 polling or Kineticlet interception, then demoting back to `Warm` $\to$ `Cold` once idle windows elapse.

### 4. Dual-Horizon Tickless Real-Time + Async Scheduler
`include/mucore/core/scheduler.hpp` implements a two-tier tickless scheduler using **pure 64-bit integer arithmetic** (zero Ring-0 floating point, avoiding FPU/AVX state-save latency):
* **Tier 0 — Isochronous Hard/Firm Real-Time (CBS + EDF):** Uses ceiling fixed-point parts-per-million (`1,000,000 ppm = 100%`) admission control:
  $$\sum_{i=1}^{n} \left\lceil \frac{C_i \times 10^6}{T_i} \right\rceil \le 850{,}000\text{ ppm}\;(85.0\%)$$
  Reserving at least `15%` bandwidth guarantees Ring-3 driver control planes can never starve even under peak RT load, while **Constant Bandwidth Server (CBS)** throttling isolates misbehaving tasks and IRQ storms.
* **Tier 1 — Async / Interactive Throughput:** Schedules event-loop workers by weighted virtual runtime (`vruntime_ns`) whenever Tier 0 has no runnable job, programming the exact next nanosecond deadline into `MSR_IA32_TSC_DEADLINE`.

### 5. Emergent Superpowers: Compile-Time Kernel Proofs & Time-Travel Replay
Because the Functional Core is pure `constexpr` C++23:
* **Compile-Time Kernel Proofs (`tests/constexpr_proofs.cpp`):** Capability monotonicity, `O(1)` lineage revocation, Kineticlet verifier soundness, and CBS/EDF deadline admission are proven via `consteval` + `static_assert` **inside the compiler during every build**. If an invariant breaks, `mucore-kernel` refuses to compile.
* **Deterministic Flight Recorder (`include/mucore/shell/trace_ring.hpp`):** `TraceRing` records incoming `KernelEvent` streams in Ring 0 and can **replay the exact state-machine trajectory bit-for-bit** inside host unit tests (`TraceRing::replay_into`).

---

## The "No Hidden Mechanisms" C++23 Manifesto

Every line of `mucore-kernel` adheres to strict mechanical transparency enforced by both compiler flags and linker assertions:

* **No Exceptions (`-fno-exceptions`):** All fallible operations return `[[nodiscard]] Result<T, Error>` or `Option<T>`.
* **No RTTI (`-fno-rtti`) & No Vtables:** Hardware polymorphism uses `concept HalPlatform` static templates.
* **No Hidden Global Constructors (`constinit` + Linker `ASSERT`):** `kernel/arch/x86_64/linker.ld` asserts `SIZEOF(.init_array) == 0`. Nothing executes behind the scenes before `_start -> kmain()`.
* **No Hidden Heap Allocations:** Zero `new`/`delete` in the Core; bounded inline containers (`StaticVec<T, N>`) make memory footprints and WCET statically visible.
* **No Hidden Struct `memcpy`s:** Large tables (`KernelState`, `CapTable`, `SchedTable`) and `StaticVec` delete implicit copy constructors (`= delete`), requiring move semantics or explicit `.clone()`.
* **Strict Hardware `W^X` ELF Segments:** `.text` (`R-X`), `.rodata` (`R--`), and `.data`/`.bss` (`RW-`) are isolated on 4 KiB page boundaries with zero `RWX` pages.

---

## Repository Structure

```text
mucore-kernel/
├── include/mucore/
│   ├── types.hpp                  # Strong register-sized IDs (DomainId, ThreadId, TickNs) & Error enum
│   ├── result.hpp                 # [[nodiscard]] constexpr Option<T> & Result<T, Error>
│   ├── array_vec.hpp              # Zero-heap Span<T> & move-only StaticVec<T, Capacity>
│   ├── core/                      # === PURE FUNCTIONAL CORE (Zero ASM, 100% Host & consteval Testable) ===
│   │   ├── capability.hpp         # Generational capabilities, AmbientProfile & O(1) epoch revocation
│   │   ├── flux.hpp               # Wait-free SPSC protocol, Urgent RT slot & Thermal Tiering
│   │   ├── kinetic.hpp            # Ring-0 Kineticlet DAG static verifier (WCET DP) & pure interpreter
│   │   ├── scheduler.hpp          # Dual-Horizon CBS/EDF Hard-RT + Virtual-Runtime tickless scheduler
│   │   ├── memory.hpp             # Physical frame bitmap policy & O(1) zero-copy GrantArena leases
│   │   ├── effects.hpp            # Algebraic KernelEvent inputs & KernelEffect hardware outputs
│   │   └── dispatcher.hpp         # Unified deterministic kernel transition engine
│   └── shell/                     # === IMPERATIVE SHELL INTERFACES ===
│       ├── hal.hpp                # Zero-vtable `concept HalPlatform` & ImperativeKernelRuntime<Hal>
│       ├── shared_conduit.hpp     # Cache-line aligned (__atomic acquire/release) wait-free SPSC ring
│       └── trace_ring.hpp         # Lock-free Flight Recorder with deterministic time-travel replay
├── kernel/                        # === BARE-METAL RING-0 IMPLEMENTATION ===
│   ├── kmain.cpp                  # constinit Ring-0 bootstrap, Limine handoff & boot POST self-check
│   └── arch/x86_64/
│       ├── boot.S                 # 64-bit Higher-Half _start, GDT/TSS reload & fast SYSCALL/SYSRETQ
│       ├── cpu.hpp                # SYSRET-ordered GDT, 64-bit TSS, MSRs & PCID CR3_NOFLUSH helpers
│       ├── hal_x86_64.hpp         # Bare-metal x86_64 HalPlatform (x2APIC, TSC-Deadline, PCID)
│       ├── limine_proto.hpp       # Standalone Limine boot protocol request definitions
│       ├── linker.ld              # Higher-half (-2 GiB) W^X ELF64 linker script (.init_array banned!)
│       └── serial.hpp             # Early 16550 UART (COM1) diagnostic console
├── tests/                         # === COMPILE-TIME PROOFS & HOST SIMULATION SUITE ===
│   ├── constexpr_proofs.cpp       # consteval static_assert proofs compiled into both kernel & tests
│   └── test_main.cpp              # Split-plane NVMe IRQ simulation, RT storm test & TraceRing replay
└── Makefile                       # Builds bare-metal ELF64 kernel (`make kernel`) & suite (`make test`)
```

---

## Building & Running Verification

### Prerequisites
* `clang++` (Clang 17+) or `g++` (GCC 13+) with C++23 support
* GNU `ld` (`elf_x86_64`) and `make`

### Build Both Bare-Metal Kernel & Host Verification Suite
```bash
make all
```
Or explicitly with Clang:
```bash
make CXX=clang++ all
```

### Expected Verification Output
```text
================================================================
  μCore (mucore-kernel) — FCIS Verification & Replay Suite
  Compile-Time `static_assert` Proofs: PASSED
================================================================
[TEST 1] Generational Capabilities & O(1) Epoch Revocation...
  [PASS] Monotonic attenuation & O(1) revocation verified.
[TEST 2] Wait-Free SPSC Shared Ring & Urgent RT Fast-Lane...
  [PASS] Wait-free SPSC & Urgent RT head-of-line preemption verified.
[TEST 3] Adaptive Conduit Thermal Promotion & Hysteresis Decay...
  [PASS] Adaptive Thermal Tiering promotes hot paths & parks idle channels.
[TEST 4] Split-Plane Userspace Driver + Ring-0 Kineticlet (100 IRQs)...
  [PASS] 99/100 IRQs completed in Ring 0 (0 switches, WCET=38 ns); 1 fault escalated; 100% replay match!
[TEST 5] Hard Real-Time CBS Temporal Isolation Under IRQ Storm...
  [PASS] CBS budget charging protects sibling Hard-RT deadlines from IRQ storms.
[TEST 6] Physical Frame Allocator & Zero-Copy GrantArena Leases...
  [PASS] Zero-copy GrantArena lease transfer & frame safety verified.
----------------------------------------------------------------
Summary: 6 passed, 0 failed.
```

---

## Roadmap

- [x] **Phase 0 — Groundwork (Current):** Explicit C++23 FCIS architecture, `O(1)` Generational + Epoch Capabilities, Wait-Free `Flux` SPSC Conduits + Adaptive Thermal Tiering, Verified Ring-0 `Kineticlet` DAG interpreter with exact WCET derivation, Dual-Horizon CBS/EDF + Async Scheduler, `TraceRing` replay, and Higher-Half `x86_64` W^X ELF64 bootstrap.
- [ ] **Phase 1 — Hardware Paging & Limine Iso Boot:** 4-level/5-level HHDM page-table builder (`VmSpace`), per-CPU APIC/TSC calibration, IDT exception vectors, and bootable Limine ISO target (`make iso` / `make qemu`).
- [ ] **Phase 2 — Ring-3 Protection Domains & Direct Pacts:** First Ring-3 ELF loader, `SharedSpscRing` dual-mapped user/kernel pages, and Intel VT-d / AMD-Vi IOMMU capability enforcement for DMA-safe userspace drivers.
- [ ] **Phase 3 — Native Machine-Code JIT for Kineticlets:** Optional ahead-of-time translation of verified `KineticProgram` DAGs into native `x86_64` instructions (reducing 38 ns interpreted fast-paths to < 5 ns native Ring-0 execution while preserving exact DAG WCET proofs).
- [ ] **Phase 4 — SMP Per-Core Sharding:** Wait-free cross-core `Flux` mailrouting with per-CPU Functional Core shards (zero global kernel lock).
