#pragma once
// ============================================================================
// μCore x86_64 Arch — Per-CPU `%gs` Hardware Context & Stack Isolation
// ============================================================================
// Eliminates the Phase-0 single-core `cpu0_user_rsp_scratch` bottleneck:
//   - Every CPU core binds its own `PerCpuArchBlock` to `MSR_IA32_GS_BASE`
//     (and `MSR_IA32_KERNEL_GS_BASE` for Ring-3 `swapgs` entry).
//   - `boot.S` accesses `kernel_rsp` at `%gs:0`, `user_rsp_scratch` at `%gs:8`,
//     and `cpu_index` at `%gs:16` — verified at compile time by `static_assert`.
// ============================================================================

#include "kernel/arch/x86_64/cpu.hpp"

namespace mucore::arch::x86_64 {

inline constexpr usize PERCPU_KERNEL_STACK_BYTES = 16384ULL;
inline constexpr usize PERCPU_IST1_STACK_BYTES   = 8192ULL;

struct alignas(CACHE_LINE_BYTES) PerCpuArchBlock {
    // --- ABI-Frozen `%gs` Header Read by `boot.S` (`x86_64_syscall_entry`) ---
    u64                 kernel_rsp{0};       // %gs:0  — Ring-0 syscall/interrupt stack top
    u64                 user_rsp_scratch{0}; // %gs:8  — Saved Ring-3 user %rsp during SYSCALL
    u32                 cpu_index{0};        // %gs:16 — Logical CpuId (`0 .. MAX_SMP_CPUS-1`)
    u32                 lapic_id{0};         // %gs:20 — Hardware Local APIC ID
    PerCpuArchBlock*    self{nullptr};       // %gs:24 — Self pointer

    // --- Per-CPU GDT & 64-Bit TSS (Each Core Requires Its Own Busy-TSS Bit!) ---
    GdtTable            gdt{};
    TaskStateSegment64  tss{};

    alignas(16) u8      ring0_stack[PERCPU_KERNEL_STACK_BYTES]{};
    alignas(16) u8      ist1_stack[PERCPU_IST1_STACK_BYTES]{};
};

static_assert(__builtin_offsetof(PerCpuArchBlock, kernel_rsp) == 0,
              "PerCpuArchBlock::kernel_rsp must be at %gs:0 for boot.S");
static_assert(__builtin_offsetof(PerCpuArchBlock, user_rsp_scratch) == 8,
              "PerCpuArchBlock::user_rsp_scratch must be at %gs:8 for boot.S");
static_assert(__builtin_offsetof(PerCpuArchBlock, cpu_index) == 16,
              "PerCpuArchBlock::cpu_index must be at %gs:16 for boot.S");

// Initialize a CPU core's GDT, TSS, Fast `SYSCALL`, and `%gs` MSRs!
inline void init_percpu_arch(PerCpuArchBlock& blk, u32 cpu_idx, u32 hw_lapic_id) noexcept {
    blk.cpu_index = cpu_idx;
    blk.lapic_id  = hw_lapic_id;
    blk.self      = &blk;

    u64 const kstack_top = reinterpret_cast<u64>(&blk.ring0_stack[PERCPU_KERNEL_STACK_BYTES]);
    u64 const ist1_top   = reinterpret_cast<u64>(&blk.ist1_stack[PERCPU_IST1_STACK_BYTES]);

    blk.kernel_rsp = kstack_top;
    blk.tss.rsp0   = kstack_top;
    blk.tss.ist1   = ist1_top;

    encode_tss_descriptor(blk.gdt, &blk.tss);
    DescriptorPtr const gdtr{
        .limit = sizeof(GdtTable) - 1u,
        .base  = reinterpret_cast<u64>(&blk.gdt),
    };
    x86_64_load_gdt_and_tss(&gdtr, KERNEL_CS, KERNEL_SS, TSS_SEL);

    // Bind `%gs` in Ring 0 (`GS_BASE`) AND stage `KERNEL_GS_BASE` for Ring-3 `swapgs`!
    // Note: `x86_64_load_gdt_and_tss` zeroes `%gs` selector, which clears `GS_BASE` on x86_64,
    // so `wrmsr(MSR_IA32_GS_BASE, ...)` MUST happen AFTER `x86_64_load_gdt_and_tss`!
    u64 const base_addr = reinterpret_cast<u64>(&blk);
    wrmsr(MSR_IA32_GS_BASE, base_addr);
    wrmsr(MSR_IA32_KERNEL_GS_BASE, base_addr);

    init_fast_syscall_msrs();
}

[[nodiscard]] inline u32 current_cpu_index() noexcept {
    u32 idx = 0;
    asm volatile("movl %%gs:16, %0" : "=r"(idx));
    return idx;
}

} // namespace mucore::arch::x86_64
