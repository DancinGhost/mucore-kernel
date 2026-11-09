#pragma once
// ============================================================================
// μCore x86_64 Imperative Shell — GDT, TSS, Fast SYSCALL/SYSRET & PCID Control
// ============================================================================
// Segment Selector Layout (Engineered for Single-Cycle `SYSRETQ` Compatibility):
//   0x00: Null Descriptor
//   0x08: Ring-0 64-bit Code (`KERNEL_CS`)
//   0x10: Ring-0 64-bit Data (`KERNEL_SS`)
//   0x18: Ring-3 64-bit Data (`USER_SS | 3` == 0x1B)  <-- STAR[63:48] = 0x10 -> +8  = 0x18!
//   0x20: Ring-3 64-bit Code (`USER_CS | 3` == 0x23)  <-- STAR[63:48] = 0x10 -> +16 = 0x20!
//   0x28: 64-bit Task State Segment (TSS low + high 16-byte system descriptor)
// ============================================================================

#include "mucore/types.hpp"

namespace mucore::arch::x86_64 {

inline constexpr u16 KERNEL_CS = 0x08;
inline constexpr u16 KERNEL_SS = 0x10;
inline constexpr u16 USER_SS   = 0x18 | 3;
inline constexpr u16 USER_CS   = 0x20 | 3;
inline constexpr u16 TSS_SEL   = 0x28;

// Architectural Model-Specific Registers (MSRs)
inline constexpr u32 MSR_IA32_EFER         = 0xC000'0080u;
inline constexpr u32 MSR_IA32_STAR         = 0xC000'0081u;
inline constexpr u32 MSR_IA32_LSTAR        = 0xC000'0082u;
inline constexpr u32 MSR_IA32_FMASK        = 0xC000'0084u;
inline constexpr u32 MSR_IA32_TSC_DEADLINE = 0x0000'06E0u;
inline constexpr u32 MSR_X2APIC_EOI        = 0x0000'080Bu;

inline constexpr u64 EFER_SCE              = 1ULL << 0;  // System Call Extensions
inline constexpr u64 RFLAGS_IF             = 1ULL << 9;  // Mask IF on SYSCALL entry
inline constexpr u64 RFLAGS_DF             = 1ULL << 10; // Mask DF on SYSCALL entry
inline constexpr u64 CR3_PCID_NOFLUSH      = 1ULL << 63; // Avoid TLB flush on CR3 switch!

struct [[gnu::packed]] TaskStateSegment64 {
    u32 reserved0{0};
    u64 rsp0{0};      // Ring-0 stack loaded on Ring-3 -> Ring-0 interrupt/trap
    u64 rsp1{0};
    u64 rsp2{0};
    u64 reserved1{0};
    u64 ist1{0};      // Dedicated Interrupt Stack Table 1 (Double Fault / NMI safety)
    u64 ist2{0};
    u64 ist3{0};
    u64 ist4{0};
    u64 ist5{0};
    u64 ist6{0};
    u64 ist7{0};
    u64 reserved2{0};
    u16 reserved3{0};
    u16 iomap_base{sizeof(TaskStateSegment64)};
};

struct [[gnu::packed]] GdtTable {
    u64 null_desc{0};
    u64 kernel_code64{0x00AF'9A00'0000'FFFFULL}; // DPL=0, L=1 (64-bit), Exec/Read
    u64 kernel_data64{0x00CF'9200'0000'FFFFULL}; // DPL=0, Read/Write
    u64 user_data64  {0x00CF'F200'0000'FFFFULL}; // DPL=3, Read/Write
    u64 user_code64  {0x00AF'FA00'0000'FFFFULL}; // DPL=3, L=1 (64-bit), Exec/Read
    u64 tss_low{0};
    u64 tss_high{0};
};

struct [[gnu::packed]] DescriptorPtr {
    u16 limit{0};
    u64 base{0};
};

[[nodiscard]] inline u64 rdmsr(u32 msr) noexcept {
    u32 lo = 0, hi = 0;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return (static_cast<u64>(hi) << 32) | lo;
}

inline void wrmsr(u32 msr, u64 val) noexcept {
    u32 const lo = static_cast<u32>(val & 0xFFFF'FFFFULL);
    u32 const hi = static_cast<u32>(val >> 32);
    asm volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi) : "memory");
}

[[nodiscard]] inline u64 rdtsc_ordered() noexcept {
    u32 lo = 0, hi = 0;
    asm volatile("lfence; rdtsc" : "=a"(lo), "=d"(hi) : : "memory");
    return (static_cast<u64>(hi) << 32) | lo;
}

// Reload CR3 with 12-bit Process Context Identifier (PCID) + NOFLUSH bit
// Eliminates expensive cross-domain TLB invalidations when switching protection domains!
inline void switch_cr3_pcid(PhysAddr pml4_phys, u16 pcid_12bit, bool preserve_tlb) noexcept {
    u64 val = (pml4_phys.raw & 0x000F'FFFF'FFFF'F000ULL) | (static_cast<u64>(pcid_12bit) & 0xFFFULL);
    if (preserve_tlb) {
        val |= CR3_PCID_NOFLUSH;
    }
    asm volatile("mov %0, %%cr3" : : "r"(val) : "memory");
}

// Write x86_64 Protection Key Rights for User Pages (PKRU) in ~20 cycles (0 TLB shootdowns!):
// Each 4-bit key `k` (0..15) uses 2 bits in PKRU: bit (2*k)=AccessDisable, bit (2*k+1)=WriteDisable.
inline void write_pkru_seal_writes(PkeyId key) noexcept {
    u32 const wd_bit = 1u << ((key.raw & 0xFu) * 2u + 1u);
    asm volatile(
        "xorl %%ecx, %%ecx\n\t"
        "xorl %%edx, %%edx\n\t"
        ".byte 0x0f, 0x01, 0xef" /* architectural wrpkru opcode */
        :
        : "a"(wd_bit)
        : "ecx", "edx", "memory"
    );
}

extern "C" void x86_64_load_gdt_and_tss(DescriptorPtr const* gdtr, u16 cs_sel, u16 ds_sel, u16 tss_sel) noexcept;
extern "C" void x86_64_syscall_entry() noexcept;

inline void encode_tss_descriptor(GdtTable& gdt, TaskStateSegment64 const* tss) noexcept {
    u64 const base  = reinterpret_cast<u64>(tss);
    u64 const limit = sizeof(TaskStateSegment64) - 1ULL;

    u64 low = 0;
    low |= (limit & 0xFFFFULL);
    low |= (base & 0xFFFFFFULL) << 16;
    low |= 0x89ULL << 40; // Present=1, DPL=0, Type=0x9 (64-bit Available TSS)
    low |= ((limit >> 16) & 0xFULL) << 48;
    low |= ((base >> 24) & 0xFFULL) << 56;

    gdt.tss_low  = low;
    gdt.tss_high = (base >> 32) & 0xFFFF'FFFFULL;
}

inline void init_fast_syscall_msrs() noexcept {
    // Enable SCE (System Call Extensions) in IA32_EFER
    u64 const efer = rdmsr(MSR_IA32_EFER) | EFER_SCE;
    wrmsr(MSR_IA32_EFER, efer);

    // STAR[47:32] = KERNEL_CS (0x08), STAR[63:48] = 0x10 (so SYSRETQ loads SS=0x18|3, CS=0x20|3)
    u64 const star = (static_cast<u64>(0x0010u) << 48) | (static_cast<u64>(KERNEL_CS) << 32);
    wrmsr(MSR_IA32_STAR, star);

    // LSTAR = 64-bit Ring-0 SYSCALL entry trampoline
    wrmsr(MSR_IA32_LSTAR, reinterpret_cast<u64>(&x86_64_syscall_entry));

    // Clear IF and DF automatically on SYSCALL entry (zero race window before stack switch!)
    wrmsr(MSR_IA32_FMASK, RFLAGS_IF | RFLAGS_DF);
}

} // namespace mucore::arch::x86_64
