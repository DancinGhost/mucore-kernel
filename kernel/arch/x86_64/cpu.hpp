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
inline constexpr u32 MSR_IA32_EFER           = 0xC000'0080u;
inline constexpr u32 MSR_IA32_STAR           = 0xC000'0081u;
inline constexpr u32 MSR_IA32_LSTAR          = 0xC000'0082u;
inline constexpr u32 MSR_IA32_FMASK          = 0xC000'0084u;
inline constexpr u32 MSR_IA32_FS_BASE        = 0xC000'0100u;
inline constexpr u32 MSR_IA32_GS_BASE        = 0xC000'0101u;
inline constexpr u32 MSR_IA32_KERNEL_GS_BASE = 0xC000'0102u;
inline constexpr u32 MSR_IA32_TSC_DEADLINE   = 0x0000'06E0u;
inline constexpr u32 MSR_X2APIC_TPR          = 0x0000'0808u; // Task Priority Register
inline constexpr u32 MSR_X2APIC_EOI          = 0x0000'080Bu;
inline constexpr u32 MSR_X2APIC_SVR          = 0x0000'080Fu; // Spurious Interrupt Vector Register
inline constexpr u32 MSR_X2APIC_ICR          = 0x0000'0830u; // 64-bit x2APIC IPI command MSR!
inline constexpr u32 MSR_X2APIC_LVT_TIMER    = 0x0000'0832u; // LVT Timer Register

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

[[nodiscard]] inline u64 read_cr2() noexcept {
    u64 addr = 0;
    asm volatile("mov %%cr2, %0" : "=r"(addr));
    return addr;
}

// Send a register-based x2APIC Fixed IPI (`MSR_X2APIC_ICR = 0x830`) — zero MMIO serialization!
inline void send_x2apic_ipi(u32 dest_lapic_id, u8 vector) noexcept {
    u64 const icr = (static_cast<u64>(dest_lapic_id) << 32) |
                    (1ULL << 14) | // Level = Assert
                    static_cast<u64>(vector);
    wrmsr(MSR_X2APIC_ICR, icr);
}

// Enable Local x2APIC with Spurious Vector (bit 8 = Software Enable)
inline void enable_x2apic_software(u8 spurious_vec = 255) noexcept {
    wrmsr(MSR_X2APIC_SVR, (1ULL << 8) | static_cast<u64>(spurious_vec));
    // Clear TPR to accept all interrupt priorities
    wrmsr(MSR_X2APIC_TPR, 0ULL);
}

// Arm x2APIC LVT Timer in TSC-Deadline Mode (Intel SDM Vol. 3A 10.5.4.1)
inline void init_x2apic_tsc_deadline(u8 timer_vec) noexcept {
    // Bits 18:17 = 10b (TSC-Deadline mode), Bit 16 = 0 (unmasked), Bits 7:0 = vector
    u64 const lvt = (1ULL << 18) | static_cast<u64>(timer_vec);
    wrmsr(MSR_X2APIC_LVT_TIMER, lvt);
}

// Port I/O Primitives
inline void outb(u16 port, u8 val) noexcept {
    asm volatile("outb %0, %1" : : "a"(val), "Nd"(port) : "memory");
}

[[nodiscard]] inline u8 inb(u16 port) noexcept {
    u8 ret = 0;
    asm volatile("inb %1, %0" : "=a"(ret) : "Nd"(port) : "memory");
    return ret;
}

inline void io_wait() noexcept {
    outb(0x80, 0);
}

// System Reset & Halt Helpers
inline void system_halt() noexcept {
    for (;;) {
        asm volatile("cli; hlt");
    }
}

inline void system_reset_8042(DescriptorPtr const* null_idtr = nullptr) noexcept {
    // 1. Keyboard Controller (8042) Pulse Reset (Port 0x64, Command 0xFE)
    outb(0x64, 0xFE);
    io_wait();

    // 2. Triple fault fallback
    if (null_idtr != nullptr) {
        asm volatile("lidt (%0); int $3" : : "r"(null_idtr));
    } else {
        DescriptorPtr const zero_idtr{.limit = 0, .base = 0};
        asm volatile("lidt (%0); int $3" : : "r"(&zero_idtr));
    }

    system_halt();
}

// TSC Cycle-to-Nanosecond Fixed-Point Scaling
struct TscClockScale {
    u64 mult{1000};             // Fixed-point factor: ns = (ticks * mult) >> shift
    u32 shift{20};              // 20-bit fixed-point fractional precision
    u64 tsc_hz{1'000'000'000ULL}; // Calibrated TSC frequency in Hz
};

[[nodiscard]] constexpr TickNs tsc_to_ns(u64 ticks, TscClockScale const& scale) noexcept {
    return TickNs{(ticks * scale.mult) >> scale.shift};
}

[[nodiscard]] constexpr u64 ns_to_tsc(TickNs ns, TscClockScale const& scale) noexcept {
    if (scale.mult == 0) return ns.raw;
    return (ns.raw << scale.shift) / scale.mult;
}

// Freestanding CPUID-based TSC frequency calibrator
inline TscClockScale calibrate_tsc() noexcept {
    TscClockScale scale{};
    u32 eax = 0, ebx = 0, ecx = 0, edx = 0;

    // Check CPUID Leaf 0x16 (Processor Frequency Information)
    asm volatile(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0x16u), "c"(0u)
    );

    u64 const base_mhz = eax & 0xFFFFu;
    if (base_mhz >= 100 && base_mhz <= 10'000) {
        scale.tsc_hz = base_mhz * 1'000'000ULL;
    } else {
        // Fallback: Check CPUID Leaf 0x15 (Crystal Clock Ratio)
        asm volatile(
            "cpuid"
            : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
            : "a"(0x15u), "c"(0u)
        );
        if (eax != 0 && ebx != 0 && ecx != 0) {
            scale.tsc_hz = (static_cast<u64>(ecx) * ebx) / eax;
        } else {
            // Nominal reference fallback: 2.4 GHz typical modern x86_64 core
            scale.tsc_hz = 2'400'000'000ULL;
        }
    }

    scale.shift = 20;
    scale.mult  = (1'000'000'000ULL << 20) / scale.tsc_hz;
    return scale;
}

extern "C" void x86_64_load_gdt_and_tss(DescriptorPtr const* gdtr, u16 cs_sel, u16 ds_sel, u16 tss_sel) noexcept;
extern "C" void x86_64_load_idt(DescriptorPtr const* idtr) noexcept;
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
