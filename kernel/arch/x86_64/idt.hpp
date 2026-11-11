#pragma once
// ============================================================================
// μCore x86_64 Arch — 256-Vector 64-Bit Interrupt Descriptor Table (IDT)
// ============================================================================
// Routes hardware faults, APIC TSC-Deadline timers, and Cross-Core SMP Parcel
// IPIs into the Imperative Shell:
//   - Vector  8 (`#DF` Double Fault): uses dedicated `IST = 1` per-CPU stack.
//   - Vector 13 (`#GP` General Protection Fault)
//   - Vector 14 (`#PF` Page Fault, reads `%cr2`)
//   - Vector 32 (`VEC_APIC_TIMER`): Tickless CBS/EDF deadline expiration
//   - Vector 33 (`VEC_SMP_PARCEL_IPI`): Wait-free `SmpMailMatrix` cross-core wake
// ============================================================================

#include "kernel/arch/x86_64/cpu.hpp"

namespace mucore::arch::x86_64 {

inline constexpr u8 VEC_DOUBLE_FAULT     = 8;
inline constexpr u8 VEC_GP_FAULT         = 13;
inline constexpr u8 VEC_PAGE_FAULT       = 14;
inline constexpr u8 VEC_APIC_TIMER       = 32;
inline constexpr u8 VEC_SMP_PARCEL_IPI   = 33;
inline constexpr u8 VEC_DEVICE_IRQ_BASE  = 48; // Base vector for external PCIe / MSI-X / IOAPIC interrupts
inline constexpr u8 VEC_DEVICE_IRQ_COUNT = 16;
inline constexpr u8 VEC_SPURIOUS         = 255;

struct [[gnu::packed]] IdtGate64 {
    u16 offset_low{0};
    u16 selector{0};
    u8  ist{0};        // 0 = normal RSP0, 1..7 = dedicated TSS IST stack!
    u8  type_attr{0};  // 0x8E = Present, DPL=0, 64-bit Interrupt Gate (masks IF)
    u16 offset_mid{0};
    u32 offset_high{0};
    u32 reserved{0};
};

static_assert(sizeof(IdtGate64) == 16, "x86_64 IdtGate64 must be 16 bytes");

struct alignas(16) IdtTable {
    IdtGate64 entries[256]{};
};

extern "C" {
void isr_stub_df() noexcept;
void isr_stub_gp() noexcept;
void isr_stub_pf() noexcept;
void isr_stub_timer() noexcept;
void isr_stub_smp_ipi() noexcept;
void isr_stub_irq48() noexcept;
void isr_stub_irq49() noexcept;
void isr_stub_irq50() noexcept;
void isr_stub_irq51() noexcept;
void isr_stub_spurious() noexcept;
}

inline void set_idt_gate(IdtTable& idt, u8 vec, void (*handler)() noexcept, u8 ist_slot = 0) noexcept {
    u64 const addr = reinterpret_cast<u64>(handler);
    idt.entries[vec] = IdtGate64{
        .offset_low  = static_cast<u16>(addr & 0xFFFFULL),
        .selector    = KERNEL_CS,
        .ist         = static_cast<u8>(ist_slot & 0x7u),
        .type_attr   = 0x8Eu, // Present=1, DPL=0, Interrupt Gate (clears IF on entry)
        .offset_mid  = static_cast<u16>((addr >> 16) & 0xFFFFULL),
        .offset_high = static_cast<u32>((addr >> 32) & 0xFFFF'FFFFULL),
        .reserved    = 0u,
    };
}

inline void build_shared_idt(IdtTable& idt) noexcept {
    for (u32 v = 0; v < 256; ++v) {
        set_idt_gate(idt, static_cast<u8>(v), &isr_stub_spurious, 0);
    }
    set_idt_gate(idt, VEC_DOUBLE_FAULT,   &isr_stub_df, 1); // Dedicated IST1 stack!
    set_idt_gate(idt, VEC_GP_FAULT,       &isr_stub_gp, 0);
    set_idt_gate(idt, VEC_PAGE_FAULT,     &isr_stub_pf, 0);
    set_idt_gate(idt, VEC_APIC_TIMER,     &isr_stub_timer, 0);
    set_idt_gate(idt, VEC_SMP_PARCEL_IPI, &isr_stub_smp_ipi, 0);
    set_idt_gate(idt, VEC_DEVICE_IRQ_BASE + 0, &isr_stub_irq48, 0);
    set_idt_gate(idt, VEC_DEVICE_IRQ_BASE + 1, &isr_stub_irq49, 0);
    set_idt_gate(idt, VEC_DEVICE_IRQ_BASE + 2, &isr_stub_irq50, 0);
    set_idt_gate(idt, VEC_DEVICE_IRQ_BASE + 3, &isr_stub_irq51, 0);
}

inline void load_idt_on_current_cpu(IdtTable const& idt) noexcept {
    DescriptorPtr const idtr{
        .limit = sizeof(IdtTable) - 1u,
        .base  = reinterpret_cast<u64>(&idt),
    };
    x86_64_load_idt(&idtr);
}

} // namespace mucore::arch::x86_64
