#pragma once
// ============================================================================
// μCore x86_64 Imperative Shell — Explicit 16550 UART (COM1) Early Console
// ============================================================================

#include "mucore/types.hpp"

namespace mucore::arch::x86_64 {

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

class SerialCom1 {
public:
    static constexpr u16 BASE = 0x3F8;

    static void init() noexcept {
        outb(BASE + 1, 0x00); // Disable UART interrupts
        outb(BASE + 3, 0x80); // Enable DLAB (divisor latch)
        outb(BASE + 0, 0x01); // 115200 baud (divisor = 1)
        outb(BASE + 1, 0x00);
        outb(BASE + 3, 0x03); // 8 bits, no parity, 1 stop bit (8N1)
        outb(BASE + 2, 0xC7); // Enable FIFO, clear TX/RX, 14-byte threshold
        outb(BASE + 4, 0x0B); // IRQs enabled, RTS/DSR set
    }

    static void putc(char c) noexcept {
        if (c == '\n') {
            putc_raw('\r');
        }
        putc_raw(c);
    }

    static void puts(const char* s) noexcept {
        if (s == nullptr) return;
        while (*s != '\0') {
            putc(*s++);
        }
    }

    static void write_u64(u64 val) noexcept {
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

    static void write_hex(u64 val) noexcept {
        static constexpr char HEX[] = "0123456789abcdef";
        puts("0x");
        for (int shift = 60; shift >= 0; shift -= 4) {
            putc(HEX[(val >> shift) & 0xFULL]);
        }
    }

private:
    static void putc_raw(char c) noexcept {
        // Bounded spin to preserve deterministic worst-case progress even if UART absent
        for (u32 spin = 0; spin < 100'000u; ++spin) {
            if ((inb(BASE + 5) & 0x20u) != 0) {
                break;
            }
        }
        outb(BASE + 0, static_cast<u8>(c));
    }
};

} // namespace mucore::arch::x86_64
