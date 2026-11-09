/* ============================================================================
 * μCore (mucore-kernel) — x86_64 64-Bit Long Mode Entry & Fast SYSCALL Stubs
 * ============================================================================
 * Explicit Imperative Shell boundary:
 *   - Zero hidden global C++ constructors (`.init_array` is forbidden by linker).
 *   - Deterministic 32 KiB aligned Ring-0 bootstrap stack & IST1 fault stack.
 *   - Fast `SYSCALL` / `SYSRETQ` cold-path & doorbell trap trampoline.
 * ============================================================================ */

.section .bss
.align 4096
.global boot_stack_bottom
boot_stack_bottom:
    .skip 32768
.global boot_stack_top
boot_stack_top:

.align 4096
.global ist1_stack_bottom
ist1_stack_bottom:
    .skip 16384
.global ist1_stack_top
ist1_stack_top:

/* Per-CPU Ring-0 / Ring-3 RSP scratch slot for fast SYSCALL entry */
.section .data
.align 64
.global cpu0_kernel_rsp
cpu0_kernel_rsp:
    .quad boot_stack_top
cpu0_user_rsp_scratch:
    .quad 0

.section .text.boot, "ax", @progbits
.global _start
.type _start, @function
_start:
    cli
    cld
    xorq    %rbp, %rbp
    leaq    boot_stack_top(%rip), %rsp
    call    kmain

.Lhalt_forever:
    cli
    hlt
    jmp     .Lhalt_forever
.size _start, . - _start

/* ----------------------------------------------------------------------------
 * void x86_64_load_gdt_and_tss(
 *     DescriptorPtr const* gdtr [%rdi],
 *     u16 cs_sel [%rsi],
 *     u16 ds_sel [%rdx],
 *     u16 tss_sel [%rcx]
 * )
 * ---------------------------------------------------------------------------- */
.section .text, "ax", @progbits
.global x86_64_load_gdt_and_tss
.type x86_64_load_gdt_and_tss, @function
x86_64_load_gdt_and_tss:
    lgdt    (%rdi)
    movw    %dx, %ds
    movw    %dx, %es
    movw    %dx, %ss
    xorl    %eax, %eax
    movw    %ax, %fs
    movw    %ax, %gs

    /* Reload 64-bit CS via lretq */
    movzwq  %si, %rsi
    pushq   %rsi
    leaq    .Lreload_cs_done(%rip), %rax
    pushq   %rax
    lretq

.Lreload_cs_done:
    ltr     %cx
    retq
.size x86_64_load_gdt_and_tss, . - x86_64_load_gdt_and_tss

/* ----------------------------------------------------------------------------
 * Fast Ring-3 -> Ring-0 `SYSCALL` Entry Stub (Used ONLY for Cold Paths &
 * Quiescent Doorbells; Hot Paths run 100% Syscall-Free via Flux + Kineticlets!)
 *   On entry from `syscall`:
 *     %rcx = User RIP, %r11 = User RFLAGS
 *     %rdi = op, %rsi = arg0, %rdx = arg1, %r10 = arg2
 * ---------------------------------------------------------------------------- */
.global x86_64_syscall_entry
.type x86_64_syscall_entry, @function
x86_64_syscall_entry:
    /* Save user RSP and pivot to deterministic Ring-0 kernel stack */
    movq    %rsp, cpu0_user_rsp_scratch(%rip)
    movq    cpu0_kernel_rsp(%rip), %rsp

    pushq   %rcx                /* User return RIP */
    pushq   %r11                /* User RFLAGS */
    pushq   %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    /* Move 4th syscall ABI arg (%r10) into SysV C ABI 4th arg (%rcx) */
    movq    %r10, %rcx
    call    mucore_syscall_entry_c

    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    popq    %r11                /* Restore User RFLAGS */
    popq    %rcx                /* Restore User RIP */

    movq    cpu0_user_rsp_scratch(%rip), %rsp
    sysretq
.size x86_64_syscall_entry, . - x86_64_syscall_entry

/* Explicitly mark stack non-executable */
.section .note.GNU-stack, "", @progbits
