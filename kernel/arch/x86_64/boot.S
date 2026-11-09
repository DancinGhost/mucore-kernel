/* ============================================================================
 * μCore (mucore-kernel) — x86_64 SMP Entry, Per-CPU `swapgs` & IDT Stubs
 * ============================================================================
 * Explicit Imperative Shell boundary:
 *   - Multi-core safe `x86_64_syscall_entry` via `swapgs` + `%gs:0` / `%gs:8`.
 *   - 16-byte SysV ABI stack-aligned 64-bit Exception, APIC Timer & SMP IPI
 *     trampolines with Ring-3 conditional `swapgs`.
 * ============================================================================ */

.section .bss
.align 4096
.global boot_stack_bottom
boot_stack_bottom:
    .skip 32768
.global boot_stack_top
boot_stack_top:

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
 * GDT / TSS & IDT Loaders
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

    movzwq  %si, %rsi
    pushq   %rsi
    leaq    .Lreload_cs_done(%rip), %rax
    pushq   %rax
    lretq

.Lreload_cs_done:
    ltr     %cx
    retq
.size x86_64_load_gdt_and_tss, . - x86_64_load_gdt_and_tss

.global x86_64_load_idt
.type x86_64_load_idt, @function
x86_64_load_idt:
    lidt    (%rdi)
    retq
.size x86_64_load_idt, . - x86_64_load_idt

/* ----------------------------------------------------------------------------
 * Multi-Core Safe `SYSCALL` / `SYSRETQ` Trampoline (`PerCpuArchBlock` in `%gs`)
 *   %gs:0  = kernel_rsp
 *   %gs:8  = user_rsp_scratch
 *   %gs:16 = cpu_index (u32)
 * ---------------------------------------------------------------------------- */
.global x86_64_syscall_entry
.type x86_64_syscall_entry, @function
x86_64_syscall_entry:
    swapgs
    movq    %rsp, %gs:8         /* Save Ring-3 user %rsp per-CPU */
    movq    %gs:0, %rsp         /* Switch to per-CPU Ring-0 stack */

    pushq   %rcx                /* User return RIP */
    pushq   %r11                /* User RFLAGS */
    pushq   %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    /* SysV C ABI: (op=%rdi, arg0=%rsi, arg1=%rdx, arg2=%rcx, cpu_id=%r8d) */
    movq    %r10, %rcx
    movl    %gs:16, %r8d
    call    mucore_syscall_entry_c

    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    popq    %r11
    popq    %rcx

    movq    %gs:8, %rsp
    swapgs
    sysretq
.size x86_64_syscall_entry, . - x86_64_syscall_entry

/* ----------------------------------------------------------------------------
 * Common 64-Bit ISR Save/Restore Macro (Conditional `swapgs` if from Ring 3!)
 * Stack on entry (after error_code push):
 *   [rsp +  0] = error_code
 *   [rsp +  8] = RIP
 *   [rsp + 16] = CS  (CS & 3 == 3 iff interrupted Ring 3!)
 * ---------------------------------------------------------------------------- */
.macro ISR_DISPATCH name, vec_num, has_errcode, c_handler
.global \name
.type \name, @function
\name:
.if \has_errcode == 0
    pushq   $0
.endif
    testb   $3, 16(%rsp)
    jz      1f
    swapgs
1:
    pushq   %rax
    pushq   %rcx
    pushq   %rdx
    pushq   %rsi
    pushq   %rdi
    pushq   %r8
    pushq   %r9
    pushq   %r10
    pushq   %r11
    pushq   %rbp
    movq    %rsp, %rbp
    andq    $-16, %rsp          /* Guarantee 16-byte SysV ABI stack alignment! */

    movl    $\vec_num, %edi
    movq    80(%rbp), %rsi      /* error_code */
    movl    %gs:16, %edx        /* logical cpu_index */
    call    \c_handler

    movq    %rbp, %rsp
    popq    %rbp
    popq    %r11
    popq    %r10
    popq    %r9
    popq    %r8
    popq    %rdi
    popq    %rsi
    popq    %rdx
    popq    %rcx
    popq    %rax

    testb   $3, 16(%rsp)
    jz      2f
    swapgs
2:
    addq    $8, %rsp            /* Pop error_code */
    iretq
.size \name, . - \name
.endm

ISR_DISPATCH isr_stub_df,       8,  1, mucore_exception_handler_c
ISR_DISPATCH isr_stub_gp,       13, 1, mucore_exception_handler_c
ISR_DISPATCH isr_stub_pf,       14, 1, mucore_exception_handler_c
ISR_DISPATCH isr_stub_timer,    32, 0, mucore_irq_vector_c
ISR_DISPATCH isr_stub_smp_ipi,  33, 0, mucore_irq_vector_c
ISR_DISPATCH isr_stub_spurious, 255, 0, mucore_irq_vector_c

.section .note.GNU-stack, "", @progbits
