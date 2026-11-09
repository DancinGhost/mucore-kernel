#pragma once
// ============================================================================
// μCore Functional Core — "Kineticlets" (Verified Ring-0 Fast-Path Framework)
// ============================================================================
// Bridges the fundamental gap between Ring-0 Performance & Ring-3 Isolation:
//   - Userspace drivers and security-sensitive services keep 95% of their code
//     (complex init, parsing, recovery) isolated in unprivileged Ring 3.
//   - For the 5% of code executed millions of times/sec (IRQ ack/coalescing,
//     descriptor ring steering, telemetry aggregation, fast cache lookups),
//     userspace submits a compact `KineticProgram` into Ring 0.
//   - Unlike monolithic kernel modules (unsafe C++) or unbounded eBPF loops,
//     Kineticlets enforce a Strictly Forward-Branching DAG instruction set:
//       1. Linear O(N) static verification (no verifier state-space explosion).
//       2. Guaranteed termination & zero raw pointer dereferences.
//       3. Static Capability Rights enforcement (`Read`/`Write`/`UrgentRt`).
//       4. Exact DAG Longest-Path WCET derivation (`wcet_ns`) so Hard Real-Time
//          admission control accounts for Ring-0 fast-paths deterministically!
// ============================================================================

#include "mucore/result.hpp"
#include "mucore/types.hpp"
#include "mucore/core/capability.hpp"

namespace mucore::core::kinetic {

inline constexpr usize MAX_KINETIC_INSNS      = 32;
inline constexpr usize NUM_KINETIC_REGS       = 8;
inline constexpr usize NUM_KINETIC_STATE_REGS = 4;
inline constexpr usize NUM_ARENA_WORDS        = 16;

// Nominal deterministic cost per instruction class (nanoseconds on reference core)
inline constexpr u32 COST_ALU_NS    = 2;
inline constexpr u32 COST_MEM_NS    = 6;
inline constexpr u32 COST_BRANCH_NS = 3;
inline constexpr u32 COST_RET_NS    = 2;

enum class KineticOp : u8 {
    Nop        = 0,
    LoadImm    = 1,  // R[dst] = imm32
    Mov        = 2,  // R[dst] = R[src]
    Add        = 3,  // R[dst] = R[dst] + R[src]
    Sub        = 4,  // R[dst] = R[dst] - R[src]
    BitAnd     = 5,  // R[dst] = R[dst] & R[src]
    BitOr      = 6,  // R[dst] = R[dst] | R[src]
    BitXor     = 7,  // R[dst] = R[dst] ^ R[src]
    Shl        = 8,  // R[dst] = R[dst] << (R[src] & 63)
    Shr        = 9,  // R[dst] = R[dst] >> (R[src] & 63)
    LoadState  = 10, // R[dst] = persistent_state[imm32]
    StoreState = 11, // persistent_state[imm32] = R[src]
    LoadArena  = 12, // R[dst] = shared_arena[imm32]  (Requires CapRights::Read)
    StoreArena = 13, // shared_arena[imm32] = R[src]  (Requires CapRights::Write)
    JumpIfEq   = 14, // if (R[dst] == R[src]) pc += imm32 (forward-only: imm32 >= 1)
    JumpIfGt   = 15, // if (R[dst] >  R[src]) pc += imm32 (forward-only: imm32 >= 1)
    Return     = 16, // Terminate with `ReturnVerdict(imm32)` and result `R[0]`
};

// Verdict returned to Ring-0 Dispatcher upon Kineticlet completion
enum class ReturnVerdict : u8 {
    CompleteFastPath    = 0, // Handled 100% in Ring 0 — ZERO context switch to Ring 3!
    EscalateToUserspace = 1, // Cold/error path — forward event to Ring-3 driver/service!
    DropSilent          = 2, // Spurious IRQ / filtered packet — drop with 0 context switch!
    WakeUrgentRt        = 3, // Handled in Ring 0 + trigger immediate RT thread wakeup!
};

// Fixed 8-byte deterministic instruction encoding
struct KineticInsn {
    KineticOp op{KineticOp::Nop};
    u8        dst{0};
    u8        src{0};
    u8        reserved{0};
    u32       imm{0};
};

// Convenience constexpr instruction builders (readable DSL, zero hidden macros!)
namespace dsl {
    [[nodiscard]] constexpr KineticInsn load_imm(u8 dst, u32 imm) noexcept {
        return KineticInsn{KineticOp::LoadImm, dst, 0, 0, imm};
    }
    [[nodiscard]] constexpr KineticInsn mov(u8 dst, u8 src) noexcept {
        return KineticInsn{KineticOp::Mov, dst, src, 0, 0};
    }
    [[nodiscard]] constexpr KineticInsn add(u8 dst, u8 src) noexcept {
        return KineticInsn{KineticOp::Add, dst, src, 0, 0};
    }
    [[nodiscard]] constexpr KineticInsn sub(u8 dst, u8 src) noexcept {
        return KineticInsn{KineticOp::Sub, dst, src, 0, 0};
    }
    [[nodiscard]] constexpr KineticInsn bit_and(u8 dst, u8 src) noexcept {
        return KineticInsn{KineticOp::BitAnd, dst, src, 0, 0};
    }
    [[nodiscard]] constexpr KineticInsn bit_or(u8 dst, u8 src) noexcept {
        return KineticInsn{KineticOp::BitOr, dst, src, 0, 0};
    }
    [[nodiscard]] constexpr KineticInsn load_state(u8 dst, u32 slot) noexcept {
        return KineticInsn{KineticOp::LoadState, dst, 0, 0, slot};
    }
    [[nodiscard]] constexpr KineticInsn store_state(u32 slot, u8 src) noexcept {
        return KineticInsn{KineticOp::StoreState, 0, src, 0, slot};
    }
    [[nodiscard]] constexpr KineticInsn load_arena(u8 dst, u32 word_idx) noexcept {
        return KineticInsn{KineticOp::LoadArena, dst, 0, 0, word_idx};
    }
    [[nodiscard]] constexpr KineticInsn store_arena(u32 word_idx, u8 src) noexcept {
        return KineticInsn{KineticOp::StoreArena, 0, src, 0, word_idx};
    }
    [[nodiscard]] constexpr KineticInsn jump_if_eq(u8 lhs, u8 rhs, u32 forward_skip) noexcept {
        return KineticInsn{KineticOp::JumpIfEq, lhs, rhs, 0, forward_skip};
    }
    [[nodiscard]] constexpr KineticInsn jump_if_gt(u8 lhs, u8 rhs, u32 forward_skip) noexcept {
        return KineticInsn{KineticOp::JumpIfGt, lhs, rhs, 0, forward_skip};
    }
    [[nodiscard]] constexpr KineticInsn ret(ReturnVerdict verdict) noexcept {
        return KineticInsn{KineticOp::Return, 0, 0, 0, static_cast<u32>(verdict)};
    }
} // namespace dsl

struct KineticProgram {
    KineticInsn insns[MAX_KINETIC_INSNS]{};
    u32         len{0};
};

// Static Verification Proof Certificate emitted before Ring-0 installation
struct VerifyReport {
    u32  max_instructions{0}; // Exact longest DAG path instruction count
    u32  wcet_ns{0};          // Exact Worst-Case Execution Time bound for RT admission!
    u16  required_rights{0};  // Rights statically exercised by this program
    bool accesses_arena{false};
};

// Installed Ring-0 Kineticlet Instance
struct KineticSlotState {
    bool           installed{false};
    KineticId      id{};
    DomainId       owner{};
    KineticProgram program{};
    VerifyReport   proof{};
    u64            persistent_state[NUM_KINETIC_STATE_REGS]{};
    u64            invocations{0};
    u64            fast_completions{0};
    u64            escalations{0};
};

// Execution Input Context (passed by value — pure & side-effect free!)
struct KineticInput {
    u64 arg0{0}; // e.g., FluxOpcode or IRQ status register snapshot
    u64 arg1{0}; // offset / payload word 0
    u64 arg2{0}; // length / payload word 1
    u64 arg3{0}; // aux_param
};

// Execution Output (explicit delta on persistent state & shared arena)
struct KineticOutput {
    ReturnVerdict verdict{ReturnVerdict::EscalateToUserspace};
    u64           return_value{0};
    u32           steps_executed{0};
    u64           next_state[NUM_KINETIC_STATE_REGS]{};
};

// ============================================================================
// PURE STATIC VERIFIER (O(N) DAG Termination, Bounds, Capability & WCET Proof)
// ============================================================================

[[nodiscard]] constexpr u32 insn_cost_ns(KineticOp op) noexcept {
    switch (op) {
        case KineticOp::LoadState:
        case KineticOp::StoreState:
        case KineticOp::LoadArena:
        case KineticOp::StoreArena:
            return COST_MEM_NS;
        case KineticOp::JumpIfEq:
        case KineticOp::JumpIfGt:
            return COST_BRANCH_NS;
        case KineticOp::Return:
            return COST_RET_NS;
        default:
            return COST_ALU_NS;
    }
}

[[nodiscard]] constexpr Result<VerifyReport, Error> verify_program(
    KineticProgram const& prog,
    u16                   granted_rights
) noexcept {
    if (prog.len == 0 || prog.len > MAX_KINETIC_INSNS) {
        return Result<VerifyReport, Error>::err(Error::VerificationFailed);
    }

    // Last instruction MUST be an unconditional `Return` so execution can never fall off end!
    if (prog.insns[prog.len - 1].op != KineticOp::Return) {
        return Result<VerifyReport, Error>::err(Error::VerificationFailed);
    }

    u16  needed_rights = cap::CapRights::ExecuteRing0;
    bool uses_arena    = false;

    // Pass 1: Validate every instruction's register indices, memory bounds, rights & DAG jumps
    for (u32 pc = 0; pc < prog.len; ++pc) {
        KineticInsn const& insn = prog.insns[pc];

        if (insn.dst >= NUM_KINETIC_REGS || insn.src >= NUM_KINETIC_REGS) {
            return Result<VerifyReport, Error>::err(Error::VerificationFailed);
        }

        switch (insn.op) {
            case KineticOp::Nop:
            case KineticOp::LoadImm:
            case KineticOp::Mov:
            case KineticOp::Add:
            case KineticOp::Sub:
            case KineticOp::BitAnd:
            case KineticOp::BitOr:
            case KineticOp::BitXor:
            case KineticOp::Shl:
            case KineticOp::Shr:
                break;

            case KineticOp::LoadState:
            case KineticOp::StoreState:
                if (insn.imm >= NUM_KINETIC_STATE_REGS) {
                    return Result<VerifyReport, Error>::err(Error::VerificationFailed);
                }
                break;

            case KineticOp::LoadArena:
                if (insn.imm >= NUM_ARENA_WORDS) {
                    return Result<VerifyReport, Error>::err(Error::VerificationFailed);
                }
                needed_rights |= cap::CapRights::Read;
                uses_arena = true;
                break;

            case KineticOp::StoreArena:
                if (insn.imm >= NUM_ARENA_WORDS) {
                    return Result<VerifyReport, Error>::err(Error::VerificationFailed);
                }
                needed_rights |= cap::CapRights::Write;
                uses_arena = true;
                break;

            case KineticOp::JumpIfEq:
            case KineticOp::JumpIfGt: {
                // Strictly forward non-zero jump: guarantees DAG (zero cycles -> 100% termination!)
                if (insn.imm == 0) {
                    return Result<VerifyReport, Error>::err(Error::VerificationFailed);
                }
                u64 const target = static_cast<u64>(pc) + 1ULL + static_cast<u64>(insn.imm);
                if (target >= prog.len) {
                    return Result<VerifyReport, Error>::err(Error::VerificationFailed);
                }
                break;
            }

            case KineticOp::Return: {
                if (insn.imm > static_cast<u32>(ReturnVerdict::WakeUrgentRt)) {
                    return Result<VerifyReport, Error>::err(Error::VerificationFailed);
                }
                if (static_cast<ReturnVerdict>(insn.imm) == ReturnVerdict::WakeUrgentRt) {
                    needed_rights |= cap::CapRights::UrgentRt;
                }
                break;
            }

            default:
                return Result<VerifyReport, Error>::err(Error::VerificationFailed);
        }
    }

    // Verify caller holds all capability rights exercised by the bytecode
    if ((granted_rights & needed_rights) != needed_rights) {
        return Result<VerifyReport, Error>::err(Error::InsufficientRights);
    }

    // Pass 2: Exact Backward Dynamic Programming on DAG for WCET & Max Steps!
    u32 dp_cost[MAX_KINETIC_INSNS]{};
    u32 dp_steps[MAX_KINETIC_INSNS]{};

    for (u32 rev = 0; rev < prog.len; ++rev) {
        u32 const pc = prog.len - 1 - rev;
        KineticInsn const& insn = prog.insns[pc];
        u32 const self_cost = insn_cost_ns(insn.op);

        if (insn.op == KineticOp::Return) {
            dp_cost[pc]  = self_cost;
            dp_steps[pc] = 1;
        } else if (insn.op == KineticOp::JumpIfEq || insn.op == KineticOp::JumpIfGt) {
            u32 const fallthrough = pc + 1;
            u32 const branch_tgt  = pc + 1 + insn.imm;

            u32 const max_rem_cost  = (dp_cost[fallthrough] > dp_cost[branch_tgt])
                                        ? dp_cost[fallthrough] : dp_cost[branch_tgt];
            u32 const max_rem_steps = (dp_steps[fallthrough] > dp_steps[branch_tgt])
                                        ? dp_steps[fallthrough] : dp_steps[branch_tgt];

            dp_cost[pc]  = self_cost + max_rem_cost;
            dp_steps[pc] = 1 + max_rem_steps;
        } else {
            dp_cost[pc]  = self_cost + dp_cost[pc + 1];
            dp_steps[pc] = 1 + dp_steps[pc + 1];
        }
    }

    return Result<VerifyReport, Error>::ok(VerifyReport{
        .max_instructions = dp_steps[0],
        .wcet_ns          = dp_cost[0],
        .required_rights  = needed_rights,
        .accesses_arena   = uses_arena,
    });
}

// ============================================================================
// PURE DETERMINISTIC RING-0 INTERPRETER (Bounded Fuel Defense-in-Depth)
// ============================================================================

[[nodiscard]] constexpr Result<KineticOutput, Error> execute_verified(
    KineticProgram const& prog,
    KineticInput const&   input,
    u64 const             current_state[NUM_KINETIC_STATE_REGS],
    u64                   arena_words[NUM_ARENA_WORDS]
) noexcept {
    u64 regs[NUM_KINETIC_REGS]{
        input.arg0, input.arg1, input.arg2, input.arg3, 0ULL, 0ULL, 0ULL, 0ULL
    };

    KineticOutput out{};
    for (usize i = 0; i < NUM_KINETIC_STATE_REGS; ++i) {
        out.next_state[i] = current_state[i];
    }

    u32 pc   = 0;
    u32 fuel = MAX_KINETIC_INSNS; // Hardware/bug defense-in-depth fuel bound

    while (pc < prog.len && fuel > 0) {
        --fuel;
        ++out.steps_executed;
        KineticInsn const& insn = prog.insns[pc];

        switch (insn.op) {
            case KineticOp::Nop:
                ++pc;
                break;
            case KineticOp::LoadImm:
                regs[insn.dst] = static_cast<u64>(insn.imm);
                ++pc;
                break;
            case KineticOp::Mov:
                regs[insn.dst] = regs[insn.src];
                ++pc;
                break;
            case KineticOp::Add:
                regs[insn.dst] += regs[insn.src];
                ++pc;
                break;
            case KineticOp::Sub:
                regs[insn.dst] -= regs[insn.src];
                ++pc;
                break;
            case KineticOp::BitAnd:
                regs[insn.dst] &= regs[insn.src];
                ++pc;
                break;
            case KineticOp::BitOr:
                regs[insn.dst] |= regs[insn.src];
                ++pc;
                break;
            case KineticOp::BitXor:
                regs[insn.dst] ^= regs[insn.src];
                ++pc;
                break;
            case KineticOp::Shl:
                regs[insn.dst] <<= (regs[insn.src] & 63ULL);
                ++pc;
                break;
            case KineticOp::Shr:
                regs[insn.dst] >>= (regs[insn.src] & 63ULL);
                ++pc;
                break;
            case KineticOp::LoadState:
                regs[insn.dst] = out.next_state[insn.imm & (NUM_KINETIC_STATE_REGS - 1)];
                ++pc;
                break;
            case KineticOp::StoreState:
                out.next_state[insn.imm & (NUM_KINETIC_STATE_REGS - 1)] = regs[insn.src];
                ++pc;
                break;
            case KineticOp::LoadArena:
                if (arena_words != nullptr) {
                    regs[insn.dst] = arena_words[insn.imm & (NUM_ARENA_WORDS - 1)];
                }
                ++pc;
                break;
            case KineticOp::StoreArena:
                if (arena_words != nullptr) {
                    arena_words[insn.imm & (NUM_ARENA_WORDS - 1)] = regs[insn.src];
                }
                ++pc;
                break;
            case KineticOp::JumpIfEq:
                pc = (regs[insn.dst] == regs[insn.src]) ? (pc + 1 + insn.imm) : (pc + 1);
                break;
            case KineticOp::JumpIfGt:
                pc = (regs[insn.dst] > regs[insn.src]) ? (pc + 1 + insn.imm) : (pc + 1);
                break;
            case KineticOp::Return:
                out.verdict      = static_cast<ReturnVerdict>(insn.imm);
                out.return_value = regs[0];
                return Result<KineticOutput, Error>::ok(out);
        }
    }

    return Result<KineticOutput, Error>::err(Error::StepBudgetExceeded);
}

} // namespace mucore::core::kinetic
