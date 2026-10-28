// SPDX-License-Identifier: Apache-2.0
/*
 * The calling conventions of Go
 */

use crate::lift::regs::{Abi, Reg, RegisterFile};

use execdump_core::disasm::Architecture;

/// The register ABI of Go (ABIInternal, Go 1.17 on x86_64 and 1.18 on aarch64), on every system: the results in
/// the registers of the arguments (a string is its pointer then its length, an error its type then its data, after
/// the other results), every other register clobbered by calls but the ones the runtime keeps (the goroutine in r14 or
/// x28, the zero xmm15, the frame pointer)
pub fn register_abi(regs: &RegisterFile) -> Option<Abi> {
    let r = |names: &[&str]| -> Vec<Reg> { names.iter().map(|n| regs.reg(n)).collect() };

    return match regs.arch {
        Architecture::X86_64 => Some(Abi {
            int_args: r(&["rax", "rbx", "rcx", "rdi", "rsi", "r8", "r9", "r10", "r11"]),
            float_args: r(&["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14"]),
            positional: false,
            ordered_args: true,
            int_ret: regs.reg("rax"),
            int_ret_high: None,
            float_ret: regs.reg("xmm0"),
            stack_pointer: regs.reg("rsp"),
            stack_args: 8,
            slot_size: 8,
            return_address: 8,
            callee_saved: r(&["rbp", "r14", "r15", "xmm15"]),
            runtime: vec![(regs.reg("r14"), "runtime_g")],
            zeroed: r(&["xmm15"]),
            stack_results: false,
            register_results: true,
            extra_params: Vec::new(),
            extra_results: Vec::new(),
        }),
        Architecture::Aarch64 => Some(Abi {
            int_args: r(&["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15"]),
            float_args: r(&["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15"]),
            positional: false,
            ordered_args: true,
            int_ret: regs.reg("x0"),
            int_ret_high: None,
            float_ret: regs.reg("v0"),
            stack_pointer: regs.reg("sp"),
            stack_args: 8,
            slot_size: 8,
            return_address: 0,
            callee_saved: r(&["x28", "x29", "x30"]),
            runtime: vec![(regs.reg("x28"), "runtime_g")],
            zeroed: Vec::new(),
            stack_results: false,
            register_results: true,
            extra_params: Vec::new(),
            extra_results: Vec::new(),
        }),
        _ => None,
    };
}

/// The stack ABI of Go (ABI0: before 1.17 on x86_64 and 1.18 on aarch64, always on x86, and the functions written
/// in assembly): the arguments then the results in the slots above the return address, every register clobbered
/// by calls but the frame pointer (and the goroutine in x28 on aarch64). The functions read no register, but the
/// closures their context (rdx, x26) and the helpers of the assembly of the runtime the registers they are given
/// (runtime.cmpbody): any of them may be a parameter.
pub fn stack_abi(regs: &RegisterFile) -> Abi {
    let r = |names: &[&str]| -> Vec<Reg> { names.iter().map(|n| regs.reg(n)).collect() };
    let mut abi = Abi::new(regs, false);

    abi.float_args = Vec::new();
    abi.extra_params = Vec::new();
    abi.extra_results = Vec::new();
    abi.ordered_args = false;
    abi.int_ret_high = None;
    abi.stack_results = true;

    match regs.arch {
        Architecture::X86_64 => {
            abi.int_args = r(&["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]);
            abi.callee_saved = vec![regs.reg("rbp")];
        }
        Architecture::X86 => {
            abi.int_args = r(&["eax", "ebx", "ecx", "edx", "esi", "edi"]);
            abi.callee_saved = vec![regs.reg("ebp")];
        }
        Architecture::Aarch64 => {
            abi.int_args = (0..28).filter(|&i| i != 18).map(|i| regs.reg(&format!("x{}", i))).collect();
            // The caller keeps the slot of the return address the callee saves its link register to
            abi.stack_args = 8;
            abi.callee_saved = vec![regs.reg("x28"), regs.reg("x29")];
            abi.runtime = vec![(regs.reg("x28"), "runtime_g")];
        }
        Architecture::Unsupported => {}
    }

    return abi;
}
