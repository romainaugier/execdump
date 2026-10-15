/*
 * Register files: one entry per full register, sub-registers are views on them (al is rax[0..8])
 */

use execdump_core::disasm::Architecture;

/// Index of a full register in the register file of an architecture
pub type Reg = usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegInfo {
    pub name: &'static str,
    pub bits: u32,
}

/// A register as used by an instruction: a view on a full register
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegRef {
    pub reg: Reg,
    pub offset: u32,
    pub bits: u32,
}

const X86_64_GPRS: [&str; 16] = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
const X86_GPRS: [&str; 8] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
const XMMS: [&str; 16] = ["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"];
const X86_FLAGS: [&str; 6] = ["cf", "pf", "zf", "sf", "of", "df"];
const AARCH64_FLAGS: [&str; 4] = ["n", "z", "c", "v"];

#[derive(Clone, Debug)]
pub struct RegisterFile {
    pub arch: Architecture,
    pub regs: Vec<RegInfo>,
}

impl RegisterFile {
    pub fn new(arch: Architecture) -> Self {
        let mut regs = Vec::new();

        match arch {
            Architecture::X86_64 => {
                regs.extend(X86_64_GPRS.iter().map(|&name| RegInfo { name, bits: 64 }));
                regs.extend(XMMS.iter().map(|&name| RegInfo { name, bits: 128 }));
                regs.extend(X86_FLAGS.iter().map(|&name| RegInfo { name, bits: 1 }));
            }
            Architecture::X86 => {
                regs.extend(X86_GPRS.iter().map(|&name| RegInfo { name, bits: 32 }));
                regs.extend(XMMS[..8].iter().map(|&name| RegInfo { name, bits: 128 }));
                regs.extend(X86_FLAGS.iter().map(|&name| RegInfo { name, bits: 1 }));
            }
            Architecture::Aarch64 => {
                const X: [&str; 31] = [
                    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16",
                    "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
                ];
                const V: [&str; 32] = [
                    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16",
                    "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
                ];

                regs.extend(X.iter().map(|&name| RegInfo { name, bits: 64 }));
                regs.push(RegInfo { name: "sp", bits: 64 });
                regs.extend(V.iter().map(|&name| RegInfo { name, bits: 128 }));
                regs.extend(AARCH64_FLAGS.iter().map(|&name| RegInfo { name, bits: 1 }));
            }
            Architecture::Unsupported => {}
        }

        return RegisterFile { arch, regs };
    }

    pub fn index(&self, name: &str) -> Option<Reg> {
        return self.regs.iter().position(|r| r.name == name);
    }

    /// Full register, panics on unknown names (only used with the names of the tables above)
    pub fn reg(&self, name: &str) -> Reg {
        return self.index(name).unwrap_or_else(|| panic!("unknown register {}", name));
    }

    /// Name of the low bits of a register, when the instructions name them (eax, r8w, al, w0)
    pub fn view_name(&self, reg: Reg, bits: u32) -> Option<String> {
        let name = self.regs.get(reg)?.name;

        return match self.arch {
            Architecture::X86 | Architecture::X86_64 => {
                if let Some(number) = name.strip_prefix('r').filter(|n| n.parse::<u32>().is_ok()) {
                    let suffix = match bits {
                        32 => "d",
                        16 => "w",
                        8 => "b",
                        _ => return None,
                    };
                    return Some(format!("r{}{}", number, suffix));
                }

                let base = name.trim_start_matches(['r', 'e']);
                match bits {
                    32 if self.arch == Architecture::X86_64 => Some(format!("e{}", base)),
                    16 => Some(base.to_string()),
                    8 if base.ends_with('x') => Some(format!("{}l", &base[..1])),
                    8 => Some(format!("{}l", base)),
                    _ => None,
                }
            }
            Architecture::Aarch64 => match (name.as_bytes().first(), bits) {
                (Some(b'x'), 32) => Some(format!("w{}", &name[1..])),
                (Some(b'v'), 64) => Some(format!("d{}", &name[1..])),
                (Some(b'v'), 32) => Some(format!("s{}", &name[1..])),
                _ => None,
            },
            Architecture::Unsupported => None,
        };
    }

    pub fn full(&self, reg: Reg) -> RegRef {
        return RegRef { reg, offset: 0, bits: self.regs[reg].bits };
    }

    /// Resolves the Capstone name of a register (al, r8d, w3, d0...) to a view on a full register
    pub fn resolve(&self, name: &str) -> Option<RegRef> {
        match self.arch {
            Architecture::X86 | Architecture::X86_64 => self.resolve_x86(name),
            Architecture::Aarch64 => self.resolve_aarch64(name),
            Architecture::Unsupported => None,
        }
    }

    fn view(&self, full: &str, offset: u32, bits: u32) -> Option<RegRef> {
        return self.index(full).map(|reg| RegRef { reg, offset, bits });
    }

    fn resolve_x86(&self, name: &str) -> Option<RegRef> {
        let wide = self.arch == Architecture::X86_64;
        let gpr = |i: usize| if wide { X86_64_GPRS[i] } else { X86_GPRS[i] };

        if let Some(reg) = self.index(name) {
            return Some(self.full(reg));
        }

        const LEGACY: [(&str, &str, &str, &str); 8] = [
            ("eax", "ax", "al", "ah"),
            ("ecx", "cx", "cl", "ch"),
            ("edx", "dx", "dl", "dh"),
            ("ebx", "bx", "bl", "bh"),
            ("esp", "sp", "spl", ""),
            ("ebp", "bp", "bpl", ""),
            ("esi", "si", "sil", ""),
            ("edi", "di", "dil", ""),
        ];

        for (i, (r32, r16, r8, high)) in LEGACY.iter().enumerate() {
            let full = gpr(i);

            match name {
                n if n == *r32 => return self.view(full, 0, 32),
                n if n == *r16 => return self.view(full, 0, 16),
                n if n == *r8 => return self.view(full, 0, 8),
                n if !high.is_empty() && n == *high => return self.view(full, 8, 8),
                _ => {}
            }
        }

        // r8d, r8w, r8b
        if let Some(rest) = name.strip_prefix('r') {
            for (suffix, bits) in [("d", 32), ("w", 16), ("b", 8)] {
                if let Some(number) = rest.strip_suffix(suffix) {
                    if number.parse::<u32>().is_ok() {
                        return self.view(&format!("r{}", number), 0, bits);
                    }
                }
            }
        }

        // ymm and zmm registers are not modeled, their low lanes are the xmm registers
        if let Some(number) = name.strip_prefix("ymm").or(name.strip_prefix("zmm")) {
            return self.view(&format!("xmm{}", number), 0, 128);
        }

        return None;
    }

    fn resolve_aarch64(&self, name: &str) -> Option<RegRef> {
        if let Some(reg) = self.index(name) {
            return Some(self.full(reg));
        }

        match name {
            "wsp" => return self.view("sp", 0, 32),
            "fp" => return self.view("x29", 0, 64),
            "lr" => return self.view("x30", 0, 64),
            _ => {}
        }

        let (prefix, number) = name.split_at(1);
        let number: u32 = number.parse().ok()?;

        let (full, bits) = match prefix {
            "w" => (format!("x{}", number), 32),
            "q" => (format!("v{}", number), 128),
            "d" => (format!("v{}", number), 64),
            "s" => (format!("v{}", number), 32),
            "h" => (format!("v{}", number), 16),
            "b" => (format!("v{}", number), 8),
            _ => return None,
        };

        return self.view(&full, 0, bits);
    }
}

/// Calling convention: where the arguments and the return values are
#[derive(Clone, Debug)]
pub struct Abi {
    pub int_args: Vec<Reg>,
    pub float_args: Vec<Reg>,
    /// Integer and floating point arguments share their slots (Win64)
    pub positional: bool,
    pub int_ret: Reg,
    /// High half of the integer results twice as wide as a register (rdx of __int128 and of the Rust slices, edx of
    /// long long on x86)
    pub int_ret_high: Option<Reg>,
    pub float_ret: Reg,
    pub stack_pointer: Reg,
    /// Offset of the first stack argument from the stack pointer at the function entry
    pub stack_args: i64,
    pub slot_size: i64,
    /// Size of the return address pushed by a call (0 when it is kept in a register)
    pub return_address: i64,
    /// Registers a callee must preserve
    pub callee_saved: Vec<Reg>,
}

impl Abi {
    /// System V on Unix-likes, Microsoft x64 on Windows, AAPCS64 on aarch64, cdecl on x86
    pub fn new(regs: &RegisterFile, windows: bool) -> Self {
        let r = |names: &[&str]| -> Vec<Reg> { names.iter().map(|n| regs.reg(n)).collect() };

        match regs.arch {
            Architecture::X86_64 if windows => Abi {
                int_args: r(&["rcx", "rdx", "r8", "r9"]),
                float_args: r(&["xmm0", "xmm1", "xmm2", "xmm3"]),
                positional: true,
                int_ret: regs.reg("rax"),
                int_ret_high: None,
                float_ret: regs.reg("xmm0"),
                stack_pointer: regs.reg("rsp"),
                stack_args: 40,
                slot_size: 8,
                return_address: 8,
                callee_saved: r(&["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"]),
            },
            Architecture::X86_64 => Abi {
                int_args: r(&["rdi", "rsi", "rdx", "rcx", "r8", "r9"]),
                float_args: r(&["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"]),
                positional: false,
                int_ret: regs.reg("rax"),
                int_ret_high: Some(regs.reg("rdx")),
                float_ret: regs.reg("xmm0"),
                stack_pointer: regs.reg("rsp"),
                stack_args: 8,
                slot_size: 8,
                return_address: 8,
                callee_saved: r(&["rbx", "rbp", "r12", "r13", "r14", "r15"]),
            },
            Architecture::X86 => Abi {
                int_args: Vec::new(),
                float_args: Vec::new(),
                positional: false,
                int_ret: regs.reg("eax"),
                int_ret_high: Some(regs.reg("edx")),
                float_ret: regs.reg("xmm0"),
                stack_pointer: regs.reg("esp"),
                stack_args: 4,
                slot_size: 4,
                return_address: 4,
                callee_saved: r(&["ebx", "ebp", "esi", "edi"]),
            },
            _ => Abi {
                int_args: r(&["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]),
                float_args: r(&["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"]),
                positional: false,
                int_ret: regs.reg("x0"),
                int_ret_high: Some(regs.reg("x1")),
                float_ret: regs.reg("v0"),
                stack_pointer: regs.reg("sp"),
                stack_args: 0,
                slot_size: 8,
                return_address: 0,
                // x30 holds the return address of the function, v8 to v15 keep their low 64 bits
                callee_saved: r(&["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15"]),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_views() {
        let regs = RegisterFile::new(Architecture::X86_64);
        let rax = regs.reg("rax");

        assert_eq!(regs.resolve("eax"), Some(RegRef { reg: rax, offset: 0, bits: 32 }));
        assert_eq!(regs.resolve("ah"), Some(RegRef { reg: rax, offset: 8, bits: 8 }));
        assert_eq!(regs.resolve("r10b"), Some(RegRef { reg: regs.reg("r10"), offset: 0, bits: 8 }));
        assert_eq!(regs.resolve("sil"), Some(RegRef { reg: regs.reg("rsi"), offset: 0, bits: 8 }));
        assert_eq!(regs.resolve("xmm3").map(|r| r.bits), Some(128));
    }

    #[test]
    fn aarch64_views() {
        let regs = RegisterFile::new(Architecture::Aarch64);

        assert_eq!(regs.resolve("w3"), Some(RegRef { reg: regs.reg("x3"), offset: 0, bits: 32 }));
        assert_eq!(regs.resolve("d1"), Some(RegRef { reg: regs.reg("v1"), offset: 0, bits: 64 }));
        assert_eq!(regs.resolve("fp"), Some(regs.full(regs.reg("x29"))));
    }
}
