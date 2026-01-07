use capstone::Insn;

pub fn is_padding_instruction(insn: &Insn) -> bool {
    match (insn.mnemonic(), insn.op_str()) {
        (Some("add"), Some("byte ptr [rax], al")) => true,
        (Some("nop"), _) => true,
        (Some("int3"), _) => true,
        (Some("ud2"), _) => true,
        (Some("hlt"), _) => true,
        (Some("mov"), Some("eax, eax")) => true,
        (Some("sub"), Some("rsp, 0")) => true,
        _ => false,
    }
}
