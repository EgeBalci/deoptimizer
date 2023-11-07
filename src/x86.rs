extern crate keystone;
use capstone::arch::x86::X86OperandType;
use capstone::arch::ArchOperand;
use capstone::prelude::*;
use capstone::{self, Arch, Capstone, Insn, InsnDetail, InsnGroupType, Mode};
use keystone::{AsmResult, Keystone};

/// Return register names
pub fn get_reg_names(cs: &Capstone, regs: &[RegId]) -> Vec<String> {
    regs.iter().map(|&x| cs.reg_name(x).unwrap()).collect()
}

/// Return instruction group names
pub fn get_group_names(cs: &Capstone, regs: &[InsnGroupId]) -> Vec<String> {
    regs.iter().map(|&x| cs.group_name(x).unwrap()).collect()
}

fn is_call(detail: &InsnDetail) -> bool {
    detail
        .groups()
        .iter()
        .any(|group| group.0 as u32 == InsnGroupType::CS_GRP_CALL)
}

fn is_jump(detail: &InsnDetail) -> bool {
    detail
        .groups()
        .iter()
        .any(|group| group.0 as u32 == InsnGroupType::CS_GRP_JUMP)
}

fn is_relative_branch(detail: &InsnDetail) -> bool {
    detail
        .groups()
        .iter()
        .any(|group| group.0 as u32 == InsnGroupType::CS_GRP_BRANCH_RELATIVE)
}

fn is_imm(op: &ArchOperand) -> Option<u64> {
    if let ArchOperand::X86Operand(op) = op {
        if let X86OperandType::Imm(imm) = op.op_type {
            return Some(imm as u64);
        }
    }
    None
}

fn is_known_address(ins: &[Insn], addr: u64) -> bool {
    for i in ins.as_ref() {
        if i.address() == addr {
            return true;
        }
    }
    false
}

// Option<(offset, address, size)>
fn is_ip_offset(insn: &Insn, op: &ArchOperand) -> Option<(i64, u64, u64)> {
    if let ArchOperand::X86Operand(op) = op {
        if let X86OperandType::Mem(op) = op.op_type {
            use capstone::arch::x86::X86Reg;
            let reg = op.base().0 as u32;
            let size = if reg == X86Reg::X86_REG_RIP {
                8
            } else if reg == X86Reg::X86_REG_EIP {
                4
            } else {
                return None;
            };
            let offset = op.disp();
            let address = (insn.address() + insn.bytes().len() as u64).wrapping_add(offset as u64);
            return Some((offset, address, size));
        }
    }
    None
}

pub fn disassemble(code: &[u8], mode: u8, start_addr: u64) -> Result<String, capstone::Error> {
    let m = match mode {
        16 => arch::x86::ArchMode::Mode16,
        32 => arch::x86::ArchMode::Mode32,
        64 => arch::x86::ArchMode::Mode64,
        _ => return Err(capstone::Error::InvalidMode),
    };

    let cs = Capstone::new()
        .x86()
        .mode(m)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()?;

    let ins = cs.disasm_all(code, start_addr)?;
    println!("Found {} instructions", ins.len());
    println!(
        "Last instruction address: {}",
        ins.last().unwrap().to_string().split(":").next().unwrap()
    );
    let mut disassembly = String::new();
    // let end_addr = u64::from_str_radix(
    //     ins.last()
    //         .unwrap()
    //         .to_string()
    //         .split(":")
    //         .next()
    //         .unwrap()
    //         .strip_prefix("0x")
    //         .unwrap(),
    //     16,
    // )
    // .unwrap();

    for i in ins.as_ref() {
        // println!("loc_{}", i.to_string().strip_prefix("0x").unwrap());
        let detail: InsnDetail = cs.insn_detail(&i)?;
        let arch_detail: ArchDetail = detail.arch_detail();
        let ops = arch_detail.operands();
        //
        // let output: &[(&str, String)] = &[
        //     ("insn id:", format!("{:?}", i.id().0)),
        //     ("bytes:", format!("{:?}", i.bytes())),
        //     ("read regs:", get_reg_names(&cs, detail.regs_read())),
        //     ("write regs:", get_reg_names(&cs, detail.regs_write())),
        //     ("insn groups:", get_group_names(&cs, detail.groups())),
        // ];
        //
        // for &(ref name, ref message) in output.iter() {
        //     println!("{:4}{:12} {}", "", name, message);
        // }
        //
        // println!("{:4}operands: {}", "", ops.len());
        // for op in ops {
        //     println!("{:8}{:?}", "", op);
        // }
        // if get_group_names(&cs, defail.groups()).contains("branch_relative")

        if is_call(&detail) || is_jump(&detail) || is_relative_branch(&detail) {
            if let Some(imm) = is_imm(ops.first().unwrap()) {
                if is_known_address(&ins, imm) {
                    disassembly +=
                        &format!("{}\n", i.to_string().replace("0x", "loc_").to_string());
                    continue;
                } else {
                    println!("[!] out of bound branch ==> {}", i.to_string());
                }
            }
        }

        disassembly +=
            &(format!("loc_{}\n", i.to_string().strip_prefix("0x").unwrap()).to_string());
    }
    Ok(disassembly)
}

pub fn assemble(code: String, mode: u8, addr: u64) -> Result<AsmResult, keystone::Error> {
    let m = match mode {
        16 => keystone::MODE_16,
        32 => keystone::MODE_32,
        64 => keystone::MODE_64,
        _ => return Err(keystone::ERR_MODE),
    };
    let engine = Keystone::new(keystone::Arch::X86, m)?;
    engine.option(keystone::OptionType::SYNTAX, keystone::OPT_SYNTAX_INTEL)?;
    engine.asm(code, addr)
}
