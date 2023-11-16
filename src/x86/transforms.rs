use chrono::format;
use iced_x86::{
    Code, ConditionCode, Decoder, DecoderOptions, Formatter, GasFormatter, IcedError, Instruction,
    InstructionInfoFactory, IntelFormatter, MasmFormatter, MemoryOperand, NasmFormatter, OpAccess,
    OpKind, Register, RegisterInfo, RflagsBits,
};
use rand::{seq::SliceRandom, Rng};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransformError {
    #[error("This transform not possible for given instruction.")]
    TransformNotPossible,
    #[error("Unexpected register size given.")]
    UnexpectedRegisterSize,
    #[error("Invalid processor mode given. (16/32/64 accepted)")]
    InvalidProcessorMode,
    #[error("Register collection failed.")]
    RegisterCollectFail,
    #[error("IcedError: {0}")]
    IcedError(#[from] IcedError),
}

pub fn get_immediate_info(inst: Instruction) -> Option<(u32, u64)> {
    for i in 0..inst.op_count() {
        match inst.op_kind(i) {
            OpKind::Immediate8_2nd => return Some((i, inst.immediate(i))),
            OpKind::Immediate8 => return Some((i, inst.immediate(i))),
            OpKind::Immediate16 => return Some((i, inst.immediate(i))),
            OpKind::Immediate32 => return Some((i, inst.immediate(i))),
            OpKind::Immediate64 => return Some((i, inst.immediate(i))),
            OpKind::Immediate8to16 => return Some((i, inst.immediate(i))),
            OpKind::Immediate8to32 => return Some((i, inst.immediate(i))),
            OpKind::Immediate8to64 => return Some((i, inst.immediate(i))),
            OpKind::Immediate32to64 => return Some((i, inst.immediate(i))),
            _ => continue,
        }
    }
    None
}

pub fn get_register_save_seq(reg: Register) -> Result<(Instruction, Instruction), TransformError> {
    let (c1, c2) = match reg.size() {
        2 => (Code::Push_r16, Code::Pop_r16),
        4 => (Code::Push_r32, Code::Pop_r32),
        8 => (Code::Push_r64, Code::Pop_r64),
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };
    let pre = Instruction::with1(c1, reg)?;
    let post = Instruction::with1(c2, reg)?;
    Ok((pre, post))
}

pub fn get_random_register_value(reg: Register) -> u64 {
    let mut rng = rand::thread_rng();
    if reg.size() > 4 {
        return rng.gen_range(1..u32::MAX) as u64;
    }
    rng.gen_range(1..u64::pow(2, (reg.size() * 8) as u32)) as u64
    // (u32::MAX - 100) as u64
}

pub fn get_random_gp_register(extended: bool, size: usize) -> Result<Register, TransformError> {
    if !extended && size > 4 {
        return Err(TransformError::UnexpectedRegisterSize);
    }

    let mut gpr8 = Vec::new();
    let mut gpr16 = Vec::new();
    let mut gpr32 = Vec::new();
    let mut gpr64 = Vec::new();

    for r in Register::values() {
        if r.is_gpr8() {
            gpr8.push(r);
            continue;
        }
        if r.is_gpr16() {
            gpr16.push(r);
            continue;
        }
        if r.is_gpr32() {
            gpr32.push(r);
            continue;
        }
        if r.is_gpr64() {
            gpr64.push(r);
            continue;
        }
    }

    loop {
        let reg = match size {
            1 => gpr8.choose(&mut rand::thread_rng()).unwrap(),
            2 => gpr16.choose(&mut rand::thread_rng()).unwrap(),
            4 => gpr32.choose(&mut rand::thread_rng()).unwrap(),
            8 => gpr64.choose(&mut rand::thread_rng()).unwrap(),
            _ => return Err(TransformError::UnexpectedRegisterSize),
        };

        let reg_str = format!("{:?}", reg);
        let is_extended = reg_str.contains("R") || reg_str.contains("IL") || reg_str.contains("PL");
        if is_extended == extended {
            // println!("{?:} = {}", reg, reg.number());
            return Ok(*reg);
        }
    }
}

fn get_add_code_with(reg: Register) -> Result<Code, TransformError> {
    let c = match reg.size() {
        1 => Code::Add_rm8_imm8,
        2 => Code::Add_rm16_imm16,
        4 | 8 => Code::Add_rm32_imm32,
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };
    Ok(c)
}

fn get_sub_code_with(reg: Register) -> Result<Code, TransformError> {
    let c = match reg.size() {
        1 => Code::Sub_rm8_imm8,
        2 => Code::Sub_rm16_imm16,
        4 | 8 => Code::Sub_rm32_imm32,
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };
    Ok(c)
}

// Memory Obfuscation Transforms

/// Applies offset mutation to given instruction.
pub fn apply_om_transform(
    inst: &mut Instruction,
    mode: u32,
) -> Result<Vec<Instruction>, TransformError> {
    // First check the operand types.
    let base_reg = inst.memory_base();
    if !inst
        .op_kinds()
        .collect::<Vec<OpKind>>()
        .contains(&OpKind::Memory)
        || base_reg == Register::None
        || base_reg.is_segment_register()
        || base_reg.is_vector_register()
    {
        return Err(TransformError::TransformNotPossible);
    }
    let rnd_reg_val = get_random_register_value(base_reg);
    // println!("Rand val: 0x{:X} = {rnd_reg_val}", rnd_reg_val);
    let coin_flip: bool = rand::thread_rng().gen();

    let (c1, c2) = match coin_flip {
        true => (get_add_code_with(base_reg)?, get_sub_code_with(base_reg)?),
        false => (get_sub_code_with(base_reg)?, get_add_code_with(base_reg)?),
    };
    let pre_inst = Instruction::with2(c1, base_reg, rnd_reg_val)?;
    let post_inst = Instruction::with2(c2, base_reg, rnd_reg_val)?;
    let new_disply = inst.memory_displacement64().abs_diff(rnd_reg_val);
    // println!("New displ: 0x{:X} = {new_disply}", new_disply);
    let mut new_disply_signed = new_disply as i64; // This is not right!!!
    if coin_flip {
        new_disply_signed = -new_disply_signed;
    }
    match mode {
        16 | 32 => inst.set_memory_displacement32(new_disply_signed as u32),
        64 => inst.set_memory_displacement64(new_disply_signed as u64),
        _ => return Err(TransformError::InvalidProcessorMode),
    }
    Ok(Vec::from([pre_inst, inst.clone(), post_inst]))
}

/// Applies offset-to-register transform to given instruction.
pub fn apply_otr_transform(
    inst: &mut Instruction,
    mode: u32,
) -> Result<Vec<Instruction>, TransformError> {
    if !inst
        .op_kinds()
        .collect::<Vec<OpKind>>()
        .contains(&OpKind::Memory)
        || inst.memory_base() != Register::None
    {
        return Err(TransformError::TransformNotPossible);
    }

    let rand_reg = get_random_gp_register(mode == 64, (mode / 8) as usize)?;
    let (reg_save_pre, reg_save_post) = get_register_save_seq(rand_reg)?;
    let mov = match mode {
        32 => Instruction::with2(Code::Mov_rm32_imm32, rand_reg, inst.memory_displacement32())?,
        64 => Instruction::with2(Code::Mov_r64_imm64, rand_reg, inst.memory_displacement64())?,
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };
    // Obfuscate mov...
    inst.set_memory_base(rand_reg);
    match mode {
        32 => inst.set_memory_displacement32(0),
        64 => inst.set_memory_displacement64(0),
        _ => return Err(TransformError::UnexpectedRegisterSize),
    }
    Ok(Vec::from([reg_save_pre, mov, *inst, reg_save_post]))
}

// Register Obfuscation Transforms

/// Applies register swapping transform to given instruction.
pub fn apply_rs_transform(
    inst: &mut Instruction,
    mode: u32,
) -> Result<Vec<Instruction>, TransformError> {
    if !inst
        .op_kinds()
        .collect::<Vec<OpKind>>()
        .contains(&OpKind::Register)
    {
        return Err(TransformError::TransformNotPossible);
    }
    let mut reg_idxs = Vec::new();
    let mut used_regs = Vec::new();
    for o in 0..inst.op_count() {
        if inst.op_kind(o) == OpKind::Register {
            reg_idxs.push(o)
        }
    }
    for i in reg_idxs {
        if inst.op_register(i).is_gpr() {
            used_regs.push((i, inst.op_register(i)));
        }
    }
    if used_regs.len() == 0 {
        return Err(TransformError::TransformNotPossible);
    }

    let (reg_index, swap_reg) = *used_regs.choose(&mut rand::thread_rng()).unwrap();
    let mut rand_reg = get_random_gp_register(mode == 64, swap_reg.size())?;
    loop {
        if rand_reg != swap_reg {
            break;
        }
        // This is bad, check for infinite loop conditions
        rand_reg = get_random_gp_register(mode == 64, swap_reg.size())?;
    }
    let xchg = match swap_reg.size() {
        1 => Instruction::with2(Code::Xchg_rm8_r8, swap_reg, rand_reg)?,
        2 => Instruction::with2(Code::Xchg_rm16_r16, swap_reg, rand_reg)?,
        4 => Instruction::with2(Code::Xchg_rm32_r32, swap_reg, rand_reg)?,
        8 => Instruction::with2(Code::Xchg_rm64_r64, swap_reg, rand_reg)?,
        _ => return Err(TransformError::TransformNotPossible),
    };
    inst.set_op_register(reg_index, rand_reg);
    Ok(Vec::from([xchg, inst.clone(), xchg]))
}

// Immidiate Obfuscation Transforms

/// Applies immidiate-to-register transform to given instruction.
pub fn apply_itr_transform(
    inst: &mut Instruction,
    mode: u32,
) -> Result<Vec<Instruction>, TransformError> {
    let (imm_index, imm) = match get_immediate_info(*inst) {
        Some((idx, imm)) => (idx, imm),
        None => return Err(TransformError::TransformNotPossible),
    };

    println!("Immidiate: {}", imm);
    let rand_reg = get_random_gp_register(mode == 64, (mode / 8) as usize)?;
    let (reg_save_pre, reg_save_post) = get_register_save_seq(rand_reg)?;

    let mov = match rand_reg.size() {
        4 => Instruction::with2(Code::Mov_rm64_imm32, rand_reg, imm)?,
        8 => Instruction::with2(Code::Mov_r64_imm64, rand_reg, imm)?,
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };
    // Obfuscate mov...

    inst.set_op_kind(imm_index, OpKind::Register);
    inst.set_op_register(imm_index, rand_reg);

    Ok(Vec::from([reg_save_pre, mov, *inst, reg_save_post]))
}
/// Applies arithmetic partitioning transform to given instruction.
pub fn apply_ap_transform(
    inst: &mut Instruction,
    mode: u32,
) -> Result<Vec<Instruction>, TransformError> {
    todo!("...")
}
/// Applies logical inverse transform to given instruction.
pub fn apply_li_transform(
    inst: &mut Instruction,
    mode: u32,
) -> Result<Vec<Instruction>, TransformError> {
    todo!("...")
}

// Others...

/// Applies call proxy instruction transform.
pub fn apply_cp_transform(inst_addr: u64, mode: u32) -> Result<(), TransformError> {
    todo!("...")
}

#[cfg(test)]
mod tests {
    use iced_x86::{Code, Formatter, Instruction, MemoryOperand, NasmFormatter, OpKind, Register};

    use crate::x86::{
        apply_itr_transform, apply_om_transform, apply_otr_transform, apply_rs_transform,
    };

    use super::get_random_gp_register;

    #[test]
    fn test_om_transform() {
        println!("[*] testing offset mutation...");
        let inst = Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RAX,
            MemoryOperand::with_base_displ(Register::RBX, 0x10),
        )
        .expect("Instruction creation failed");
        let mut formatter = NasmFormatter::new();
        let mut formatted_inst = String::new();
        formatter.format(&inst, &mut formatted_inst);
        println!("[*] instruction: {}", formatted_inst);
        println!("[*] Memory Base: {:?}", inst.memory_base());
        // assert_eq!(formatted_inst, "mov eax,[ebx+10h]");
        for _i in 0..1000 {
            println!("---------------------");
            match apply_om_transform(&mut inst.clone(), 64) {
                Ok(result) => {
                    for i in result {
                        formatted_inst.clear();
                        formatter.format(&mut i.clone(), &mut formatted_inst);
                        println!("[+] {}", formatted_inst);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    break;
                }
            };
        }
    }

    #[test]
    fn test_rs_transform() {
        println!("[*] Testing register swap...");
        let inst = Instruction::with2(Code::Mov_rm64_r64, Register::RAX, Register::RBX)
            .expect("Instruction creation failed");
        let mut formatter = NasmFormatter::new();
        let mut formatted_inst = String::new();
        formatter.format(&inst, &mut formatted_inst);
        println!("[*] instruction: {}", formatted_inst);
        // assert_eq!(formatted_inst, "mov eax,bl");
        for _i in 0..1000 {
            println!("---------------------");
            match apply_rs_transform(&mut inst.clone(), 64) {
                Ok(res) => {
                    for i in res {
                        formatted_inst.clear();
                        formatter.format(&mut i.clone(), &mut formatted_inst);
                        println!("[+] {}", formatted_inst);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    break;
                }
            }
        }
    }

    #[test]
    fn test_otr_transform() {
        println!("[*] Testing offset to register transform...");
        let inst = Instruction::with2(
            Code::Mov_r64_rm64,
            Register::EAX,
            MemoryOperand::with_displ(0xDEADBEEFDEADBEEF, 8),
        )
        .expect("Instruction creation failed");
        let mut formatter = NasmFormatter::new();
        let mut formatted_inst = String::new();
        formatter.format(&inst, &mut formatted_inst);
        println!("[*] instruction: {}", formatted_inst);
        // assert_eq!(formatted_inst, "mov eax,ebx");
        for _i in 0..1000 {
            println!("---------------------");
            match apply_otr_transform(&mut inst.clone(), 64) {
                Ok(res) => {
                    for i in res {
                        formatted_inst.clear();
                        formatter.format(&mut i.clone(), &mut formatted_inst);
                        println!("[+] {}", formatted_inst);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    break;
                }
            }
        }
    }

    #[test]
    fn test_itr_transform() {
        println!("[*] Testing immediate to register transform...");
        let inst = Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0x6931)
            .expect("Instruction creation failed");
        let mut formatter = NasmFormatter::new();
        let mut formatted_inst = String::new();
        formatter.format(&inst, &mut formatted_inst);
        println!("[*] instruction: {}", formatted_inst);
        // assert_eq!(formatted_inst, "mov eax,ebx");
        for _i in 0..1000 {
            println!("---------------------");
            match apply_itr_transform(&mut inst.clone(), 32) {
                Ok(res) => {
                    for i in res {
                        formatted_inst.clear();
                        formatter.format(&mut i.clone(), &mut formatted_inst);
                        println!("[+] {}", formatted_inst);
                    }
                }
                Err(e) => {
                    println!("[-] {e}");
                    break;
                }
            }
        }
    }

    #[test]
    fn test_get_random_gp_register() {
        match get_random_gp_register(false, 4) {
            Ok(reg) => assert_eq!(reg.size(), 4),
            Err(e) => println!("[-] {e}"),
        };
    }
}
