use crate::x86::{
    get_add_code_with, get_immediate_indexes, get_random_arithmetic_mnemonic,
    get_random_gp_register, get_random_register_value, get_register_save_seq, get_sub_code_with,
    is_arithmetic_instruction, is_immediate_operand,
};
use iced_x86::{
    Code, ConditionCode, Decoder, DecoderOptions, Formatter, GasFormatter, IcedError, Instruction,
    InstructionInfoFactory, IntelFormatter, MasmFormatter, MemoryOperand, Mnemonic, NasmFormatter,
    OpAccess, OpKind, Register, RegisterInfo, RflagsBits,
};
use rand::{seq::SliceRandom, thread_rng, Rng};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransformError {
    #[error("This transform not possible for given instruction.")]
    TransformNotPossible,
    #[error("Unexpected register size given.")]
    UnexpectedRegisterSize,
    #[error("Unexpected immediate operand size encountered.")]
    UnexpectedImmediateSize,
    #[error("Invalid processor mode given. (16/32/64 accepted)")]
    InvalidProcessorMode,
    #[error("Register collection failed.")]
    RegisterCollectFail,
    #[error("No GP register found with given parameters.")]
    RegisterNotFound,
    #[error("IcedError: {0}")]
    IcedError(#[from] IcedError),
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
    let mut info_factory = InstructionInfoFactory::new();
    let info = info_factory.info(&inst);

    let rand_reg =
        get_random_gp_register(mode == 64, (mode / 8) as usize, Some(info.used_registers()))?;
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
    let mut info_factory = InstructionInfoFactory::new();
    let info = info_factory.info(&inst);

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
    let mut rand_reg =
        get_random_gp_register(mode == 64, swap_reg.size(), Some(info.used_registers()))?;
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
    let idxs = match get_immediate_indexes(inst) {
        Some(i) => i,
        None => return Err(TransformError::TransformNotPossible),
    };
    let mut info_factory = InstructionInfoFactory::new();
    let info = info_factory.info(&inst);

    let rand_reg =
        get_random_gp_register(mode == 64, (mode / 8) as usize, Some(info.used_registers()))?;
    let (reg_save_pre, reg_save_post) = get_register_save_seq(rand_reg)?;

    let mov = match rand_reg.size() {
        4 => Instruction::with2(
            Code::Mov_rm64_imm32,
            rand_reg,
            inst.immediate(*idxs.first().unwrap()),
        )?,
        8 => Instruction::with2(
            Code::Mov_r64_imm64,
            rand_reg,
            inst.immediate(*idxs.first().unwrap()),
        )?,
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };
    // Obfuscate mov...

    inst.set_op_kind(*idxs.first().unwrap(), OpKind::Register);
    inst.set_op_register(*idxs.first().unwrap(), rand_reg);

    Ok(Vec::from([reg_save_pre, mov, *inst, reg_save_post]))
}
/// Applies arithmetic partitioning transform to given instruction.
pub fn apply_ap_transform(
    inst: &mut Instruction,
    mode: u32,
) -> Result<Vec<Instruction>, TransformError> {
    if !is_arithmetic_instruction(inst)
        && inst.op0_kind() != OpKind::Register
        && !is_immediate_operand(inst.op1_kind())
        && inst.op_count() != 2
    {
        return Err(TransformError::TransformNotPossible);
    }

    // We are looking for MOV (=) ADD/ADC (+) SUB/SBB (-) CMP (-)
    // but we also need to preserve the flags, try to find the branch instructions
    // based on this arithmetic operation.
    let reg = inst.op0_register();
    let imm = inst.immediate(1);
    let coin_flip: bool = thread_rng().gen();
    let rand_imm_val = match inst.op1_kind() {
        OpKind::Immediate8 => {
            let r = get_random_register_value(Register::AL);
            inst.set_immediate8(r as u8);
            r
        }
        OpKind::Immediate8to16 => {
            let r = get_random_register_value(Register::AL);
            inst.set_immediate8to16(r as i16); // this is problematic
            r
        }
        OpKind::Immediate8to32 => {
            let r = get_random_register_value(Register::AL);
            inst.set_immediate8to32(r as i32); // this is problematic
            r
        }
        OpKind::Immediate8to64 => {
            let r = get_random_register_value(Register::AL);
            inst.set_immediate8to64(r as i64); // this is problematic
            r
        }
        OpKind::Immediate8_2nd => {
            let r = get_random_register_value(Register::AL);
            inst.set_immediate8_2nd(r as u8); // this is problematic
            r
        }
        OpKind::Immediate16 => {
            let r = get_random_register_value(Register::AX);
            inst.set_immediate16(r as u16); // this is problematic
            r
        }
        OpKind::Immediate32 => {
            let r = get_random_register_value(Register::EAX);
            inst.set_immediate32(r as u32); // this is problematic
            r
        }
        OpKind::Immediate32to64 => {
            let r = get_random_register_value(Register::EAX);
            inst.set_immediate32(r as u32); // this is problematic
            r
        }
        OpKind::Immediate64 => {
            let r = get_random_register_value(Register::RAX);
            inst.set_immediate64(r); // this is problematic
            r
        }
        _ => return Err(TransformError::UnexpectedImmediateSize),
    };

    let mut fix_inst = Instruction::default();
    // we're gonna decide if we add our fix instruction before of after the original instruction
    if coin_flip {
        // before
        if imm > rand_imm_val {
            fix_inst =
                Instruction::with2(get_add_code_with(reg)?, reg, rand_imm_val.abs_diff(imm))?;
        } else {
            fix_inst =
                Instruction::with2(get_sub_code_with(reg)?, reg, rand_imm_val.abs_diff(imm))?;
        }
        Ok(Vec::from([fix_inst, inst.clone()]))
    } else {
        // after
        if imm > rand_imm_val {
            fix_inst =
                Instruction::with2(get_add_code_with(reg)?, reg, rand_imm_val.abs_diff(imm))?;
        } else {
            fix_inst =
                Instruction::with2(get_sub_code_with(reg)?, reg, rand_imm_val.abs_diff(imm))?;
        }
        Ok(Vec::from([inst.clone(), fix_inst]))
    }
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
        // let inst = Instruction::with2(
        //     Code::Mov_r64_rm64,
        //     Register::RAX,
        //     MemoryOperand::with_base_displ(Register::RBX, 0x10),
        // )
        let inst = Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RAX,
            MemoryOperand::new(
                Register::RBX,
                Register::AL,
                1,
                0x10,
                1,
                false,
                Register::None,
            ),
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
