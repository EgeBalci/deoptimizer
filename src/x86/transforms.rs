use crate::x86::*;
use iced_x86::*;
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
    let coin_flip: bool = rand::thread_rng().gen();

    let (c1, c2) = match coin_flip {
        true => (get_add_code_with(base_reg)?, get_sub_code_with(base_reg)?),
        false => (get_sub_code_with(base_reg)?, get_add_code_with(base_reg)?),
    };
    let pre_inst = Instruction::with2(c1, base_reg, rnd_reg_val)?;
    let post_inst = Instruction::with2(c2, base_reg, rnd_reg_val)?;
    let new_disply = inst.memory_displacement64().abs_diff(rnd_reg_val);
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
    let rand_reg =
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

    let mut mov = match rand_reg.size() {
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
    let obs_mov = apply_ap_transform(&mut mov)?;
    inst.set_op_kind(*idxs.first().unwrap(), OpKind::Register);
    inst.set_op_register(*idxs.first().unwrap(), rand_reg);
    let mut result = [Vec::from([reg_save_pre]), obs_mov].concat();
    result.push(*inst);
    result.push(reg_save_post);
    Ok(result)
}

/// Applies arithmetic partitioning transform to given instruction.
pub fn apply_ap_transform(inst: &mut Instruction) -> Result<Vec<Instruction>, TransformError> {
    if !is_ap_safe_instruction(inst)
        || inst.op0_kind() != OpKind::Register
        || !is_immediate_operand(inst.op1_kind())
        || inst.op_count() != 2
    {
        return Err(TransformError::TransformNotPossible);
    }

    // We are looking for MOV (=) ADD/ADC (+) SUB/SBB (-)
    // let mnemonic = inst.mnemonic();
    let reg = inst.op0_register();
    let imm = inst.immediate(1);
    let rand_imm_val = randomize_immediate_value(imm);
    match inst.op1_kind() {
        OpKind::Immediate8 => inst.set_immediate8(rand_imm_val as u8),
        OpKind::Immediate8to16 => inst.set_immediate8to16(rand_imm_val as i16),
        OpKind::Immediate8to32 => inst.set_immediate8to32(rand_imm_val as i32),
        OpKind::Immediate8to64 => inst.set_immediate8to64(rand_imm_val as i64),
        OpKind::Immediate8_2nd => inst.set_immediate8_2nd(rand_imm_val as u8),
        OpKind::Immediate16 => inst.set_immediate16(rand_imm_val as u16),
        OpKind::Immediate32 => inst.set_immediate32(rand_imm_val as u32),
        OpKind::Immediate32to64 => inst.set_immediate32(rand_imm_val as u32),
        OpKind::Immediate64 => inst.set_immediate64(rand_imm_val),
        _ => return Err(TransformError::UnexpectedImmediateSize),
    };

    let mut result = Vec::new();
    // we always need to make the value adjustment before the original instruction for preserving
    // the cflags...
    if imm > rand_imm_val {
        result.push(Instruction::with2(
            get_sub_code_with(reg)?,
            reg,
            rand_imm_val.abs_diff(imm),
        )?);
    } else {
        result.push(Instruction::with2(
            get_add_code_with(reg)?,
            reg,
            rand_imm_val.abs_diff(imm),
        )?);
    }
    result.push(*inst);
    Ok(result)
}

/// Applies logical inverse transform to given instruction.
pub fn apply_li_transform(inst: &mut Instruction) -> Result<Vec<Instruction>, TransformError> {
    if !is_li_safe_instruction(inst)
        || inst.op0_kind() != OpKind::Register
        || !is_immediate_operand(inst.op1_kind())
        || inst.op_count() != 2
    {
        return Err(TransformError::TransformNotPossible);
    }
    // We are looking for XOR (^) AND (&) OR (|) SHR (>) SHL (<) ROR (>>) ROL (<<)
    let mnemonic = inst.mnemonic();
    let reg = inst.op0_register();
    let mut imm = inst.immediate(1);
    // let rand_imm_val = randomize_immediate_value(imm);
    let result = match mnemonic {
        Mnemonic::Xor => {
            match reg.size() {
                1 => inst.set_immediate8(!(imm as u8)),
                2 => inst.set_immediate16(!(imm as u16)),
                4 => inst.set_immediate32(!(imm as u32)),
                8 => inst.set_immediate32(!(imm as u32)),
                _ => return Err(TransformError::UnexpectedRegisterSize),
            };
            Vec::from([Instruction::with1(get_not_code_with(reg)?, reg)?, *inst])
        }
        Mnemonic::And => {
            let mut or = Instruction::with2(get_or_code_with(reg)?, reg, 0)?;
            match reg.size() {
                1 => or.set_immediate8(!(imm as u8)),
                2 => or.set_immediate16(!(imm as u16)),
                4 => or.set_immediate32(!(imm as u32)),
                8 => or.set_immediate32(!(imm as u32)),
                _ => return Err(TransformError::UnexpectedRegisterSize),
            };
            Vec::from([
                Instruction::with1(get_not_code_with(reg)?, reg)?,
                or,
                Instruction::with1(get_not_code_with(reg)?, reg)?,
            ])
        }
        Mnemonic::Or => {
            let mut or = Instruction::with2(get_and_code_with(reg)?, reg, 0)?;
            match reg.size() {
                1 => or.set_immediate8(!(imm as u8)),
                2 => or.set_immediate16(!(imm as u16)),
                4 => or.set_immediate32(!(imm as u32)),
                8 => or.set_immediate32(!(imm as u32)),
                _ => return Err(TransformError::UnexpectedRegisterSize),
            };
            Vec::from([
                Instruction::with1(get_not_code_with(reg)?, reg)?,
                or,
                Instruction::with1(get_not_code_with(reg)?, reg)?,
            ])
        }
        Mnemonic::Shr | Mnemonic::Sar | Mnemonic::Shl | Mnemonic::Sal => {
            if imm.is_power_of_two() {
                let mut shift1 = inst.clone();
                let mut shift2 = inst.clone();
                shift1.set_immediate8(imm as u8 / 2);
                shift2.set_immediate8(imm as u8 / 2);
                Vec::from([shift1, shift2])
            } else {
                let mut shift1 = inst.clone();
                let mut shift2 = inst.clone();
                shift1.set_immediate8(((imm - 1) as u8 / 2) + 1);
                shift2.set_immediate8((imm - 1) as u8 / 2);
                Vec::from([shift1, shift2])
            }
        }
        Mnemonic::Ror | Mnemonic::Rcr | Mnemonic::Rol | Mnemonic::Rcl => {
            let reg_size = (reg.size() * 8) as u64;
            imm = imm % reg_size;
            let pow = rand::thread_rng().gen_range(1..((u8::MAX as u64 / reg_size) - 2) as u8) - 1;
            inst.set_immediate8((reg_size * pow as u64 + imm) as u8);
            Vec::from([*inst])
        }
        _ => return Err(TransformError::TransformNotPossible),
    };
    Ok(result)
}

// Others...

/// Applies call proxy instruction transform.
pub fn apply_cp_transform(inst_addr: u64, mode: u32) -> Result<(), TransformError> {
    todo!("...")
}
