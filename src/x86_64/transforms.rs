use crate::x86_64::*;
use iced_x86::code_asm::*;
use iced_x86::*;
use rand::{seq::SliceRandom, Rng};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransformError {
    #[error("This transform not possible for given instruction.")]
    TransformNotPossible,
    #[error("Unexpected memory size given.")]
    UnexpectedMemorySize,
    #[error("Unexpected register size given.")]
    UnexpectedRegisterSize,
    #[error("Unexpected immediate operand size encountered.")]
    UnexpectedImmediateSize,
    #[error("Invalid processor mode(bitness). (16/32/64 accepted)")]
    InvalidProcessorMode,
    #[error("No GP register found with given parameters.")]
    RegisterNotFound,
    #[error("Invalid instruction template.")]
    InvalidTemplate,
    #[error("IcedError: {0}")]
    IcedError(#[from] IcedError),
}

// Immidiate Obfuscation Transforms

/// Applies arithmetic partitioning transform to given instruction.
pub fn apply_ap_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, TransformError> {
    if !is_ap_compatible(inst) || !is_immediate_operand(inst.op1_kind()) || inst.op_count() != 2 {
        return Err(TransformError::TransformNotPossible);
    }
    // We are looking for MOV (=) ADD/ADC (+) SUB/SBB (-)
    let rip = inst.ip();
    let imm = inst.immediate(1);
    let rand_imm_val = randomize_immediate_value(imm);
    let imm_delta: u64 = rand_imm_val.abs_diff(imm);
    let mut fix_inst = inst.clone();
    if inst.mnemonic() == Mnemonic::Mov && inst.op1_kind() == OpKind::Immediate64 {
        set_op1_immediate(inst, !imm)?;
        fix_inst = Instruction::with1(get_code_with_size(Mnemonic::Not, 8)?, inst.op0_register())?;
    } else {
        set_op1_immediate(inst, rand_imm_val)?;
        if imm > rand_imm_val {
            fix_inst.set_code(get_code_with_template(Mnemonic::Add, inst)?);
            set_op1_immediate(&mut fix_inst, imm_delta)?;
        } else {
            fix_inst.set_code(get_code_with_template(Mnemonic::Sub, inst)?);
            set_op1_immediate(&mut fix_inst, imm_delta)?;
        }
    }

    if inst.mnemonic() == Mnemonic::Mov {
        Ok(encode(bitness, Vec::from([*inst, fix_inst]), rip)?)
    } else {
        Ok(encode(bitness, Vec::from([fix_inst, *inst]), rip)?)
    }
}

/// Applies logical inverse transform to given instruction.
pub fn apply_li_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, TransformError> {
    if !is_li_compatible(inst) || !is_immediate_operand(inst.op1_kind()) || inst.op_count() != 2 {
        return Err(TransformError::TransformNotPossible);
    }
    // We are looking for XOR (^) AND (&) OR (|) SHR (>) SHL (<) ROR (>>) ROL (<<)
    let rip = inst.ip();
    let mnemonic = inst.mnemonic();
    let mut imm = inst.immediate(1);
    if imm == 0 {
        // Unlikely but possible...
        return Ok(Vec::from([Instruction::with(Code::Nopd)]));
    }

    let result = match mnemonic {
        Mnemonic::Xor => {
            set_op1_immediate(inst, !imm)?;
            let mut not = inst.clone();
            not.set_code(get_code_with_template(Mnemonic::Not, inst)?);
            Vec::from([not, *inst])
        }
        Mnemonic::And => {
            let mut or = inst.clone();
            or.set_code(get_code_with_template(Mnemonic::Or, inst)?);
            set_op1_immediate(&mut or, !imm)?;
            let mut not = inst.clone();
            not.set_code(get_code_with_template(Mnemonic::Not, inst)?);
            Vec::from([not, or, not])
        }
        Mnemonic::Or => {
            let mut and = inst.clone();
            and.set_code(get_code_with_template(Mnemonic::And, inst)?);
            set_op1_immediate(&mut and, !imm)?;
            let mut not = inst.clone();
            not.set_code(get_code_with_template(Mnemonic::Not, inst)?);
            Vec::from([not, and, not])
        }
        Mnemonic::Shr | Mnemonic::Sar | Mnemonic::Shl | Mnemonic::Sal => {
            if imm == 1 {
                // Need to fix this case...
                return Err(TransformError::TransformNotPossible);
            }
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
            let dst_op_size = match inst.op0_kind() {
                OpKind::Memory => (inst.memory_size().element_size() * 8) as u64,
                OpKind::Register => (inst.op0_register().size() * 8) as u64,
                _ => return Err(TransformError::InvalidTemplate),
            };
            imm = imm % dst_op_size;
            let pow = rand::thread_rng().gen_range(2..(u8::MAX as u64 / dst_op_size) as u8);
            inst.set_immediate8((dst_op_size * pow as u64 + imm) as u8);
            Vec::from([*inst])
        }
        _ => return Err(TransformError::TransformNotPossible),
    };
    Ok(encode(bitness, result, rip)?)
}

/// Applies immidiate-to-register transform to given instruction.
pub fn apply_itr_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, TransformError> {
    if inst.is_stack_instruction() {
        return Err(TransformError::TransformNotPossible);
    }
    let idxs = match get_immediate_indexes(inst) {
        Some(i) => i,
        None => return Err(TransformError::TransformNotPossible),
    };

    let rip = inst.ip();
    let mut info_factory = InstructionInfoFactory::new();
    let info = info_factory.info(&inst);
    let rand_reg = get_random_gp_register(
        bitness == 64,
        (bitness / 8) as usize,
        Some(info.used_registers()),
    )?;
    let (reg_save_pre, reg_save_post) = get_register_save_seq(rand_reg)?;

    let mut mov = match rand_reg.size() {
        4 => Instruction::with2(
            Code::Mov_rm32_imm32,
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
    let obs_mov = apply_ap_transform(bitness, &mut mov)?;
    inst.set_op_kind(*idxs.first().unwrap(), OpKind::Register);
    inst.set_op_register(*idxs.first().unwrap(), rand_reg);
    let mut result = [Vec::from([reg_save_pre]), obs_mov].concat();
    result.push(*inst);
    result.push(reg_save_post);
    Ok(encode(bitness, result, rip)?)
}
// Memory Obfuscation Transforms

/// Applies offset mutation to given instruction.
/// Note: This transform may clobber the CFLAGS!
/// avoid using with CF altering instructions.
pub fn apply_om_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, TransformError> {
    // First check the operand types.
    let base_reg = inst.memory_base();
    if !inst
        .op_kinds()
        .collect::<Vec<OpKind>>()
        .contains(&OpKind::Memory)
        || base_reg.is_segment_register()
        || base_reg.is_vector_register()
    {
        return Err(TransformError::TransformNotPossible);
    }
    let rip = inst.ip();
    let mem_disp = inst.memory_displacement64();
    if base_reg == Register::None {
        if inst.is_stack_instruction() {
            return Err(TransformError::TransformNotPossible);
        }
        let mut ifac = InstructionInfoFactory::new();
        let info = ifac.info(inst);
        let rand_reg = get_random_gp_register(
            bitness == 64,
            (bitness / 8) as usize,
            Some(info.used_registers()),
        )?;
        let (reg_save_pre, reg_save_suf) = get_register_save_seq(rand_reg)?;
        inst.set_memory_base(rand_reg);
        inst.set_memory_displacement64(0);
        inst.set_memory_displ_size(0);

        let mut mov = match bitness {
            16 => Instruction::with2(Code::Mov_rm16_imm16, rand_reg, mem_disp)?,
            32 => Instruction::with2(Code::Mov_rm32_imm32, rand_reg, mem_disp)?,
            64 => Instruction::with2(Code::Mov_r64_imm64, rand_reg, mem_disp)?,
            _ => return Err(TransformError::UnexpectedRegisterSize),
        };

        let movs = apply_ap_transform(bitness, &mut mov)?;
        let mut result = Vec::from([reg_save_pre]);
        result = [result, movs].concat();
        result.push(*inst);
        result.push(reg_save_suf);
        Ok(encode(bitness, result, rip)?)
    } else {
        let rnd_reg_val = get_random_register_value(base_reg);
        let coin_flip: bool = rand::thread_rng().gen();
        let (c1, c2) = match coin_flip {
            true => (
                get_code_with_size(Mnemonic::Add, base_reg.size())?,
                get_code_with_size(Mnemonic::Sub, base_reg.size())?,
            ),
            false => (
                get_code_with_size(Mnemonic::Sub, base_reg.size())?,
                get_code_with_size(Mnemonic::Add, base_reg.size())?,
            ),
        };
        let pre_inst = Instruction::with2(c1, base_reg, rnd_reg_val)?;
        let post_inst = Instruction::with2(c2, base_reg, rnd_reg_val)?;
        let new_disply = mem_disp.abs_diff(rnd_reg_val);
        let mut new_disply_signed = new_disply as i64; // This is not right!!!
        if coin_flip {
            new_disply_signed = -new_disply_signed;
        }
        inst.set_memory_displ_size(1);
        inst.set_memory_displacement64(new_disply_signed as u64);
        Ok(encode(
            bitness,
            Vec::from([pre_inst, inst.clone(), post_inst]),
            rip,
        )?)
    }
}

// Register Obfuscation Transforms
/// Applies register swapping transform to given instruction.
pub fn apply_rs_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, TransformError> {
    if !inst
        .op_kinds()
        .collect::<Vec<OpKind>>()
        .contains(&OpKind::Register)
    {
        return Err(TransformError::TransformNotPossible);
    }
    // We need to fix the code if it is spesific to any register
    if is_using_static_register(inst) && is_immediate_operand(inst.op1_kind()) {
        if let Ok(code) = get_code_with_template(inst.mnemonic(), inst) {
            inst.set_code(code);
            match inst.op0_register().size() {
                1 => inst.set_op1_kind(OpKind::Immediate8),
                2 => inst.set_op1_kind(OpKind::Immediate16),
                4 => inst.set_op1_kind(OpKind::Immediate32),
                8 => inst.set_op1_kind(OpKind::Immediate64), // This may actually fail
                _ => return Err(TransformError::UnexpectedRegisterSize),
            }
        } else {
            return Err(TransformError::TransformNotPossible);
        }
    }
    let rip = inst.ip();
    let mut info_factory = InstructionInfoFactory::new();
    let info = info_factory.info(&inst);

    let swap_reg = info
        .used_registers()
        .choose(&mut rand::thread_rng())
        .unwrap()
        .register();
    let rand_reg =
        get_random_gp_register(bitness == 64, swap_reg.size(), Some(info.used_registers()))?;

    for i in 0..inst.op_count() {
        if inst.op_kind(i) == OpKind::Register && inst.op_register(i) == swap_reg {
            inst.set_op_register(i, rand_reg);
        }
    }

    let xchg = match swap_reg.size() {
        1 => Instruction::with2(Code::Xchg_rm8_r8, swap_reg, rand_reg)?,
        2 => Instruction::with2(Code::Xchg_rm16_r16, swap_reg, rand_reg)?,
        4 => Instruction::with2(Code::Xchg_rm32_r32, swap_reg, rand_reg)?,
        8 => Instruction::with2(Code::Xchg_rm64_r64, swap_reg, rand_reg)?,
        _ => return Err(TransformError::TransformNotPossible),
    };
    Ok(encode(bitness, Vec::from([xchg, inst.clone(), xchg]), rip)?)
}

// Other special cases...

/// Applies condition extention transform.
pub fn apply_ce_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, TransformError> {
    if !matches!(
        inst.mnemonic(),
        Mnemonic::Jcxz | Mnemonic::Jecxz | Mnemonic::Jrcxz
    ) && (!inst.is_loopcc() && !inst.is_loop())
    {
        return Err(TransformError::TransformNotPossible);
    }

    let mut asm = CodeAssembler::new(bitness)?;
    let mut test = match bitness {
        16 => Instruction::with2(Code::Test_rm16_r16, Register::CX, Register::CX)?,
        32 => Instruction::with2(Code::Test_rm32_r32, Register::ECX, Register::ECX)?,
        64 => Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX)?,
        _ => return Err(TransformError::InvalidProcessorMode),
    };
    test.set_ip(inst.ip());

    if inst.is_loopcc() || inst.is_loop() {
        match inst.mnemonic() {
            Mnemonic::Loop => {
                asm.jz(inst.near_branch_target())?;
                let insts = asm.instructions();
                let mut jz = insts.first().unwrap().clone();
                jz.set_ip(test.next_ip());
                return Ok(Vec::from([test, jz]));
            }
            Mnemonic::Loope => {
                todo!("...");
            }
            Mnemonic::Loopne => {
                asm.jnz(inst.near_branch_target())?;
                let insts = asm.instructions();
                let mut jnz = insts.first().unwrap().clone();
                jnz.set_ip(test.next_ip());
                return Ok(Vec::from([test, jnz]));
            }
            _ => return Err(TransformError::TransformNotPossible),
        }
    }

    if matches!(
        inst.mnemonic(),
        Mnemonic::Jrcxz | Mnemonic::Jecxz | Mnemonic::Jcxz
    ) {
        asm.jz(inst.near_branch_target())?;
        let insts = asm.instructions();
        let mut jz = insts.first().unwrap().clone();
        jz.set_ip(test.next_ip());
        return Ok(Vec::from([test, jz]));
    }

    Err(TransformError::TransformNotPossible)
}

// /// Applies call proxy instruction transform.
// pub fn apply_cp_transform(inst_addr: u64, mode: u32) -> Result<(), TransformError> {
//     todo!("...")
// }
