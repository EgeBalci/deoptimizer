use iced_x86::{
    Code, ConditionCode, Decoder, DecoderOptions, Formatter, GasFormatter, Instruction,
    InstructionInfoFactory, IntelFormatter, MasmFormatter, NasmFormatter, OpKind, Register,
    RflagsBits,
};
use rand::Rng;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransformError {
    #[error("This transform not possible for given instruction.")]
    TransformNotPossible,
    #[error("Unexpected register size given.")]
    UnexpectedRegisterSize,
    #[error("Invalid processor mode given. (16/32/64 accepted)")]
    InvalidProcessorMode,
}

pub fn get_random_register_value(reg: Register) -> usize {
    let mut rng = rand::thread_rng();
    rng.gen_range(0..(reg.size() * 8))
}

fn get_add_code_with(size: usize) -> Result<Code, TransformError> {
    let c = match size {
        1 => Code::Add_rm8_imm8,
        2 => Code::Add_rm16_imm16,
        4 => Code::Add_rm32_imm32,
        8 => Code::Add_rm64_imm32,
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };
    Ok(c)
}

fn get_sub_code_with(size: usize) -> Result<Code, TransformError> {
    let c = match size {
        1 => Code::Sub_rm8_imm8,
        2 => Code::Sub_rm16_imm16,
        4 => Code::Sub_rm32_imm32,
        8 => Code::Sub_rm64_imm32,
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
    let index_reg = inst.memory_index();
    if !inst
        .op_kinds()
        .collect::<Vec<OpKind>>()
        .contains(&OpKind::Memory)
        || index_reg == Register::None
        || index_reg.is_segment_register()
    {
        return Err(TransformError::TransformNotPossible);
    }
    let rnd_reg_val = get_random_register_value(index_reg);
    let coin_flip: bool = rand::thread_rng().gen();
    let code = match coin_flip {
        true => get_add_code_with(index_reg.size())?,
        false => get_sub_code_with(index_reg.size())?,
    };
    let mut pre_inst = Instruction::with(code);

    match index_reg.size() {
        1 => pre_inst.set_immediate8(rnd_reg_val as u8),
        2 => pre_inst.set_immediate16(rnd_reg_val as u16),
        4 => pre_inst.set_immediate32(rnd_reg_val as u32),
        8 => pre_inst.set_immediate64(rnd_reg_val as u64),
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };

    let new_disply = match coin_flip {
        true => inst.memory_displacement64() - rnd_reg_val as u64,
        false => inst.memory_displacement64() - rnd_reg_val as u64,
    };

    let mut post_inst = match coin_flip {
        true => Instruction::with(get_sub_code_with(index_reg.size())?),
        false => Instruction::with(get_add_code_with(index_reg.size())?),
    };

    match mode {
        16 => {
            post_inst.set_immediate32(rnd_reg_val as u32);
            inst.set_memory_displacement64(new_disply);
        }
        32 => {
            post_inst.set_immediate32(rnd_reg_val as u32);
            inst.set_memory_displacement32(new_disply as u32);
        }
        64 => {
            post_inst.set_immediate64(rnd_reg_val as u64);
            inst.set_memory_displacement64(new_disply);
        }
        _ => return Err(TransformError::InvalidProcessorMode),
    }

    Ok(Vec::from([pre_inst, inst.clone(), post_inst]))
}
/// Applies offset-to-register transform to given instruction.
pub fn apply_otr_transform(
    inst: &mut Instruction,
    mode: u32,
) -> Result<Vec<Instruction>, TransformError> {
    let index_reg = inst.memory_index();
    if !inst
        .op_kinds()
        .collect::<Vec<OpKind>>()
        .contains(&OpKind::Memory)
        || index_reg != Register::None
    {
        return Err(TransformError::TransformNotPossible);
    }

    todo!("...")
}

// Register Obfuscation Transforms

/// Applies register swapping transform to given instruction.
pub fn apply_rs_transform(
    inst: &mut Instruction,
    mode: u32,
) -> Result<Vec<Instruction>, TransformError> {
    todo!("...")
}

// Immidiate Obfuscation Transforms

/// Applies immidiate-to-register transform to given instruction.
pub fn apply_itr_transform(
    inst: &mut Instruction,
    mode: u32,
) -> Result<Vec<Instruction>, TransformError> {
    todo!("...")
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
