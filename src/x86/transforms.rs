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

pub fn get_register_save_seq(reg: Register) -> Result<Vec<Instruction>, TransformError> {
    let (c1, c2) = match reg.size() {
        2 => (Code::Push_r16, Code::Pop_r16),
        4 => (Code::Push_r32, Code::Pop_r32),
        8 => (Code::Push_r64, Code::Pop_r64),
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };
    let pre = Instruction::with1(c1, reg)?;
    let post = Instruction::with1(c2, reg)?;
    Ok(Vec::from([pre, post]))
}

pub fn get_random_register_value(reg: Register) -> i64 {
    let mut rng = rand::thread_rng();
    if reg.size() > 8 {
        return rng.gen_range(1..i64::MAX) as i64;
    }
    rng.gen_range(1..(2 ^ (reg.size() * 8))) as i64
}

pub fn get_random_gp_register(extended: bool, size: usize) -> Result<Register, TransformError> {
    let regs: Vec<Register> = Register::values().collect::<Vec<Register>>();
    let reg = match regs.choose(&mut rand::thread_rng()) {
        Some(r) => r,
        None => return Err(TransformError::RegisterCollectFail),
    };

    let correct_size = match size {
        1 => reg.is_gpr8(),
        2 => reg.is_gpr16(),
        4 => reg.is_gpr32(),
        8 => reg.is_gpr64(),
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };

    let is_extended = reg.number() > 7;
    if correct_size && is_extended == extended {
        return Ok(*reg);
    }
    return get_random_gp_register(extended, size);
}

fn get_add_code_with(reg: Register) -> Result<Code, TransformError> {
    let c = match reg.size() {
        1 => Code::Add_rm8_imm8,
        2 => Code::Add_rm16_imm16,
        4 => Code::Add_rm32_imm32,
        8 => Code::Add_rm64_imm32,
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };
    Ok(c)
}

fn get_sub_code_with(reg: Register) -> Result<Code, TransformError> {
    let c = match reg.size() {
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

    let mut code = match coin_flip {
        true => get_add_code_with(base_reg)?,
        false => get_sub_code_with(base_reg)?,
    };
    let mut pre_inst = Instruction::with2(code, base_reg, 0)?;
    pre_inst.set_immediate8to64(rnd_reg_val);

    let new_disply = match coin_flip {
        true => inst.memory_displacement64() as i64 - rnd_reg_val as i64,
        false => inst.memory_displacement64() as i64 - rnd_reg_val as i64,
    };

    code = match coin_flip {
        true => get_sub_code_with(base_reg)?,
        false => get_add_code_with(base_reg)?,
    };
    let mut post_inst = Instruction::with2(code, base_reg, 0)?;
    post_inst.set_immediate8to64(rnd_reg_val);

    match mode {
        16 | 32 => inst.set_memory_displacement32(new_disply as u32),
        64 => inst.set_memory_displacement64(new_disply as u64),
        _ => return Err(TransformError::InvalidProcessorMode),
    }

    Ok(Vec::from([pre_inst, inst.clone(), post_inst]))
}
/// Applies offset-to-register transform to given instruction.
pub fn apply_otr_transform(
    inst: &mut Instruction,
    mode: u32,
) -> Result<Vec<Instruction>, TransformError> {
    let base_reg = inst.memory_base();
    if !inst
        .op_kinds()
        .collect::<Vec<OpKind>>()
        .contains(&OpKind::Memory)
        || base_reg != Register::None
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
    if !inst
        .op_kinds()
        .collect::<Vec<OpKind>>()
        .contains(&OpKind::Register)
    {
        return Err(TransformError::TransformNotPossible);
    }

    let mut info_factory = InstructionInfoFactory::new();
    let info = info_factory.info(&inst);
    let mut used_regs = Vec::new();
    for ri in info.used_registers() {
        let mut reg_index = 0;
        for i in 0..inst.op_count() {
            if inst.op_register(i) == ri.register() {
                reg_index = i;
            }
        }
        if ri.register().is_gpr() {
            used_regs.push((reg_index, ri.register()))
        }
    }
    if used_regs.len() == 0 {
        return Err(TransformError::TransformNotPossible);
    }

    let (reg_index, swap_reg) = *used_regs.choose(&mut rand::thread_rng()).unwrap();
    let mut rand_reg = get_random_gp_register(mode == 64, swap_reg.size())?;
    while rand_reg == swap_reg {
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

#[cfg(test)]
mod tests {
    use iced_x86::{Code, Formatter, Instruction, MemoryOperand, NasmFormatter, OpKind, Register};

    use crate::x86::{apply_om_transform, apply_rs_transform};

    use super::get_random_gp_register;

    #[test]
    fn test_om_transform() {
        println!("[*] testing offset mutation...");
        let mut inst = Instruction::with2(
            Code::Mov_r32_rm32,
            Register::EAX,
            MemoryOperand::with_base_displ(Register::EBX, 0x10),
        )
        .expect("Instruction creation failed");
        let mut formatter = NasmFormatter::new();
        let mut formatted_inst = String::new();
        formatter.format(&inst, &mut formatted_inst);
        println!("[*] instruction: {}", formatted_inst);
        println!("[*] Memory Base: {:?}", inst.memory_base());
        assert_eq!(formatted_inst, "mov eax,[ebx+10h]");
        println!("---------------------");
        match apply_om_transform(&mut inst, 64) {
            Ok(result) => {
                for i in result {
                    formatted_inst.clear();
                    formatter.format(&mut i.clone(), &mut formatted_inst);
                    println!("[+] {}", formatted_inst);
                }
            }
            Err(e) => println!("[-] {e}"),
        };
    }

    #[test]
    fn test_apply_rs_transform() {
        println!("[*] Testing register swap...");
        let mut inst = Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::EBX)
            .expect("Instruction creation failed");
        let mut formatter = NasmFormatter::new();
        let mut formatted_inst = String::new();
        formatter.format(&inst, &mut formatted_inst);
        println!("[*] instruction: {}", formatted_inst);
        assert_eq!(formatted_inst, "mov eax,ebx");
        println!("---------------------");
        match apply_rs_transform(&mut inst, 32) {
            Ok(res) => {
                for i in res {
                    formatted_inst.clear();
                    formatter.format(&mut i.clone(), &mut formatted_inst);
                    println!("[+] {}", formatted_inst);
                }
            }
            Err(e) => println!("[-] {e}"),
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
