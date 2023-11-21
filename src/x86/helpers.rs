use crate::x86::TransformError;
use iced_x86::{
    Code, ConditionCode, Decoder, DecoderOptions, Formatter, GasFormatter, IcedError, Instruction,
    InstructionInfoFactory, IntelFormatter, MasmFormatter, MemoryOperand, Mnemonic, NasmFormatter,
    OpAccess, OpKind, Register, RegisterInfo, RflagsBits, UsedRegister,
};
use rand::thread_rng;
use rand::{seq::SliceRandom, Rng};

pub fn randomize_immediate_value(imm: u64) -> u64 {
    let mut rng = rand::thread_rng();
    if imm < u8::MAX as u64 {
        rng.gen_range(1..u8::MAX) as u64
    } else if imm > u8::MAX as u64 && imm < u16::MAX as u64 {
        rng.gen_range(u8::MAX as u16..u16::MAX) as u64
    } else if imm > u16::MAX as u64 && imm < u32::MAX as u64 {
        rng.gen_range(u16::MAX as u32..u32::MAX) as u64
    } else {
        rng.gen_range(u32::MAX as u64..u64::MAX) as u64
    }
}

pub fn get_inverse_mnemonic(inst: &Instruction) -> Option<Mnemonic> {
    let ret = match inst.mnemonic() {
        Mnemonic::Add => Mnemonic::Sub,
        Mnemonic::Sub => Mnemonic::Add,
        Mnemonic::Sbb => Mnemonic::Adc,
        Mnemonic::Adc => Mnemonic::Sbb,
        Mnemonic::Rol => Mnemonic::Ror,
        Mnemonic::Ror => Mnemonic::Rol,
        Mnemonic::Xor => Mnemonic::Xor,
        Mnemonic::Inc => Mnemonic::Dec,
        Mnemonic::Dec => Mnemonic::Inc,
        Mnemonic::Or => Mnemonic::And,
        Mnemonic::And => Mnemonic::Or,
        Mnemonic::Shr => Mnemonic::Shl,
        Mnemonic::Shl => Mnemonic::Shr,
        Mnemonic::Not => Mnemonic::Not,
        _ => return None,
    };
    Some(ret)
}

pub fn is_ap_safe_instruction(inst: &Instruction) -> bool {
    matches!(
        inst.mnemonic(),
        Mnemonic::Mov | Mnemonic::Add | Mnemonic::Adc | Mnemonic::Sub | Mnemonic::Sbb
    )
}

pub fn is_li_safe_instruction(inst: &Instruction) -> bool {
    matches!(
        inst.mnemonic(),
        Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Shl
            | Mnemonic::Sal
            | Mnemonic::Rol
            | Mnemonic::Rcl
            | Mnemonic::Ror
            | Mnemonic::Rcr
    )
}

pub fn get_random_arithmetic_mnemonic() -> Mnemonic {
    let arithmetics = Vec::from([
        Mnemonic::Mov,
        Mnemonic::Add,
        Mnemonic::Sub,
        Mnemonic::Cmp,
        Mnemonic::Adc,
        Mnemonic::Sbb,
        Mnemonic::Inc,
        Mnemonic::Dec,
    ]);
    *arithmetics.choose(&mut rand::thread_rng()).unwrap()
}

pub fn get_immediate_indexes(inst: &Instruction) -> Option<Vec<u32>> {
    let mut indexes = Vec::new();
    for i in 0..inst.op_count() {
        if is_immediate_operand(inst.op_kind(i)) {
            indexes.push(i);
        }
    }
    if indexes.len() == 0 {
        return None;
    }
    Some(indexes)
}

pub fn is_immediate_operand(op: OpKind) -> bool {
    matches!(
        op,
        OpKind::Immediate8_2nd
            | OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
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
}

pub fn get_random_gp_register(
    extended: bool,
    size: usize,
    exclude_list: Option<&[UsedRegister]>,
) -> Result<Register, TransformError> {
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

    let mut shuffed_regs = match size {
        1 => {
            gpr8.shuffle(&mut thread_rng());
            gpr8
        }
        2 => {
            gpr16.shuffle(&mut thread_rng());
            gpr16
        }
        4 => {
            gpr32.shuffle(&mut thread_rng());
            gpr32
        }
        8 => {
            gpr64.shuffle(&mut thread_rng());
            gpr64
        }
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };

    // Remove excluded registers
    if let Some(list) = exclude_list {
        for ex in list {
            let index = shuffed_regs.iter().position(|x| *x == ex.register());
            if index.is_some() {
                shuffed_regs.remove(index.unwrap());
            }
        }
    }

    for reg in shuffed_regs {
        let reg_str = format!("{:?}", reg);
        let is_extended = reg_str.contains("R") || reg_str.contains("IL") || reg_str.contains("PL");
        if is_extended == extended {
            return Ok(reg);
        }
    }
    Err(TransformError::RegisterNotFound)
}
pub fn get_xor_code_with(reg: Register) -> Result<Code, TransformError> {
    let c = match reg.size() {
        1 => Code::Xor_rm8_imm8,
        2 => Code::Xor_rm16_imm16,
        4 | 8 => Code::Xor_rm32_imm32,
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };
    Ok(c)
}
pub fn get_and_code_with(reg: Register) -> Result<Code, TransformError> {
    let c = match reg.size() {
        1 => Code::And_rm8_imm8,
        2 => Code::And_rm16_imm16,
        4 | 8 => Code::And_rm32_imm32,
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };
    Ok(c)
}
pub fn get_or_code_with(reg: Register) -> Result<Code, TransformError> {
    let c = match reg.size() {
        1 => Code::Or_rm8_imm8,
        2 => Code::Or_rm16_imm16,
        4 | 8 => Code::Or_rm32_imm32,
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };
    Ok(c)
}

pub fn get_not_code_with(reg: Register) -> Result<Code, TransformError> {
    let c = match reg.size() {
        1 => Code::Not_rm8,
        2 => Code::Not_rm16,
        4 => Code::Not_rm32,
        8 => Code::Not_rm64,
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };
    Ok(c)
}

pub fn get_add_code_with(reg: Register) -> Result<Code, TransformError> {
    let c = match reg.size() {
        1 => Code::Add_rm8_imm8,
        2 => Code::Add_rm16_imm16,
        4 | 8 => Code::Add_rm32_imm32,
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };
    Ok(c)
}

pub fn get_sub_code_with(reg: Register) -> Result<Code, TransformError> {
    let c = match reg.size() {
        1 => Code::Sub_rm8_imm8,
        2 => Code::Sub_rm16_imm16,
        4 | 8 => Code::Sub_rm32_imm32,
        _ => return Err(TransformError::UnexpectedRegisterSize),
    };
    Ok(c)
}
