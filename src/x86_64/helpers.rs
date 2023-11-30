use crate::x86_64::TransformError;
use iced_x86::*;
use rand::thread_rng;
use rand::{seq::SliceRandom, Rng};

use super::DeoptimizerError;

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

pub fn encode(
    bitness: u32,
    insts: Vec<Instruction>,
    rip: u64,
) -> Result<Vec<Instruction>, IcedError> {
    let mut buffer = Vec::new();
    let mut result = Vec::new();
    for inst in insts.clone() {
        let mut encoder = Encoder::new(bitness);
        match encoder.encode(&inst, inst.ip()) {
            Ok(_) => buffer = [buffer, encoder.take_buffer()].concat(),
            Err(e) => return Err(e),
        };
    }
    let mut decoder = Decoder::new(bitness, &buffer, DecoderOptions::NONE);
    decoder.set_ip(rip);
    let mut inst = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut inst);
        result.push(inst);
    }

    Ok(result)
}

pub fn is_using_static_register(inst: &Instruction) -> bool {
    if !matches!(
        inst.mnemonic(),
        Mnemonic::In
            | Mnemonic::Out
            | Mnemonic::Outsb
            | Mnemonic::Outsd
            | Mnemonic::Outsw
            | Mnemonic::Or
            | Mnemonic::Adc
            | Mnemonic::Add
            | Mnemonic::And
            | Mnemonic::Cmp
            | Mnemonic::Sbb
            | Mnemonic::Sub
            | Mnemonic::Xor
            | Mnemonic::Mov
            | Mnemonic::Test
            | Mnemonic::Lodsb
            | Mnemonic::Scasb
    ) {
        return false;
    }

    if matches!(
        inst.op0_register(),
        Register::AL | Register::AX | Register::EAX
    ) {
        return true;
    }

    if inst.op_count() > 0 && inst.op0_kind() == OpKind::Register {
        if matches!(
            inst.mnemonic(),
            Mnemonic::In | Mnemonic::Out | Mnemonic::Outsb | Mnemonic::Outsd | Mnemonic::Outsw
        ) && inst.op0_register() == Register::DX
        {
            return true;
        }
    }
    false
}

pub fn is_ap_compatible(inst: &Instruction) -> bool {
    matches!(
        inst.mnemonic(),
        Mnemonic::Mov | Mnemonic::Add | Mnemonic::Adc | Mnemonic::Sub | Mnemonic::Sbb
    )
}

pub fn is_li_compatible(inst: &Instruction) -> bool {
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

pub fn get_aprx_immediate_size(imm: u64) -> OpKind {
    if imm <= u8::MAX as u64 {
        return OpKind::Immediate8;
    } else if imm > u8::MAX as u64 && imm <= u16::MAX as u64 {
        return OpKind::Immediate16;
    } else if imm > u16::MAX as u64 && imm <= u32::MAX as u64 {
        return OpKind::Immediate32;
    } else if imm > u32::MAX as u64 && imm <= u64::MAX {
        return OpKind::Immediate64;
    } else {
        return OpKind::Immediate8to64;
    }
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
        return rng.gen_range(1..i32::MAX) as u64;
    }
    rng.gen_range(1..i64::pow(2, (reg.size() * 8) as u32)) as u64
}

pub fn set_op1_immediate(inst: &mut Instruction, imm: u64) -> Result<(), TransformError> {
    match inst.op1_kind() {
        OpKind::Immediate8 => inst.set_immediate8(imm as u8),
        OpKind::Immediate8to16 => inst.set_immediate8to16(imm as i16),
        OpKind::Immediate8to32 => inst.set_immediate8to32(imm as i32),
        OpKind::Immediate8to64 => inst.set_immediate8to64(imm as i64),
        OpKind::Immediate8_2nd => inst.set_immediate8_2nd(imm as u8),
        OpKind::Immediate16 => inst.set_immediate16(imm as u16),
        OpKind::Immediate32 => inst.set_immediate32(imm as u32),
        OpKind::Immediate32to64 => inst.set_immediate32to64(imm as i64),
        OpKind::Immediate64 => inst.set_immediate64(imm),
        _ => return Err(TransformError::UnexpectedImmediateSize),
    };
    Ok(())
}

pub fn set_branch_target(inst: &mut Instruction, bt: u64) -> Result<(), DeoptimizerError> {
    if matches!(inst.op0_kind(), OpKind::FarBranch16 | OpKind::FarBranch32) {
        if bt < u16::MAX as u64 {
            inst.set_op0_kind(OpKind::FarBranch16);
            inst.set_far_branch16(bt as u16);
        } else if bt >= u16::MAX as u64 && bt < u32::MAX as u64 {
            inst.set_op0_kind(OpKind::FarBranch32);
            inst.set_near_branch32(bt as u32);
        } else {
            return Err(DeoptimizerError::FarBranchTooBig);
        }
        return Ok(());
    }
    if bt < u16::MAX as u64 {
        inst.set_op0_kind(OpKind::NearBranch16);
        inst.set_near_branch16(bt as u16);
    } else if bt >= u16::MAX as u64 && bt < u32::MAX as u64 {
        inst.set_op0_kind(OpKind::NearBranch32);
        inst.set_near_branch32(bt as u32);
    } else if bt >= u32::MAX as u64 && bt < u64::MAX {
        inst.set_op0_kind(OpKind::NearBranch64);
        inst.set_near_branch64(bt);
    } else {
        return Err(DeoptimizerError::NearBranchTooBig);
    }
    Ok(())
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
        if r.is_gpr32() && r != Register::ESP {
            // We don't want stack pointers
            gpr32.push(r);
            continue;
        }
        if r.is_gpr64() && r != Register::RSP {
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

pub fn get_code_with_template(
    mnemonic: Mnemonic,
    inst: &Instruction,
) -> Result<Code, TransformError> {
    if (inst.op_count() != 2 && inst.op_count() != 1) || !is_immediate_operand(inst.op1_kind()) {
        return Err(TransformError::InvalidTemplate);
    }
    let dst_op_size = match inst.op0_kind() {
        OpKind::Memory => inst.memory_size().element_size(),
        OpKind::Register => inst.op0_register().size(),
        _ => return Err(TransformError::InvalidTemplate),
    };

    Ok(get_code_with_size(mnemonic, dst_op_size)?)
}

pub fn get_code_with_size(mnemonic: Mnemonic, size: usize) -> Result<Code, TransformError> {
    let c = match mnemonic {
        Mnemonic::Add => match size {
            1 => Code::Add_rm8_imm8,
            2 => Code::Add_rm16_imm16,
            4 => Code::Add_rm32_imm32,
            8 => Code::Add_rm64_imm32,
            _ => return Err(TransformError::InvalidTemplate),
        },
        Mnemonic::Adc => match size {
            1 => Code::Adc_rm8_imm8,
            2 => Code::Adc_rm16_imm16,
            4 => Code::Adc_rm32_imm32,
            8 => Code::Adc_rm64_imm32,
            _ => return Err(TransformError::InvalidTemplate),
        },
        Mnemonic::Sub => match size {
            1 => Code::Sub_rm8_imm8,
            2 => Code::Sub_rm16_imm16,
            4 => Code::Sub_rm32_imm32,
            8 => Code::Sub_rm64_imm32,
            _ => return Err(TransformError::InvalidTemplate),
        },
        Mnemonic::Xor => match size {
            1 => Code::Xor_rm8_imm8,
            2 => Code::Xor_rm16_imm16,
            4 => Code::Xor_rm32_imm32,
            8 => Code::Xor_rm64_imm32,
            _ => return Err(TransformError::InvalidTemplate),
        },
        Mnemonic::And => match size {
            1 => Code::And_rm8_imm8,
            2 => Code::And_rm16_imm16,
            4 => Code::And_rm32_imm32,
            8 => Code::And_rm64_imm32,
            _ => return Err(TransformError::InvalidTemplate),
        },
        Mnemonic::Or => match size {
            1 => Code::Or_rm8_imm8,
            2 => Code::Or_rm16_imm16,
            4 => Code::Or_rm32_imm32,
            8 => Code::Or_rm64_imm32,
            _ => return Err(TransformError::InvalidTemplate),
        },
        Mnemonic::Not => match size {
            1 => Code::Not_rm8,
            2 => Code::Not_rm16,
            4 => Code::Not_rm32,
            8 => Code::Not_rm64,
            _ => return Err(TransformError::InvalidTemplate),
        },
        Mnemonic::Mov => match size {
            1 => Code::Mov_rm8_imm8,
            2 => Code::Mov_rm16_imm16,
            4 => Code::Mov_rm32_imm32,
            8 => Code::Mov_rm64_imm32,
            _ => return Err(TransformError::InvalidTemplate),
        },
        Mnemonic::Cmp => match size {
            1 => Code::Cmp_rm8_imm8,
            2 => Code::Cmp_rm16_imm16,
            4 => Code::Cmp_rm32_imm32,
            8 => Code::Cmp_rm64_imm32,
            _ => return Err(TransformError::InvalidTemplate),
        },
        Mnemonic::Test => match size {
            1 => Code::Test_rm8_imm8,
            2 => Code::Test_rm16_imm16,
            4 => Code::Test_rm32_imm32,
            8 => Code::Test_rm64_imm32,
            _ => return Err(TransformError::InvalidTemplate),
        },
        _ => return Err(TransformError::InvalidTemplate),
    };
    Ok(c)
}

pub fn to_db_mnemonic(bytes: &[u8]) -> String {
    let mut db_inst = String::from("db ");
    for b in bytes.iter() {
        db_inst += &format!("0x{:02X}, ", b);
    }
    db_inst.trim_end_matches(", ").to_string()
}
