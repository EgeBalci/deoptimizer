use crate::x86_64::DeoptimizerError;
use iced_x86::*;
use log::{debug, error, info, warn};
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

pub fn adjust_instruction_addr(code: &mut Vec<Instruction>, start_addr: u64) {
    let mut new_ip = start_addr;
    for inst in code.iter_mut() {
        inst.set_ip(new_ip);
        new_ip = inst.next_ip();
    }
}

pub fn rencode(
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
            Err(e) => {
                debug!("Encoding Error: {}", inst);
                return Err(e);
            }
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

pub fn is_using_fixed_register(inst: &Instruction) -> bool {
    let code_str = format!("{:?}", inst.code());
    for reg in Register::values() {
        if code_str.contains(&format!("{:?}", reg).to_string()) {
            return true;
        }
    }
    false
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

pub fn to_db_mnemonic(bytes: &[u8]) -> String {
    let mut db_inst = String::from("db ");
    for b in bytes.iter() {
        db_inst += &format!("0x{:02X}, ", b);
    }
    db_inst.trim_end_matches(", ").to_string()
}

pub fn get_register_save_seq(
    bitness: u32,
    reg: Register,
) -> Result<(Instruction, Instruction), DeoptimizerError> {
    let mut full_reg = reg.full_register();
    if bitness != 64 {
        full_reg = reg.full_register32();
    }
    let (c1, c2) = match bitness {
        16 => (Code::Push_r16, Code::Pop_r16),
        32 => (Code::Push_r32, Code::Pop_r32),
        64 => (Code::Push_r64, Code::Pop_r64),
        _ => return Err(DeoptimizerError::InvalidProcessorMode),
    };
    Ok((
        Instruction::with1(c1, full_reg)?,
        Instruction::with1(c2, full_reg)?,
    ))
}

pub fn get_random_register_value(reg: Register) -> u64 {
    let mut rng = rand::thread_rng();
    if reg.size() > 4 {
        // because its hard to handle 64 bit values
        return rng.gen_range(1..i32::MAX) as u64;
    }
    rng.gen_range(1..u64::pow(2, (reg.size() * 8) as u32)) as u64
}

pub fn set_op_immediate(
    inst: &mut Instruction,
    op_index: u32,
    imm: u64,
) -> Result<(), DeoptimizerError> {
    match inst.op_kind(op_index) {
        OpKind::Immediate8 => inst.set_immediate8(imm as u8),
        OpKind::Immediate8to16 => inst.set_immediate8to16(imm as i16),
        OpKind::Immediate8to32 => inst.set_immediate8to32(imm as i32),
        OpKind::Immediate8to64 => inst.set_immediate8to64(imm as i64),
        OpKind::Immediate8_2nd => inst.set_immediate8_2nd(imm as u8),
        OpKind::Immediate16 => inst.set_immediate16(imm as u16),
        OpKind::Immediate32 => inst.set_immediate32(imm as u32),
        OpKind::Immediate32to64 => inst.set_immediate32to64(imm as i64),
        OpKind::Immediate64 => inst.set_immediate64(imm),
        _ => return Err(DeoptimizerError::UnexpectedOperandType),
    };
    Ok(())
}

pub fn set_branch_target(
    inst: &Instruction,
    bt: u64,
    bitness: u32,
) -> Result<Instruction, DeoptimizerError> {
    let mut my_inst = inst.clone();

    if matches!(inst.op0_kind(), OpKind::FarBranch16 | OpKind::FarBranch32) {
        if bt < u16::MAX as u64 {
            my_inst.set_op0_kind(OpKind::FarBranch16);
            my_inst.set_far_branch16(bt as u16);
        } else if bt >= u16::MAX as u64 && bt < u32::MAX as u64 {
            my_inst.set_op0_kind(OpKind::FarBranch32);
            my_inst.set_near_branch32(bt as u32);
        } else {
            return Err(DeoptimizerError::FarBranchTooBig);
        }
        return Ok(*rencode(bitness, Vec::from([my_inst]), my_inst.ip())?
            .first()
            .unwrap());
    }

    match bitness {
        16 => {
            my_inst.set_op0_kind(OpKind::NearBranch16);
            my_inst.set_near_branch16(bt as u16);
        }
        32 => {
            my_inst.set_op0_kind(OpKind::NearBranch32);
            my_inst.set_near_branch32(bt as u32);
        }
        64 => {
            my_inst.set_op0_kind(OpKind::NearBranch64);
            my_inst.set_near_branch64(bt);
        }
        _ => return Err(DeoptimizerError::InvalidProcessorMode),
    }

    let diff = my_inst.next_ip().abs_diff(bt);
    if diff > i8::MAX as u64 {
        my_inst.as_near_branch();
    }

    Ok(*rencode(bitness, Vec::from([my_inst]), my_inst.ip())?
        .first()
        .unwrap())
}

pub fn get_branch_target(inst: &Instruction) -> Result<u64, DeoptimizerError> {
    let nbt = inst.near_branch_target();
    if nbt != 0 {
        return Ok(nbt);
    }

    Ok(match inst.op0_kind() {
        OpKind::FarBranch32 => inst.far_branch32() as u64,
        OpKind::FarBranch16 => inst.far_branch16() as u64,
        _ => return Err(DeoptimizerError::BracnhTargetNotFound),
    })
}

pub fn get_random_gp_register(
    extended: bool,
    size: usize,
    exclude_list: Option<&[UsedRegister]>,
) -> Result<Register, DeoptimizerError> {
    if !extended && size > 4 {
        return Err(DeoptimizerError::UnexpectedRegisterSize);
    }

    let mut gpr8 = Vec::new();
    let mut gpr16 = Vec::new();
    let mut gpr32 = Vec::new();
    let mut gpr64 = Vec::new();

    for r in Register::values() {
        if r.is_segment_register() || r.full_register() == Register::RSP {
            continue;
        }
        if r.is_gpr8() {
            gpr8.push(r);
            continue;
        }
        if r.is_gpr16() {
            gpr16.push(r);
            continue;
        }
        if r.is_gpr32() {
            // We don't want stack pointers
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
        _ => return Err(DeoptimizerError::UnexpectedRegisterSize),
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
    Err(DeoptimizerError::RegisterNotFound)
}

pub fn get_op_size(op: u32, inst: &Instruction) -> Result<usize, DeoptimizerError> {
    // let op_size = match inst.op_kind(op) {
    //     OpKind::Memory => inst.memory_size().element_size(),
    //     OpKind::Register => inst.op0_register().size(),
    //     OpKind::Immediate8 => 1,
    //     OpKind::Immediate8to16 => 2,
    //     OpKind::Immediate8to32 => 4,
    //     OpKind::Immediate8to64 => 8,
    //     OpKind::Immediate8_2nd => 1,
    //     OpKind::Immediate16 => 2,
    //     OpKind::Immediate32 => 4,
    //     OpKind::Immediate32to64 => 8,
    //     OpKind::Immediate64 => 8,
    //     _ => return Err(DeoptimizerError::UnexpectedOperandType),
    // };

    let op_size = match inst.op_kind(op) {
        OpKind::Memory => inst.memory_size().element_size(),
        OpKind::Register => inst.op0_register().size(),
        OpKind::Immediate8
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate8_2nd => 1,
        OpKind::Immediate16 => 2,
        OpKind::Immediate32 => 4,
        OpKind::Immediate32to64 => 4,
        OpKind::Immediate64 => 8,
        _ => return Err(DeoptimizerError::UnexpectedOperandType),
    };
    Ok(op_size)
}

pub fn get_code_with_str(code_str: &str) -> Code {
    for c in Code::values() {
        if format!("{:?}", c).to_lowercase() == code_str.to_lowercase() {
            return c;
        }
    }
    Code::INVALID
}

pub fn get_code_with_template(mnemonic: Mnemonic, inst: &Instruction) -> Code {
    let new_code = format!("{:?}", inst.code()).replace(
        &format!("{:?}", inst.mnemonic()),
        &format!("{:?}", mnemonic),
    );
    get_code_with_str(new_code.as_str())
}
