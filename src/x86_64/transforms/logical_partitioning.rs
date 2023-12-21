use crate::x86_64::helpers::*;
use crate::x86_64::DeoptimizerError;
use iced_x86::*;
use rand::Rng;

/// Applies logical partitioning transform to given instruction.
pub fn apply_lp_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, DeoptimizerError> {
    if !is_lp_compatible(inst) || !is_immediate_operand(inst.op1_kind()) || inst.op_count() != 2 {
        return Err(DeoptimizerError::TransformNotPossible);
    }
    // We are looking for SHR/SAR (>) SHL/SAL (<) ROR/RCR (>>) ROL/RCL (<<)
    let rip = inst.ip();
    let mnemonic = inst.mnemonic();
    let mut imm = inst.immediate(1);
    let op0_size = get_op_size(0, inst)?;
    if imm == 0 {
        // Unlikely but possible...
        return Ok(Vec::from([Instruction::with(Code::Nopd)]));
    }
    let result = match mnemonic {
        Mnemonic::Shr | Mnemonic::Sar | Mnemonic::Shl | Mnemonic::Sal => {
            if imm == 1 {
                // This is simple x2 or /2
                match mnemonic {
                    Mnemonic::Shr | Mnemonic::Sar => {
                        let mut and = inst.clone();
                        let mut op1_size = op0_size * 8;
                        if op1_size == 64 {
                            op1_size = 32;
                        }
                        and.set_code(get_code_with_str(&format!(
                            "And_rm{}_imm{}",
                            op0_size * 8,
                            op1_size
                        )));
                        let new_imm = u64::pow(2, (op0_size * 8) as u32 - 1) + 1;
                        match op0_size {
                            1 => {
                                and.set_immediate8(new_imm as u8);
                                and.set_op1_kind(OpKind::Immediate8);
                            }
                            2 => {
                                and.set_immediate16(new_imm as u16);
                                and.set_op1_kind(OpKind::Immediate16);
                            }
                            4 => {
                                and.set_immediate32(new_imm as u32);
                                and.set_op1_kind(OpKind::Immediate32);
                            }
                            8 => {
                                and.set_immediate32to64(-2);
                                and.set_op1_kind(OpKind::Immediate32to64);
                            }
                            _ => return Err(DeoptimizerError::TransformNotPossible),
                        }
                        if mnemonic == Mnemonic::Shr {
                            inst.set_code(get_code_with_template(Mnemonic::Ror, inst));
                            [and, *inst].to_vec()
                        } else {
                            inst.set_code(get_code_with_template(Mnemonic::Rcr, inst));
                            [and, *inst].to_vec()
                        }
                    }
                    Mnemonic::Shl => {
                        let add_code = match op0_size {
                            1 => Code::Add_rm8_r8,
                            2 => Code::Add_rm16_r16,
                            4 => Code::Add_rm32_r32,
                            8 => Code::Add_rm64_r64,
                            _ => return Err(DeoptimizerError::TransformNotPossible),
                        };
                        let add =
                            Instruction::with2(add_code, inst.op0_register(), inst.op0_register())?;
                        [add].to_vec()
                    }
                    Mnemonic::Sal => {
                        let adc_code = match op0_size {
                            1 => Code::Adc_rm8_r8,
                            2 => Code::Adc_rm16_r16,
                            4 => Code::Adc_rm32_r32,
                            8 => Code::Adc_rm64_r64,
                            _ => return Err(DeoptimizerError::TransformNotPossible),
                        };
                        let adc =
                            Instruction::with2(adc_code, inst.op0_register(), inst.op0_register())?;
                        [adc].to_vec()
                    }
                    _ => return Err(DeoptimizerError::TransformNotPossible),
                }
            } else {
                if imm.is_power_of_two() {
                    let mut shift1 = inst.clone();
                    let mut shift2 = inst.clone();
                    shift1.set_immediate8(imm as u8 / 2);
                    shift2.set_immediate8(imm as u8 / 2);
                    [shift1, shift2].to_vec()
                } else {
                    let mut shift1 = inst.clone();
                    let mut shift2 = inst.clone();
                    shift1.set_immediate8(((imm - 1) as u8 / 2) + 1);
                    shift2.set_immediate8((imm - 1) as u8 / 2);
                    [shift1, shift2].to_vec()
                }
            }
        }
        Mnemonic::Ror | Mnemonic::Rcr | Mnemonic::Rol | Mnemonic::Rcl => {
            let dst_op_size = match inst.op0_kind() {
                OpKind::Memory => (inst.memory_size().element_size() * 8) as u64,
                OpKind::Register => (inst.op0_register().size() * 8) as u64,
                _ => return Err(DeoptimizerError::InvalidTemplate),
            };
            imm = imm % dst_op_size;
            let pow = rand::thread_rng().gen_range(2..(u8::MAX as u64 / dst_op_size) as u8);
            inst.set_immediate8((dst_op_size * pow as u64 + imm) as u8);
            [*inst].to_vec()
        }
        _ => return Err(DeoptimizerError::TransformNotPossible),
    };
    Ok(rencode(bitness, result, rip)?)
}

pub fn is_lp_compatible(inst: &Instruction) -> bool {
    matches!(
        inst.mnemonic(),
        Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Shl
            | Mnemonic::Sal
            | Mnemonic::Rol
            | Mnemonic::Rcl
            | Mnemonic::Ror
            | Mnemonic::Rcr
    )
}
