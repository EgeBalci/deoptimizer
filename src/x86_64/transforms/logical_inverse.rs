use crate::x86_64::helpers::*;
use crate::x86_64::DeoptimizerError;
use iced_x86::*;

/// Applies logical inverse transform to given instruction.
pub fn apply_li_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, DeoptimizerError> {
    if !is_li_compatible(inst) || !is_immediate_operand(inst.op1_kind()) || inst.op_count() != 2 {
        return Err(DeoptimizerError::TransformNotPossible);
    }
    // We are looking for XOR (^) AND (&) OR (|)
    let rip = inst.ip();
    let mnemonic = inst.mnemonic();
    let imm = inst.immediate(1);
    if imm == 0 {
        // Unlikely but possible...
        return Ok(Vec::from([Instruction::with(Code::Nopd)]));
    }

    let op0_size = get_op_size(0, inst)? * 8;
    let op1_size = get_op_size(1, inst)? * 8;
    let result = match mnemonic {
        Mnemonic::Xor => {
            set_op_immediate(inst, 1, !imm)?;
            let mut not = inst.clone();
            not.set_code(get_code_with_str(&format!("Not_rm{op0_size}")));
            [not, *inst].to_vec()
        }
        Mnemonic::And => {
            let mut or = inst.clone();
            or.set_code(get_code_with_str(&format!("Or_rm{op0_size}_imm{op1_size}")));
            set_op_immediate(&mut or, 1, !imm)?;
            let mut not = inst.clone();
            not.set_code(get_code_with_str(&format!("Not_rm{op0_size}")));
            [not, or, not].to_vec()
        }
        Mnemonic::Or => {
            let mut and = inst.clone();
            and.set_code(get_code_with_str(&format!(
                "And_rm{op0_size}_imm{op1_size}"
            )));
            set_op_immediate(&mut and, 1, !imm)?;
            let mut not = inst.clone();
            not.set_code(get_code_with_str(&format!("Not_rm{op0_size}")));
            [not, and, not].to_vec()
        }
        _ => return Err(DeoptimizerError::TransformNotPossible),
    };
    Ok(rencode(bitness, result, rip)?)
}

pub fn is_li_compatible(inst: &Instruction) -> bool {
    matches!(
        inst.mnemonic(),
        Mnemonic::And | Mnemonic::Or | Mnemonic::Xor
    )
}
