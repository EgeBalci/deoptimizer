use crate::x86_64::helpers::*;
use crate::x86_64::DeoptimizerError;
use iced_x86::*;

/// Applies arithmetic partitioning transform to given instruction.
pub fn apply_ap_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, DeoptimizerError> {
    if !is_ap_compatible(inst) || !is_immediate_operand(inst.op1_kind()) || inst.op_count() != 2 {
        return Err(DeoptimizerError::TransformNotPossible);
    }
    // We are looking for MOV (=) ADD/ADC (+) SUB/SBB (-)
    let rip = inst.ip();
    let imm = inst.immediate(1);
    let rand_imm_val = randomize_immediate_value(imm);
    let imm_delta: u64 = rand_imm_val.abs_diff(imm);
    let mut fix_inst = inst.clone();
    if inst.mnemonic() == Mnemonic::Mov && inst.op1_kind() == OpKind::Immediate64 {
        set_op_immediate(inst, 1, !imm)?;
        fix_inst = Instruction::with1(get_code_with_str("Not_rm64"), inst.op0_register())?;
    } else {
        set_op_immediate(inst, 1, rand_imm_val)?;
        let op0_size = get_op_size(0, inst)? * 8;
        let op1_size = get_op_size(1, inst)? * 8;
        println!("code: {:?}", inst.code());
        println!(
            "op1_kind: {:?} {op1_size}",
            inst.code().op_code().op1_kind()
        );
        if imm > rand_imm_val {
            match inst.mnemonic() {
                Mnemonic::Add | Mnemonic::Adc | Mnemonic::Mov => fix_inst.set_code(
                    get_code_with_str(&format!("Sub_rm{op0_size}_imm{op1_size}")),
                ),
                Mnemonic::Sub | Mnemonic::Sbb => fix_inst.set_code(get_code_with_str(&format!(
                    "Add_rm{op0_size}_imm{op1_size}"
                ))),
                _ => return Err(DeoptimizerError::TransformNotPossible),
            }
        } else {
            match inst.mnemonic() {
                Mnemonic::Add | Mnemonic::Adc | Mnemonic::Mov => fix_inst.set_code(
                    get_code_with_str(&format!("Sub_rm{op0_size}_imm{op1_size}")),
                ),
                Mnemonic::Sub | Mnemonic::Sbb => fix_inst.set_code(get_code_with_str(&format!(
                    "Add_rm{op0_size}_imm{op1_size}"
                ))),
                _ => return Err(DeoptimizerError::TransformNotPossible),
            }
        }
        set_op_immediate(&mut fix_inst, 1, imm_delta)?;
    }
    Ok(rencode(bitness, [*inst, fix_inst].to_vec(), rip)?)
}

pub fn is_ap_compatible(inst: &Instruction) -> bool {
    matches!(
        inst.mnemonic(),
        Mnemonic::Mov | Mnemonic::Add | Mnemonic::Adc | Mnemonic::Sub | Mnemonic::Sbb
    )
}
