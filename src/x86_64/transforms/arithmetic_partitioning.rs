use crate::x86_64::helpers::*;
use crate::x86_64::DeoptimizerError;
use iced_x86::*;

/// Applies arithmetic partitioning transform to given instruction.
pub fn apply_ap_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, DeoptimizerError> {
    if !is_ap_compatible(inst) {
        return Err(DeoptimizerError::TransformNotPossible);
    }
    // We are looking for MOV/PUSH (=) ADD/ADC (+) SUB/SBB (-)
    let rip = inst.ip();
    let (imm, kind) = match inst.mnemonic() {
        Mnemonic::Push => (inst.immediate(0), inst.op0_kind()),
        _ => (inst.immediate(1), inst.op1_kind()),
    };
    let rand_imm_val = random_immediate_value(kind)?;
    let imm_delta: u64 = rand_imm_val.abs_diff(imm);
    let mut fix_inst = inst.clone();
    if inst.mnemonic() == Mnemonic::Push {
        let sp_reg = get_stack_pointer_register(bitness)?;
        let op0_size = get_op_size(0, inst)? * 8;
        fix_inst = Instruction::with2(
            get_code_with_str(&format!("Add_rm{bitness}_imm{op0_size}")),
            MemoryOperand::with_base(sp_reg),
            0,
        )?;
    }
    if inst.mnemonic() == Mnemonic::Pop {
        let mut info_factory = InstructionInfoFactory::new();
        let info = info_factory.info(&inst);
        let op0_size = get_op_size(0, inst)? * 8;
        let rand_reg =
            get_random_gp_register(bitness == 64, op0_size, Some(info.used_registers()))?;
        fix_inst = Instruction::with1(
            get_code_with_str(&format!("Xchg_rm{op0_size}_rm{op0_size}")),
            rand_reg,
        )?;
        return Ok(rencode(bitness, [*inst, fix_inst].to_vec(), rip)?);
    }
    if inst.mnemonic() == Mnemonic::Mov && inst.op1_kind() == OpKind::Immediate64 {
        set_op_immediate(inst, 1, !imm)?;
        fix_inst = Instruction::with1(get_code_with_str("Not_rm64"), inst.op0_register())?;
    } else {
        let (op0_size, op1_size) = match inst.mnemonic() {
            Mnemonic::Push => {
                set_op_immediate(inst, 0, rand_imm_val)?;
                (bitness as usize, get_op_size(0, inst)? * 8)
            }
            _ => {
                set_op_immediate(inst, 1, rand_imm_val)?;
                (get_op_size(0, inst)? * 8, get_op_size(1, inst)? * 8)
            }
        };
        if imm > rand_imm_val {
            match inst.mnemonic() {
                Mnemonic::Add | Mnemonic::Adc | Mnemonic::Mov | Mnemonic::Push => fix_inst
                    .set_code(get_code_with_str(&format!(
                        "Add_rm{op0_size}_imm{op1_size}"
                    ))),
                Mnemonic::Sub | Mnemonic::Sbb => fix_inst.set_code(get_code_with_str(&format!(
                    "Sub_rm{op0_size}_imm{op1_size}"
                ))),
                _ => return Err(DeoptimizerError::TransformNotPossible),
            }
        } else {
            match inst.mnemonic() {
                Mnemonic::Add | Mnemonic::Adc | Mnemonic::Mov | Mnemonic::Push => fix_inst
                    .set_code(get_code_with_str(&format!(
                        "Sub_rm{op0_size}_imm{op1_size}"
                    ))),
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
    (matches!(
        inst.mnemonic(),
        Mnemonic::Mov | Mnemonic::Add | Mnemonic::Adc | Mnemonic::Sub | Mnemonic::Sbb
    ) && is_immediate_operand(inst.op1_kind()))
        || (inst.mnemonic() == Mnemonic::Push && is_immediate_operand(inst.op0_kind()))
}
