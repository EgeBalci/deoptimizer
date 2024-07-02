use crate::x86_64::helpers::*;
use crate::x86_64::DeoptimizerError;
use iced_x86::*;
use rand::prelude::SliceRandom;

/// Applies register swapping transform to given instruction.
pub fn apply_rs_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, DeoptimizerError> {
    if !is_rs_compatible(inst) {
        return Err(DeoptimizerError::TransformNotPossible);
    }
    // We need to fix the code if it is spesific to any register
    transpose_fixed_register_operand(inst)?;
    let rip = inst.ip();
    let mut info_factory = InstructionInfoFactory::new();
    let info = info_factory.info(inst);
    let mut used_regs = Vec::new();
    for i in 0..inst.op_count() {
        if inst.op_kind(i) != OpKind::Register {
            continue;
        }
        if !(inst.op_register(i).size() * 8 == 32 && bitness == 64) {
            used_regs.push(inst.op_register(i));
        }
    }

    if used_regs.is_empty() {
        return Err(DeoptimizerError::TransformNotPossible);
    }
    let swap_reg = *used_regs.choose(&mut rand::thread_rng()).unwrap();
    let rand_reg =
        get_random_gp_register(bitness == 64, swap_reg.size(), Some(info.used_registers()))?;
    for i in 0..inst.op_count() {
        if inst.op_kind(i) == OpKind::Register && inst.op_register(i) == swap_reg
            || inst.op_register(i).full_register() == swap_reg
        {
            inst.set_op_register(i, rand_reg);
        }
    }
    let xchg_code = get_code_with_str(&format!(
        "Xchg_rm{}_r{}",
        swap_reg.size() * 8,
        swap_reg.size() * 8
    ));
    let xchg = Instruction::with2(xchg_code, swap_reg, rand_reg)?;
    Ok(rencode(bitness, [xchg, *inst, xchg].to_vec(), rip)?)
}

pub fn is_rs_compatible(inst: &Instruction) -> bool {
    let mut info_factory = InstructionInfoFactory::new();
    let info = info_factory.info(inst);
    for r in info.used_registers() {
        if r.register().full_register() == Register::RSP {
            return false;
        }
    }

    !(!inst
        .op_kinds()
        .collect::<Vec<OpKind>>()
        .contains(&OpKind::Register)
        || inst
            .op_kinds()
            .collect::<Vec<OpKind>>()
            .contains(&OpKind::Memory)
        || inst.op_count() < 2
        || inst.is_jcc_short_or_near()
        || inst.is_loop()
        || inst.is_loopcc()
        || inst.mnemonic() == Mnemonic::Call
        || inst.is_string_instruction()
        || inst.is_stack_instruction())
}
