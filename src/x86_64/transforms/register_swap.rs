use crate::x86_64::helpers::*;
use crate::x86_64::DeoptimizerError;
use iced_x86::*;
use rand::prelude::SliceRandom;

/// Applies register swapping transform to given instruction.
pub fn apply_rs_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, DeoptimizerError> {
    if !inst
        .op_kinds()
        .collect::<Vec<OpKind>>()
        .contains(&OpKind::Register)
        || inst.is_stack_instruction()
    {
        return Err(DeoptimizerError::TransformNotPossible);
    }

    // We need to fix the code if it is spesific to any register
    if is_using_fixed_register(inst) && is_immediate_operand(inst.op1_kind()) {
        let code = format!("{:?}", inst.code());
        for (i, op) in inst.op_kinds().enumerate() {
            if op == OpKind::Register {
                let reg = inst.op_register(i as u32);
                let new_op_kind = &format!("rm{}", reg.size() * 8);
                inst.set_code(get_code_with_str(
                    &code.replace(&format!("{:?}", reg), new_op_kind),
                ));
            }
        }
    }
    let rip = inst.ip();
    let mut info_factory = InstructionInfoFactory::new();
    let info = info_factory.info(&inst);

    let mut used_regs = Vec::new();
    for r in info.used_registers() {
        if r.register().is_segment_register() {
            continue;
        }
        used_regs.push(r.register());
    }
    let swap_reg = *used_regs.choose(&mut rand::thread_rng()).unwrap();
    let rand_reg =
        get_random_gp_register(bitness == 64, swap_reg.size(), Some(info.used_registers()))?;
    for i in 0..inst.op_count() {
        if inst.op_kind(i) == OpKind::Register && inst.op_register(i) == swap_reg {
            inst.set_op_register(i, rand_reg);
        }
    }
    let xchg_code = get_code_with_str(&format!(
        "Xchg_rm{}_r{}",
        swap_reg.size() * 8,
        swap_reg.size() * 8
    ));
    let xchg = Instruction::with2(xchg_code, swap_reg, rand_reg)?;

    Ok(rencode(bitness, [xchg, inst.clone(), xchg].to_vec(), rip)?)
}
