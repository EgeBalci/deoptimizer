use crate::x86_64::helpers::*;
use crate::x86_64::DeoptimizerError;
use iced_x86::*;

/// Applies offset mutation to given instruction.
/// Note: This transform may clobber the CFLAGS!
/// avoid using with CF altering instructions.
pub fn apply_om_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, DeoptimizerError> {
    // First check the operand types.
    let base_reg = inst.memory_base();
    if !is_om_compatible(inst) {
        return Err(DeoptimizerError::TransformNotPossible);
    }
    let rip = inst.ip();
    let mem_disp = inst.memory_displacement64();
    let rand_val = get_random_register_value(base_reg);
    let op0_size = base_reg.size() * 8;
    let mut op1_size = op0_size;
    if op1_size == 64 {
        op1_size = 32;
    }
    let new_mem_disp_sign = rand_val as i32 > 0; // The sign of the memory displacement
    let old_mem_disp_sign = mem_disp as i32 > 0; // The sign of the memory displacement
    let abs_old_mem_disp = match old_mem_disp_sign {
        true => mem_disp,
        false => (mem_disp as i32).abs() as u64,
    };
    let (c1, c2) = match new_mem_disp_sign {
        true => (
            get_code_with_str(&format!("Sub_rm{op0_size}_imm{op1_size}")),
            get_code_with_str(&format!("Add_rm{op0_size}_imm{op1_size}")),
        ),
        false => (
            get_code_with_str(&format!("Add_rm{op0_size}_imm{op1_size}")),
            get_code_with_str(&format!("Sub_rm{op0_size}_imm{op1_size}")),
        ),
    };

    let fix_val = match (new_mem_disp_sign, old_mem_disp_sign) {
        (true, true) => mem_disp.abs_diff(rand_val),
        (false, false) => match base_reg.size() {
            1 => ((rand_val as i8).abs() as u64).abs_diff(abs_old_mem_disp),
            2 => ((rand_val as i16).abs() as u64).abs_diff(abs_old_mem_disp),
            _ => ((rand_val as i32).abs() as u64).abs_diff(abs_old_mem_disp),
        },
        (true, false) | (false, true) => match base_reg.size() {
            1 => ((rand_val as i8).abs() as u64) + abs_old_mem_disp,
            2 => ((rand_val as i16).abs() as u64) + abs_old_mem_disp,
            _ => ((rand_val as i32).abs() as u64) + abs_old_mem_disp,
        },
    };

    let mut pre_inst = Instruction::with2(c1, base_reg, 0)?;
    set_op_immediate(&mut pre_inst, 1, fix_val)?;
    let mut post_inst = Instruction::with2(c2, base_reg, 0)?;
    set_op_immediate(&mut post_inst, 1, fix_val)?;

    inst.set_memory_displ_size(bitness / 8);
    inst.set_memory_displacement64(rand_val);
    let mut result = [pre_inst, inst.clone()].to_vec();
    if base_reg.full_register() != inst.op0_register().full_register() {
        result.push(post_inst);
    }

    Ok(rencode(bitness, result, rip)?)
}

pub fn is_om_compatible(inst: &Instruction) -> bool {
    let base_reg = inst.memory_base();
    let mut info_factory = InstructionInfoFactory::new();
    let info = info_factory.info(&inst);
    if !matches!(
        inst.mnemonic(),
        Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movd | Mnemonic::Movq | Mnemonic::Lea
    ) && info.used_registers().iter().any(|r| {
        // This needs more mnemonics
        r.register().full_register() == base_reg.full_register()
            && matches!(r.access(), OpAccess::Write | OpAccess::ReadWrite)
    }) {
        return false;
    }

    !(matches!(inst.mnemonic(), Mnemonic::Test | Mnemonic::Cmp)
        || inst.is_jcc_short_or_near()
        || !inst
            .op_kinds()
            .collect::<Vec<OpKind>>()
            .contains(&OpKind::Memory)
        || base_reg.is_segment_register()
        || base_reg.is_vector_register()
        || inst.is_stack_instruction()
        || base_reg == Register::None)

