use crate::x86_64::apply_ap_transform;
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
    if !inst
        .op_kinds()
        .collect::<Vec<OpKind>>()
        .contains(&OpKind::Memory)
        || base_reg.is_segment_register()
        || base_reg.is_vector_register()
        || inst.is_stack_instruction()
    {
        return Err(DeoptimizerError::TransformNotPossible);
    }
    let rip = inst.ip();
    let mem_disp = inst.memory_displacement64();
    if base_reg == Register::None {
        let mut ifac = InstructionInfoFactory::new();
        let info = ifac.info(inst);
        let rand_reg = get_random_gp_register(
            bitness == 64,
            (bitness / 8) as usize,
            Some(info.used_registers()),
        )?;
        let (reg_save_pre, reg_save_suf) = get_register_save_seq(rand_reg)?;
        inst.set_memory_base(rand_reg);
        inst.set_memory_displacement64(0);
        inst.set_memory_displ_size(0);
        inst.set_memory_index(Register::None);
        inst.set_segment_prefix(Register::None);
        // This case is spesific to mov instruction
        let opc0 = inst.code().op_code().op0_kind();
        let opc1 = inst.code().op_code().op1_kind();
        let op0_size = get_op_size(0, inst)? * 8;
        let op1_size = get_op_size(1, inst)? * 8;
        if opc0 == OpCodeOperandKind::mem_offs {
            inst.set_code(get_code_with_str(&format!("Mov_rm{op0_size}_r{op1_size}")));
        }
        if opc1 == OpCodeOperandKind::mem_offs {
            inst.set_code(get_code_with_str(&format!("Mov_r{op0_size}_rm{op1_size}")));
        }

        let mut mov = match bitness {
            16 => Instruction::with2(Code::Mov_rm16_imm16, rand_reg, mem_disp)?,
            32 => Instruction::with2(Code::Mov_rm32_imm32, rand_reg, mem_disp)?,
            64 => Instruction::with2(Code::Mov_r64_imm64, rand_reg, mem_disp)?,
            _ => return Err(DeoptimizerError::UnexpectedRegisterSize),
        };
        let movs = apply_ap_transform(bitness, &mut mov)?;
        let mut result = [reg_save_pre].to_vec();
        result = [result, movs].concat();
        result.push(*inst);
        result.push(reg_save_suf);
        Ok(rencode(bitness, result, rip)?)
    } else {
        let rnd_reg_val = get_random_register_value(base_reg);
        let op_size = base_reg.size() * 8;
        let (c1, c2) = match (mem_disp as i32) < 0 {
            true => (
                get_code_with_str(&format!("Add_rm{}_imm{}", op_size, op_size)),
                get_code_with_str(&format!("Sub_rm{}_imm{}", op_size, op_size)),
            ),
            false => (
                get_code_with_str(&format!("Sub_rm{}_imm{}", op_size, op_size)),
                get_code_with_str(&format!("Add_rm{}_imm{}", op_size, op_size)),
            ),
        };
        let mut pre_inst = Instruction::with2(c1, base_reg, 0)?;
        set_op_immediate(&mut pre_inst, 1, rnd_reg_val)?;
        let mut post_inst = Instruction::with2(c2, base_reg, 0)?;
        set_op_immediate(&mut post_inst, 1, rnd_reg_val)?;
        let new_disply = mem_disp.abs_diff(rnd_reg_val); // This is not right!!!
        inst.set_memory_displ_size(base_reg.size() as u32);
        inst.set_memory_displacement64(new_disply as u64);

        Ok(rencode(
            bitness,
            [pre_inst, inst.clone(), post_inst].to_vec(),
            rip,
        )?)
    }
}
