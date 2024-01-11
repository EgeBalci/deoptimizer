use crate::x86_64::apply_ap_transform;
use crate::x86_64::helpers::*;
use crate::x86_64::DeoptimizerError;
use iced_x86::*;

/// Applies immidiate-to-register transform to given instruction.
pub fn apply_itr_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, DeoptimizerError> {
    if inst.is_stack_instruction() || !is_itr_compatible(inst) || is_using_fixed_register(inst) {
        return Err(DeoptimizerError::TransformNotPossible);
    }
    let idxs = match get_immediate_indexes(inst) {
        Some(i) => i,
        None => return Err(DeoptimizerError::TransformNotPossible),
    };
    transpose_fixed_register_operand(inst)?;
    let rip = inst.ip();
    let mut info_factory = InstructionInfoFactory::new();
    let info = info_factory.info(&inst);
    let imm_index = *idxs.first().unwrap();
    let imm = inst.immediate(imm_index);
    let imm_size = get_op_size(imm_index, inst)?;
    let rand_reg = get_random_gp_register(
        bitness == 64,
        imm_size as usize,
        Some(info.used_registers()),
    )?;
    let (reg_save_pre, reg_save_post) = get_register_save_seq(bitness, rand_reg)?;
    let mov_op_size = imm_size * 8;
    let mut mov_code = get_code_with_str(&format!("Mov_rm{mov_op_size}_imm{mov_op_size}"));
    let mut new_code = get_code_with_str(&format!("{:?}", inst.code()).replace("imm", "rm"));
    if new_code == Code::INVALID {
        new_code = get_code_with_str(&format!("{:?}", inst.code()).replace("imm", "r"));
    }
    inst.set_op_kind(*idxs.first().unwrap(), OpKind::Register);
    println!("code: {:?}", inst.code());
    let mut mov: Instruction;
    if imm > u64::pow(2, mov_op_size as u32) {
        mov_code = get_code_with_str(&format!("Mov_rm{}_imm{}", mov_op_size * 2, mov_op_size * 2));
        // This is for fixing sign extended instructions...
        if mov_op_size * 2 == 64 {
            // This means it is a sign extended immediate operand
            mov_code = get_code_with_str(&format!("Mov_r64_imm64"));
        }
        println!("op0: {mov_op_size} | op1: {mov_op_size}");
        println!("mov_code: {:?}", mov_code);
        if new_code == Code::INVALID {
            new_code = get_code_with_str(&format!("{:?}", inst.code()).replace(
                &format!("imm{mov_op_size}"),
                &format!("r{}", mov_op_size * 2),
            ));
        }
        if new_code == Code::INVALID {
            new_code = get_code_with_str(&format!("{:?}", inst.code()).replace(
                &format!("imm{mov_op_size}"),
                &format!("rm{}", mov_op_size * 2),
            ));
        }
        mov = Instruction::with2(mov_code, rand_reg.full_register(), imm)?;
        inst.set_op_register(*idxs.first().unwrap(), rand_reg.full_register());
    } else {
        println!("mov_code: {:?}", mov_code);
        mov = Instruction::with2(mov_code, rand_reg, imm)?;
        inst.set_op_register(*idxs.first().unwrap(), rand_reg);
    }

    println!("new_code: {:?}", new_code);
    // Obfuscate mov...
    let obs_mov = apply_ap_transform(bitness, &mut mov)?;

    inst.set_code(new_code);
    let mut result = [[reg_save_pre].to_vec(), obs_mov].concat();
    result.push(*inst);
    result.push(reg_save_post);
    Ok(rencode(bitness, result, rip)?)
}

pub fn is_itr_compatible(inst: &Instruction) -> bool {
    let mut my_inst = inst.clone();
    let idx = match get_immediate_indexes(inst) {
        Some(i) => i,
        None => return false,
    };

    let imm_size = match get_op_size(*idx.first().unwrap(), inst) {
        Ok(i) => i * 8,
        Err(_) => return false,
    };

    let _ = transpose_fixed_register_operand(&mut my_inst); // we can ignore the error
    get_code_with_str(&format!("{:?}", my_inst.code()).replace("imm", "rm")) != Code::INVALID
        || get_code_with_str(&format!("{:?}", my_inst.code()).replace("imm", "r")) != Code::INVALID
        || get_code_with_str(
            &format!("{:?}", my_inst.code())
                .replace(&format!("imm{imm_size}"), &format!("r{}", imm_size * 2)),
        ) != Code::INVALID
        || get_code_with_str(
            &format!("{:?}", my_inst.code())
                .replace(&format!("imm{imm_size}"), &format!("rm{}", imm_size * 2)),
        ) != Code::INVALID
}
