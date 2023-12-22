use crate::x86_64::apply_ap_transform;
use crate::x86_64::helpers::*;
use crate::x86_64::DeoptimizerError;
use iced_x86::*;

/// Applies immidiate-to-register transform to given instruction.
pub fn apply_itr_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, DeoptimizerError> {
    if inst.is_stack_instruction() || inst.op_count() > 2 {
        return Err(DeoptimizerError::TransformNotPossible);
    }
    let idxs = match get_immediate_indexes(inst) {
        Some(i) => i,
        None => return Err(DeoptimizerError::TransformNotPossible),
    };

    let rip = inst.ip();
    let mut info_factory = InstructionInfoFactory::new();
    let info = info_factory.info(&inst);
    println!("imm_index: {}", *idxs.first().unwrap());
    let reg_size = get_op_size(*idxs.first().unwrap(), inst)?;
    println!("op1_kind: {:?}", inst.op1_kind());
    let rand_reg = get_random_gp_register(
        bitness == 64,
        reg_size as usize,
        Some(info.used_registers()),
    )?;
    let (reg_save_pre, reg_save_post) = get_register_save_seq(bitness, rand_reg)?;
    let op0_size = rand_reg.size() * 8;
    let op1_size = get_op_size(1, inst)? * 8;
    let mut mov_code = get_code_with_str(&format!("Mov_rm{op0_size}_imm{op1_size}"));
    if rand_reg.size() == 8 {
        mov_code = get_code_with_str(&format!("Mov_r64_imm{op1_size}"));
    }
    println!("reg_size: {reg_size}");
    println!("rand_reg: {:?}", rand_reg);
    let mut mov = Instruction::with2(mov_code, rand_reg, inst.immediate(*idxs.first().unwrap()))?;
    // Obfuscate mov...
    let obs_mov = apply_ap_transform(bitness, &mut mov)?;
    inst.set_op_kind(*idxs.first().unwrap(), OpKind::Register);
    inst.set_op_register(*idxs.first().unwrap(), rand_reg);
    let new_code = get_code_with_str(&format!("{:?}_rm{op0_size}_r{op0_size}", inst.mnemonic()));
    inst.set_code(new_code);
    let mut result = [[reg_save_pre].to_vec(), obs_mov].concat();
    result.push(*inst);
    result.push(reg_save_post);
    Ok(rencode(bitness, result, rip)?)
}
