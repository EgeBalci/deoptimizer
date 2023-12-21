use crate::x86_64::apply_ap_transform;
use crate::x86_64::helpers::*;
use crate::x86_64::DeoptimizerError;
use iced_x86::*;

/// Applies immidiate-to-register transform to given instruction.
pub fn apply_itr_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, DeoptimizerError> {
    if inst.is_stack_instruction() {
        return Err(DeoptimizerError::TransformNotPossible);
    }
    let idxs = match get_immediate_indexes(inst) {
        Some(i) => i,
        None => return Err(DeoptimizerError::TransformNotPossible),
    };

    let rip = inst.ip();
    let mut info_factory = InstructionInfoFactory::new();
    let info = info_factory.info(&inst);
    let reg_size = get_op_size(*idxs.first().unwrap(), inst)?;
    let rand_reg = get_random_gp_register(
        bitness == 64,
        reg_size as usize,
        Some(info.used_registers()),
    )?;
    let (reg_save_pre, reg_save_post) = get_register_save_seq(rand_reg)?;

    let mut mov = match rand_reg.size() {
        4 => Instruction::with2(
            Code::Mov_rm32_imm32,
            rand_reg,
            inst.immediate(*idxs.first().unwrap()),
        )?,
        8 => Instruction::with2(
            Code::Mov_r64_imm64,
            rand_reg,
            inst.immediate(*idxs.first().unwrap()),
        )?,
        _ => return Err(DeoptimizerError::UnexpectedRegisterSize),
    };
    // Obfuscate mov...
    println!("rand-reg: {:?}", rand_reg);
    let obs_mov = apply_ap_transform(bitness, &mut mov)?;
    inst.set_op_kind(*idxs.first().unwrap(), OpKind::Register);
    inst.set_op_register(*idxs.first().unwrap(), rand_reg);
    let new_code = format!("{:?}", inst.code())
        .replace("rm", "r")
        .replace("imm", "rm");
    println!("new code: {new_code}");
    inst.set_code(get_code_with_str(&new_code));
    let mut result = [[reg_save_pre].to_vec(), obs_mov].concat();
    result.push(*inst);
    result.push(reg_save_post);
    Ok(rencode(bitness, result, rip)?)
}
