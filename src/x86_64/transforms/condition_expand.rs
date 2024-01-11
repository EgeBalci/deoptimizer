use crate::x86_64::*;
use iced_x86::code_asm::*;
use iced_x86::*;

/// Applies condition extention transform.
pub fn apply_ce_transform(
    bitness: u32,
    inst: &mut Instruction,
) -> Result<Vec<Instruction>, DeoptimizerError> {
    if !is_ce_compatible(inst) {
        return Err(DeoptimizerError::TransformNotPossible);
    }
    let mut asm = CodeAssembler::new(bitness)?;
    let mut test = match bitness {
        16 => Instruction::with2(Code::Test_rm16_r16, Register::CX, Register::CX)?,
        32 => Instruction::with2(Code::Test_rm32_r32, Register::ECX, Register::ECX)?,
        64 => Instruction::with2(Code::Test_rm64_r64, Register::RCX, Register::RCX)?,
        _ => return Err(DeoptimizerError::InvalidProcessorMode),
    };
    // test.set_ip(inst.ip());
    test = *rencode(bitness, [test].to_vec(), inst.ip())?
        .first()
        .unwrap();
    let bt = inst.near_branch_target();

    if inst.is_loopcc() || inst.is_loop() {
        match inst.mnemonic() {
            Mnemonic::Loop | Mnemonic::Loope => {
                asm.jz(bt)?;
                let insts = asm.instructions();
                let mut jz = insts.first().unwrap().clone();
                jz.set_ip(test.next_ip());
                jz.as_near_branch();
                return Ok(rencode(bitness, [test, jz].to_vec(), inst.ip())?);
            }
            Mnemonic::Loopne => {
                asm.jnz(bt)?;
                let insts = asm.instructions();
                let mut jnz = insts.first().unwrap().clone();
                jnz.set_ip(test.next_ip());
                jnz.as_near_branch();
                return Ok(rencode(bitness, [test, jnz].to_vec(), inst.ip())?);
            }
            _ => return Err(DeoptimizerError::TransformNotPossible),
        }
    }

    if matches!(
        inst.mnemonic(),
        Mnemonic::Jrcxz | Mnemonic::Jecxz | Mnemonic::Jcxz
    ) {
        asm.jz(bt)?;
        let insts = asm.instructions();
        let mut jz = insts.first().unwrap().clone();
        jz.set_ip(test.next_ip());
        jz.as_near_branch();
        return Ok(rencode(bitness, [test, jz].to_vec(), inst.ip())?);
    }

    Err(DeoptimizerError::TransformNotPossible)
}

pub fn is_ce_compatible(inst: &Instruction) -> bool {
    matches!(
        inst.mnemonic(),
        Mnemonic::Jcxz | Mnemonic::Jecxz | Mnemonic::Jrcxz | Mnemonic::Loop
    ) || inst.is_loopcc()
}
