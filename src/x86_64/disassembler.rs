use crate::x86_64::*;
use iced_x86::*;
use log::{error, info, warn};

pub fn format_instruction(syntax: String, inst: &Instruction) -> String {
    let mut result = String::new();
    match syntax.to_uppercase().as_str() {
        "KEYSTONE" => {
            let mut formatter = IntelFormatter::new();
            formatter.options_mut().set_uppercase_keywords(false);
            formatter
                .options_mut()
                .set_memory_size_options(iced_x86::MemorySizeOptions::Always);
            formatter.options_mut().set_hex_prefix("0x");
            formatter.options_mut().set_hex_suffix("");
            formatter.format(inst, &mut result);
        }
        "NASM" => {
            let mut formatter = NasmFormatter::new();
            formatter.format(inst, &mut result);
        }
        "MASM" => {
            let mut formatter = MasmFormatter::new();
            formatter.format(inst, &mut result);
        }
        "INTEL" => {
            let mut formatter = IntelFormatter::new();
            formatter.format(inst, &mut result);
        }
        "GAS" => {
            let mut formatter = GasFormatter::new();
            formatter.format(inst, &mut result);
        }
        _ => {
            error!("Unknown disassembler syntax: {}", syntax);
            panic!("Instruction formatting failed!")
        }
    };
    result
}

pub fn disassemble(
    bytes: &[u8],
    bitness: u32,
    start_addr: u64,
    syntax: String,
) -> Result<String, DeoptimizerError> {
    info!(
        "Disassembling at -> 0x{:016X} (mode={})",
        start_addr, bitness
    );

    let mut result = String::new();
    let mut decoder = Decoder::with_ip(bitness, bytes, start_addr, DecoderOptions::NONE);
    let mut inst = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut inst);
        if inst.is_invalid() {
            warn!(
                "Inlining invalid instruction bytes at: 0x{:016X}",
                inst.ip()
            );
            let start_index = (inst.ip() - start_addr) as usize;
            let instr_bytes = &bytes[start_index..start_index + inst.len()];
            result += &format!("loc_{:016X}: {}\n", inst.ip(), to_db_mnemonic(instr_bytes));
            continue;
        }
        let temp = format_instruction(syntax.clone(), &inst);
        let nbt = inst.near_branch_target();
        if nbt != 0 {
            result += &format!(
                "loc_{:016X}: {} {}\n",
                inst.ip(),
                temp.split(' ').next().unwrap(),
                &format!("loc_{:016X}", nbt)
            );
            continue;
        }
        result += &format!("loc_{:016X}: {}\n", inst.ip(), temp);
    }
    Ok(result)
}
