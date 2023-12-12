use crate::x86_64::*;
use iced_x86::code_asm::*;
use iced_x86::*;
use log::{debug, error, info, warn};
use rand::{seq::SliceRandom, Rng};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DeoptimizerError {
    #[error("Invalid formatter syntax.")]
    InvalidSyntax,
    #[error("Invalid processor mode(bitness). (16/32/64 accepted)")]
    InvalidProcessorMode,
    #[error("Instruction with unexpected operand count.")]
    UnexpectedOperandCount,
    #[error("All available instruction transform gadgets failed.")]
    AllTransformsFailed,
    #[error("Given instruction not found in code map.")]
    InstructionNotFound,
    #[error("Code analysis results are not found.")]
    MissingCodeAnalysis,
    #[error("Near branch value too large.")]
    NearBranchTooBig,
    #[error("Far branch value too large.")]
    FarBranchTooBig,
    #[error("Found invalid instruction.")]
    InvalidInstruction,
    #[error("Branch target not found.")]
    BracnhTargetNotFound,
    #[error("Instruction encoding failed: {0}")]
    EncodingFail(#[from] IcedError),
}

enum AssemblySyntax {
    Keystone,
    Nasm,
    Masm,
    Intel,
    Gas,
}

pub struct AnalyzedCode {
    bitness: u32,
    bytes: Vec<u8>,
    start_addr: u64,
    code: Vec<Instruction>,
    addr_map: HashMap<u64, Instruction>,
    known_addr_table: Vec<u64>,
    branch_targets: Vec<u64>,
    cfe_addr_table: Vec<u64>,
}

impl AnalyzedCode {
    fn is_known_address(&self, addr: u64) -> bool {
        self.known_addr_table.contains(&addr)
    }
    fn is_branch_target(&self, addr: u64) -> bool {
        self.branch_targets.contains(&addr)
    }
    fn get_random_cfe_addr(&self) -> Option<u64> {
        self.cfe_addr_table.choose(&mut rand::thread_rng()).copied()
    }
    pub fn is_affecting_cf(&self, inst: &Instruction) -> Result<bool, DeoptimizerError> {
        // Check if the instruction exists in self.code
        if self.addr_map.get(&inst.ip()).is_none() {
            return Err(DeoptimizerError::InstructionNotFound);
        }

        let mut rflags = RflagsBits::NONE;
        let m_rflags = inst.rflags_modified();
        if m_rflags == RflagsBits::NONE {
            return Ok(false);
        }

        let mut cursor = inst.clone();
        while self.addr_map.get(&cursor.next_ip()).is_some() {
            cursor = *self.addr_map.get(&cursor.next_ip()).unwrap();
            rflags = rflags | cursor.rflags_modified();
            if (cursor.rflags_read() & m_rflags) > 0 {
                break;
            }
            if (m_rflags & rflags) == m_rflags {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

pub struct Deoptimizer {
    /// Total number of deoptimization cycles.
    pub cycle: u32,
    /// Deoptimization frequency.
    pub freq: f32,
    /// Allow processing of invalid instructions.
    pub allow_invalid: bool,
    /// Disassembler syntax.
    syntax: AssemblySyntax,
}

impl Deoptimizer {
    pub fn new() -> Self {
        Self {
            cycle: 1,
            freq: 0.5,
            allow_invalid: false,
            syntax: AssemblySyntax::Nasm,
        }
    }

    pub fn set_syntax(&mut self, syntax: String) -> Result<(), DeoptimizerError> {
        match syntax.to_lowercase().as_str() {
            "keystone" => self.syntax = AssemblySyntax::Keystone,
            "nasm" => self.syntax = AssemblySyntax::Nasm,
            "masm" => self.syntax = AssemblySyntax::Masm,
            "intel" => self.syntax = AssemblySyntax::Intel,
            "gas" => self.syntax = AssemblySyntax::Gas,
            _ => return Err(DeoptimizerError::InvalidSyntax),
        }
        Ok(())
    }

    pub fn analyze(
        &mut self,
        bytes: &[u8],
        bitness: u32,
        start_addr: u64,
    ) -> Result<AnalyzedCode, DeoptimizerError> {
        info!(
            "Analyzing {} bytes with {} bit mode...",
            bytes.len(),
            bitness
        );
        let mut decoder = Decoder::with_ip(bitness, bytes, start_addr, DecoderOptions::NONE);
        let mut inst = Instruction::default();
        let mut known_addr_table = Vec::new();
        let mut branch_targets = Vec::new();
        let mut cfe_addr_table = Vec::new();
        let mut code = Vec::new();
        let mut addr_map: HashMap<u64, Instruction> = HashMap::new();
        while decoder.can_decode() {
            decoder.decode_out(&mut inst);
            if inst.is_invalid() {
                warn!("Found invalid instruction at: 0x{:016X}", inst.ip());
                if !self.allow_invalid {
                    return Err(DeoptimizerError::InvalidSyntax);
                }
            }
            code.push(inst);
            addr_map.insert(inst.ip(), inst);

            let bt = get_branch_target(&inst).unwrap_or(0);
            if bt != 0 {
                branch_targets.push(bt);
            }

            // Push to known address table
            known_addr_table.push(inst.ip());

            // Push to control flow exit address table if it is a JMP of RET
            if inst.mnemonic() == Mnemonic::Ret
                || inst.mnemonic() == Mnemonic::Retf
                || inst.mnemonic() == Mnemonic::Jmp
            {
                cfe_addr_table.push(inst.ip())
            }
        }

        Ok(AnalyzedCode {
            bitness,
            bytes: bytes.to_vec(),
            start_addr,
            code,
            addr_map,
            known_addr_table,
            branch_targets,
            cfe_addr_table,
        })
    }

    pub fn format_instruction(&self, inst: &Instruction) -> String {
        let mut result = String::new();
        match self.syntax {
            AssemblySyntax::Keystone => {
                let mut formatter = IntelFormatter::new();
                formatter.options_mut().set_uppercase_keywords(false);
                formatter
                    .options_mut()
                    .set_memory_size_options(iced_x86::MemorySizeOptions::Always);
                formatter.options_mut().set_hex_prefix("0x");
                formatter.options_mut().set_hex_suffix("");
                formatter.format(inst, &mut result);
            }
            AssemblySyntax::Nasm => {
                let mut formatter = NasmFormatter::new();
                formatter.format(inst, &mut result);
            }
            AssemblySyntax::Masm => {
                let mut formatter = MasmFormatter::new();
                formatter.format(inst, &mut result);
            }
            AssemblySyntax::Intel => {
                let mut formatter = IntelFormatter::new();
                formatter.format(inst, &mut result);
            }
            AssemblySyntax::Gas => {
                let mut formatter = GasFormatter::new();
                formatter.format(inst, &mut result);
            }
        };
        result
    }

    pub fn disassemble(&mut self, acode: &AnalyzedCode) -> Result<String, DeoptimizerError> {
        info!(
            "Disassembling at -> 0x{:X} (mode={})",
            acode.start_addr, acode.bitness
        );
        let mut result = String::new();
        for inst in acode.code.clone() {
            if inst.is_invalid() {
                warn!(
                    "Inlining invalid instruction bytes at: 0x{:016X}",
                    inst.ip()
                );
                let start_index = (inst.ip() - acode.start_addr) as usize;
                let instr_bytes = &acode.bytes[start_index..start_index + inst.len()];
                result += &format!("loc_{:016X}: {}\n", inst.ip(), to_db_mnemonic(instr_bytes));
                continue;
            }
            let temp = self.format_instruction(&inst);
            let nbt = inst.near_branch_target();
            if nbt != 0 {
                if acode.is_known_address(nbt) {
                    result += &format!(
                        "loc_{:016X}: {} {}\n",
                        inst.ip(),
                        temp.split(' ').next().unwrap(),
                        &format!("loc_{:016X}", nbt)
                    );
                    continue;
                } else {
                    warn!("Misaligned instruction detected at {}", inst.ip())
                }
            }
            result += &format!("loc_{:016X}: {}\n", inst.ip(), temp);
        }
        Ok(result)
    }

    pub fn apply_transform(
        bitness: u32,
        inst: &Instruction,
        freq: f32,
    ) -> Result<Vec<Instruction>, DeoptimizerError> {
        if inst.op_count() > 0 {
            // First handle special cases...
            if let Ok(t) = apply_ce_transform(bitness, &mut inst.clone()) {
                return Ok(t);
            }
            if rand::thread_rng().gen_range(0.0..1.0) < freq {
                // Priority is important, start with immidate obfuscation
                if let Ok(t) = apply_ap_transform(bitness, &mut inst.clone()) {
                    return Ok(t);
                }
                if let Ok(t) = apply_li_transform(bitness, &mut inst.clone()) {
                    return Ok(t);
                }
                if let Ok(t) = apply_itr_transform(bitness, &mut inst.clone()) {
                    // Clobbers CFLAGS
                    return Ok(t);
                }
                // second target, memory obfuscation
                if let Ok(t) = apply_om_transform(bitness, &mut inst.clone()) {
                    return Ok(t);
                }
                // Now swap registers
                if let Ok(t) = apply_rs_transform(bitness, &mut inst.clone()) {
                    return Ok(t);
                }
            }
        }
        Err(DeoptimizerError::AllTransformsFailed)
    }

    pub fn deoptimize(&self, acode: &AnalyzedCode) -> Result<Vec<u8>, DeoptimizerError> {
        let mut step1 = Vec::new(); // deoptimized code
        let mut bt_fix_table: HashMap<u64, usize> = HashMap::new();
        let mut final_fix_table: HashMap<usize, usize> = HashMap::new();
        let mut new_ip: u64 = acode.start_addr;
        for mut inst in acode.code.clone() {
            if acode.is_branch_target(inst.ip()) {
                // warn!("BT 0x{:X} -> 0x{:X}", inst.ip(), new_ip);
                bt_fix_table.insert(inst.ip(), step1.len());
            }
            inst.set_ip(new_ip);
            match Deoptimizer::apply_transform(acode.bitness, &inst, self.freq) {
                Ok(dinst) => {
                    new_ip = dinst.last().unwrap().next_ip();
                    step1 = [step1, dinst.clone()].concat();
                    continue;
                }
                Err(e) => debug!("TransformError: {e} => [{}]", inst),
            }
            new_ip = inst.next_ip();
            step1.push(inst);
        }

        for (i, inst) in step1.iter().enumerate() {
            let bt = get_branch_target(inst).unwrap_or(0);
            if bt != 0 {
                if let Some(idx) = bt_fix_table.get(&bt) {
                    final_fix_table.insert(i, *idx);
                    debug!("{:016X} {} >> {}", inst.ip(), inst, step1[*idx]);
                } else {
                    error!("Could not find branch fix entry for: {}", inst);
                }
                continue;
            }
        }

        let mut fin_address = step1.last().unwrap().ip();
        loop {
            warn!("============ adjusting branch targets ===========");
            for i in 0..step1.len() {
                if final_fix_table.contains_key(&i) {
                    if let Some(idx) = final_fix_table.get(&i) {
                        debug!(
                            "Adjusting BT: 0x{:X} -> 0x{:X} {}",
                            step1[i].ip(),
                            step1[*idx].ip(),
                            step1[*idx]
                        );
                        step1[i] = set_branch_target(
                            &mut step1[i].clone(),
                            step1[*idx].ip(),
                            acode.bitness,
                        )?;
                        adjust_instruction_addr(&mut step1, acode.start_addr);
                    } else {
                        error!("Could not find branch fix entry for: {}", step1[i]);
                    }
                }
            }
            if step1.last().unwrap().ip() == fin_address {
                break;
            } else {
                fin_address = step1.last().unwrap().ip();
            }
        }

        let mut encoder = Encoder::new(acode.bitness);
        let mut buffer = Vec::new();
        for inst in step1.clone() {
            match encoder.encode(&inst, inst.ip()) {
                Ok(_) => buffer = [buffer, encoder.take_buffer()].concat(),
                Err(e) => {
                    error!(
                        "Encoding failed for -> {} [OPK0: {:?}]",
                        inst,
                        inst.op0_kind()
                    );
                    return Err(DeoptimizerError::EncodingFail(e));
                }
            }
        }
        Ok(buffer)
    }
}
