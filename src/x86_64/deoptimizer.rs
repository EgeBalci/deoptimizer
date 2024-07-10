use crate::x86_64::*;
use bitflags::bitflags;
use iced_x86::code_asm::*;
use iced_x86::*;
use log::{debug, error, info, trace, warn};
use rand::Rng;
use std::collections::HashMap;
use thiserror::Error;
use tracer::*;

#[derive(Error, Debug)]
pub enum DeoptimizerError {
    // #[error("Instruction with unexpected operand count.")]
    // UnexpectedOperandCount,
    // #[error("Given instruction not found in code map.")]
    // InstructionNotFound,
    // #[error("Code analysis results are not found.")]
    // MissingCodeAnalysis,
    // #[error("Near branch value too large.")]
    // NearBranchTooBig,
    // #[error("Unexpected memory size given.")]
    // UnexpectedMemorySize,
    // #[error("Offset skipping failed!")]
    // OffsetSkipFail,
    #[error("Invalid processor mode(bitness). (16/32/64 accepted)")]
    InvalidProcessorMode,
    #[error("All available instruction transform gadgets failed.")]
    AllTransformsFailed,
    #[error("Far branch value too large.")]
    FarBranchTooBig,
    #[error("Found invalid instruction.")]
    InvalidInstruction,
    #[error("Branch target not found.")]
    BracnhTargetNotFound,
    #[error("This transform not possible for given instruction.")]
    TransformNotPossible,
    #[error("Unexpected register size given.")]
    UnexpectedRegisterSize,
    #[error("Unexpected operand type encountered.")]
    UnexpectedOperandType,
    #[error("No GP register found with given parameters.")]
    RegisterNotFound,
    #[error("Invalid instruction template.")]
    InvalidTemplate,
    #[error("Instruction transpose attempt failed.")]
    TransposeFailed,
    #[error("Invalid transform gadget.")]
    InvalidTransformGadget,
    #[error("Tracer Error: {0}")]
    TracerError(#[from] TracerError),
    #[error("Instruction encoding failed: {0}")]
    EncodingFail(#[from] IcedError),
}

#[allow(dead_code)]
pub enum FileType {
    Pe,
    Elf,
    Coff,
    Shellcode,
}

bitflags! {
    #[derive(Clone, Copy, Debug,PartialEq,Eq, Hash)]
    pub struct AvailableTransforms: u8 {
        const None = 0;
        const ArithmeticPartitioning = 1;
        const LogicalInverse = 1 << 1;
        const LogicalPartitioning = 1 << 2;
        const OffsetMutation = 1 << 3;
        const RegisterSwap = 1 << 4;
        const All = u8::MAX;
    }
}

impl AvailableTransforms {
    fn is_set(self, flag: Self) -> bool {
        self & flag == flag
    }
}

#[allow(dead_code)]
pub struct AnalyzedCode {
    bytes: Vec<u8>,
    bitness: u32,
    start_addr: u64,
    file_type: FileType,
    instructions: Vec<Instruction>,
    known_addr_table: Vec<u64>,
    branch_targets: Vec<u64>,
    trace_results: Option<TraceResults>,
}

impl AnalyzedCode {
    // pub fn get_bytes(&self) -> Vec<u8> {
    //     self.bytes
    // }
    // pub fn get_instructions(&self) -> Vec<Instruction> {
    //     self.instructions
    // }
    // pub fn get_bitness(&self) -> u32 {
    //     self.bitness
    // }
    // pub fn get_start_address(&self) -> u64 {
    //     self.start_addr
    // }
    pub fn is_known_address(&self, addr: u64) -> bool {
        self.known_addr_table.contains(&addr)
    }
    pub fn is_branch_target(&self, addr: u64) -> bool {
        self.branch_targets.contains(&addr)
    }

    // pub fn is_affecting_cf(&self, inst: &Instruction) -> Result<bool, DeoptimizerError> {
    //     // Check if the instruction exists in self.code
    //     if self.addr_map.get(&inst.ip()).is_none() {
    //         return Err(DeoptimizerError::InstructionNotFound);
    //     }
    //
    //     let mut rflags = RflagsBits::NONE;
    //     let m_rflags = inst.rflags_modified();
    //     if m_rflags == RflagsBits::NONE {
    //         return Ok(false);
    //     }
    //
    //     let mut cursor = inst.clone();
    //     while self.addr_map.get(&cursor.next_ip()).is_some() {
    //         cursor = *self.addr_map.get(&cursor.next_ip()).unwrap();
    //         rflags = rflags | cursor.rflags_modified();
    //         if (cursor.rflags_read() & m_rflags) > 0 {
    //             break;
    //         }
    //         if (m_rflags & rflags) == m_rflags {
    //             return Ok(false);
    //         }
    //     }
    //
    //     Ok(true)
    // }
}

pub struct Deoptimizer {
    /// Total number of deoptimization cycles.
    pub cycle: u32,
    /// Deoptimization frequency.
    pub freq: f32,
    /// Allowed transform routines.
    pub transforms: AvailableTransforms,
    /// Allow processing of invalid instructions.
    pub allow_invalid: bool,
    /// Trace the control flow of the given binary
    pub trace: bool,
    skipped_offsets: HashMap<u64, bool>,
}

impl Deoptimizer {
    pub fn new() -> Self {
        Self {
            cycle: 1,
            freq: 0.5,
            trace: false,
            allow_invalid: false,
            transforms: AvailableTransforms::All,
            skipped_offsets: HashMap::new(),
        }
    }

    pub fn set_transform_gadgets(&mut self, transforms: String) -> Result<(), DeoptimizerError> {
        let mut selected_transforms = AvailableTransforms::None;
        let trs = transforms.split(',');
        for t in trs {
            match t.to_uppercase().as_str() {
                "AP" => selected_transforms |= AvailableTransforms::ArithmeticPartitioning,
                "LI" => selected_transforms |= AvailableTransforms::LogicalInverse,
                "LP" => selected_transforms |= AvailableTransforms::LogicalPartitioning,
                "OM" => selected_transforms |= AvailableTransforms::OffsetMutation,
                "RS" => selected_transforms |= AvailableTransforms::RegisterSwap,
                _ => return Err(DeoptimizerError::InvalidTransformGadget),
            }
        }
        self.transforms = selected_transforms;
        Ok(())
    }

    pub fn set_skipped_offsets(&mut self, skipped: Vec<(u64, u64)>) {
        for range in skipped {
            let (o1, o2) = range;
            for o in o1..o2 {
                self.skipped_offsets.insert(o, true);
            }
        }
    }

    fn replace_skipped_offsets(
        &mut self,
        bytes: &[u8],
        fill: u8,
    ) -> Result<Vec<u8>, DeoptimizerError> {
        if self.skipped_offsets.is_empty() {
            return Ok(bytes.to_vec());
        }
        let mut replaced_bytes = Vec::new();
        trace!("Replacing skipped offsets with NOPs...");
        for (i, b) in bytes.iter().enumerate() {
            if self.skipped_offsets.contains_key(&(i as u64)) {
                replaced_bytes.push(fill);
                continue;
            }
            replaced_bytes.push(*b);
        }
        Ok(replaced_bytes)
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

        // Determine the file type here...
        if bytes.len() > 1000 && self.trace {
            warn!("Given shellcode seems to be too large for effective tracing.")
        }

        let mut trace_results = None;
        if self.trace {
            info!("Tracing the execution control flow...");
            let tr = tracer::trace(bytes, bitness, start_addr)?;
            info!("Done tracing!");
            info!("Found {} possible strings.", tr.possible_strings.len());
            debug!("Total coverage: {}", tr.total_coverage);
            debug!("Coverage without strings: {}", tr.coverage_whitout_strings);
            for o in 0..bytes.len() {
                if !tr.active_offsets.contains(&(o as u64 + start_addr)) {
                    self.skipped_offsets.insert(o as u64 + start_addr, true);
                }
            }
            trace_results = Some(tr);
        }

        let mut decoder = Decoder::with_ip(bitness, bytes, start_addr, DecoderOptions::NONE);
        let replaced_bytes: Vec<u8>;
        if !self.skipped_offsets.is_empty() {
            replaced_bytes = self.replace_skipped_offsets(bytes, 0x90)?;
            decoder = Decoder::with_ip(bitness, &replaced_bytes, start_addr, DecoderOptions::NONE);
        }

        let mut inst = Instruction::default();
        let mut known_addr_table = Vec::new();
        let mut branch_targets = Vec::new();
        let mut instructions = Vec::new();
        let mut addr_map: HashMap<u64, Instruction> = HashMap::new();
        let mut offset = 0;
        while decoder.can_decode() {
            decoder.decode_out(&mut inst);
            if self.skipped_offsets.contains_key(&offset) {
                let mut db = Instruction::with_declare_byte_1(bytes[offset as usize]);
                db.set_ip(inst.ip());
                db.set_code(Code::DeclareByte);
                // Push to known address table
                known_addr_table.push(db.ip());
                addr_map.insert(db.ip(), db);
                instructions.push(db);
                offset += 1;
                continue;
            }

            if inst.is_invalid() {
                warn!("Found invalid instruction at: 0x{:016X}", inst.ip());
                if !self.allow_invalid {
                    return Err(DeoptimizerError::InvalidInstruction);
                }
            }
            // Push to known address table
            known_addr_table.push(inst.ip());
            addr_map.insert(inst.ip(), inst);
            instructions.push(inst);

            let bt = get_branch_target(&inst).unwrap_or(0);
            if bt != 0 {
                branch_targets.push(bt);
            }
            offset += inst.len() as u64;
        }

        for bt in branch_targets.iter() {
            if !known_addr_table.contains(bt) {
                warn!(
                    "Branch target 0x{:016X} is outside the known address sapce!",
                    bt
                );
            }
        }

        Ok(AnalyzedCode {
            bitness,
            bytes: bytes.to_vec(),
            start_addr,
            file_type: FileType::Shellcode,
            instructions,
            known_addr_table,
            branch_targets,
            trace_results,
        })
    }

    pub fn apply_transform(
        bitness: u32,
        inst: &Instruction,
        freq: f32,
        transforms: AvailableTransforms,
    ) -> Result<Vec<Instruction>, DeoptimizerError> {
        if inst.is_invalid() {
            // We can skip invalid instructions (including hardcoded data
            return Err(DeoptimizerError::InvalidInstruction);
        }
        // We can bailout if there is no operand
        if inst.op_count() == 0 || inst.code() == Code::DeclareByte {
            return Err(DeoptimizerError::AllTransformsFailed);
        }

        // First we must handle special cases...
        match apply_ce_transform(bitness, &mut inst.clone()) {
            Ok(t) => return Ok(t),
            Err(e) => {
                if is_ce_compatible(inst) {
                    error!("CE transform failed for: {}", inst);
                    error!("{}", e);
                }
            }
        }

        if rand::thread_rng().gen_range(0.0..1.0) < freq {
            // Priority is important, start with immidate obfuscation
            if transforms.is_set(AvailableTransforms::ArithmeticPartitioning) {
                match apply_ap_transform(bitness, &mut inst.clone()) {
                    Ok(t) => return Ok(t),
                    Err(e) => trace!("[AP] TransformError: {}", e),
                }
            }
            if transforms.is_set(AvailableTransforms::LogicalInverse) {
                match apply_li_transform(bitness, &mut inst.clone()) {
                    Ok(t) => return Ok(t),
                    Err(e) => trace!("[LI] TransformError: {}", e),
                }
            }

            if transforms.is_set(AvailableTransforms::LogicalPartitioning) {
                match apply_lp_transform(bitness, &mut inst.clone()) {
                    Ok(t) => return Ok(t),
                    Err(e) => trace!("[LP] TransformError: {}", e),
                }
            }

            if transforms.is_set(AvailableTransforms::OffsetMutation) {
                // second target, memory obfuscation
                match apply_om_transform(bitness, &mut inst.clone()) {
                    Ok(t) => return Ok(t),
                    Err(e) => trace!("[OM] TransformError: {}", e),
                }
            }

            if transforms.is_set(AvailableTransforms::RegisterSwap) {
                // Now swap registers
                match apply_rs_transform(bitness, &mut inst.clone()) {
                    Ok(t) => return Ok(t),
                    Err(e) => trace!("[RS] TransformError: {}", e),
                }
            }
        }

        Err(DeoptimizerError::AllTransformsFailed)
    }

    pub fn deoptimize(&mut self, acode: &AnalyzedCode) -> Result<Vec<u8>, DeoptimizerError> {
        let mut result: Vec<Instruction> = Vec::new(); // deoptimized code
        let mut ip_to_index_table: HashMap<u64, usize> = HashMap::new();
        let mut index_to_index_table: HashMap<usize, usize> = HashMap::new();
        // let mut new_ip: u64 = acode.start_addr;
        for inst in acode.instructions.clone() {
            if acode.is_branch_target(inst.ip()) {
                ip_to_index_table.insert(inst.ip(), result.len());
            }
            match Deoptimizer::apply_transform(acode.bitness, &inst, self.freq, self.transforms) {
                Ok(dinst) => {
                    result = [result, dinst.clone()].concat();
                    print_inst_diff(&inst, dinst);
                    continue;
                }
                Err(e) => {
                    trace!("TransformError: {e} => [{}]", inst);
                }
            }
            result.push(inst);
            print_inst_diff(&inst, [inst].to_vec());
        }
        adjust_instruction_addrs(&mut result, acode.start_addr);

        for (i, inst) in result.iter().enumerate() {
            let bt = get_branch_target(inst).unwrap_or(0);
            if bt != 0 {
                if let Some(idx) = ip_to_index_table.get(&bt) {
                    index_to_index_table.insert(i, *idx);
                    trace!("{:016X} {} >> {}", inst.ip(), inst, result[*idx]);
                } else {
                    error!("Could not find branch fix entry for: {}", inst);
                }
            }
        }

        let mut fin_address = result.last().unwrap().ip();
        loop {
            trace!("[============ ADJUSTING BRANCH TARGETS ===========]");
            for i in 0..result.len() {
                if index_to_index_table.contains_key(&i) {
                    if let Some(idx) = index_to_index_table.get(&i) {
                        trace!(
                            "BT: 0x{:X} {} -> 0x{:X} {}",
                            result[i].ip(),
                            result[i],
                            result[*idx].ip(),
                            result[*idx]
                        );
                        result[i] = set_branch_target(
                            &result[i].clone(),
                            result[*idx].ip(),
                            acode.bitness,
                        )?;
                        adjust_instruction_addrs(&mut result, acode.start_addr);
                    } else {
                        error!("Could not find branch fix entry for: {}", result[i]);
                    }
                }
            }
            if result.last().unwrap().ip() == fin_address {
                break;
            } else {
                fin_address = result.last().unwrap().ip();
            }
        }
        adjust_instruction_addrs(&mut result, acode.start_addr);
        let mut encoder = Encoder::new(acode.bitness);
        let mut buffer = Vec::new();
        for inst in result.clone() {
            if inst.code() == Code::DeclareByte {
                buffer.push(inst.get_declare_byte_value(0));
                continue;
            }
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
