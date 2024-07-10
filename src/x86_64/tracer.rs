use crate::x86_64::*;
use iced_x86::code_asm::*;
use iced_x86::*;
use log::{error, trace};
use regex::bytes::Regex;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TracerError {
    #[error("Unexpected operand type encountered.")]
    UnexpectedOperandType,
    #[error("Instruction encoding failed: {0}")]
    EncodingFail(#[from] IcedError),
}

#[derive(PartialEq, Debug)]
enum HaltResason {
    Return,
    EndOfBlock,
    LoopCondition,
    DynamicBranch,
    AddressOutOfBounds,
    InvalidInstruction,
}

struct Tracer {
    bytes: Vec<u8>,
    bitness: u32,
    stack: Vec<u64>,
    context: HashMap<Register, u64>,
    cf_addr_map: Vec<u64>,
    active_offsets: Vec<u64>,
    possible_strings: Vec<String>,
    possible_string_offsets: Vec<u64>,
}

pub struct TraceResults {
    pub bytes: Vec<u8>,
    pub cf_addr_map: Vec<u64>,
    pub active_offsets: Vec<u64>,
    pub possible_strings: Vec<String>,
    pub possible_string_offsets: Vec<u64>,
    pub total_coverage: f64,
    pub coverage_whitout_strings: f64,
}

// impl TraceResults {
//     pub fn print_dead_code(&self) {
//         let mut last = 0;
//         for (i, b) in self.bytes.iter().enumerate() {
//             if self.active_offsets.contains(&(i as u64)) {
//                 continue;
//             }
//             if i - last != 1 {
//                 print!("\n0x{:016X}:\t", i);
//             }
//
//             if *b >= 0x20 && *b <= 0x7E {
//                 print!("{}", String::from_utf8_lossy(&[*b]));
//             } else if *b == 0x00 {
//                 continue;
//             } else {
//                 print!("\\x{:X}", b);
//             }
//             last = i
//         }
//         println!("\n");
//     }
// }

impl Tracer {
    fn new(bytes: &[u8], bitness: u32) -> Self {
        let re = match bitness {
            64 => Regex::new(r"(?<str>[\x20-\x7E]{8,}\x00)").unwrap(),
            _ => Regex::new(r"(?<str>[\x20-\x7E]{4,}\x00)").unwrap(),
        };
        let mut ps = Vec::new();
        let mut pso = Vec::new();
        for mat in re.find_iter(bytes) {
            // println!("Found match at position: {}", mat.start());
            // println!("-> {:?}", String::from_utf8_lossy(mat.as_bytes()));
            ps.push(String::from_utf8_lossy(mat.as_bytes()).to_string());
            for o in mat.start()..mat.start() + mat.len() {
                pso.push(o as u64);
            }
        }
        // info!("Found {} possible strings.", ps.len());
        Self {
            bytes: bytes.to_vec(),
            bitness,
            stack: Vec::new(),
            context: HashMap::new(),
            cf_addr_map: Vec::new(),
            active_offsets: Vec::new(),
            possible_strings: ps,
            possible_string_offsets: pso,
        }
    }

    fn set_active_offsets(&mut self, start: u64, end: u64) {
        for o in start..end {
            self.active_offsets.push(o);
        }
    }

    fn trace_code_paths(&mut self, start_offset: u64) -> Result<HaltResason, TracerError> {
        trace!("[TRACER] Tracing -> 0x{:016X}", start_offset);
        let mut ip = start_offset;
        loop {
            if ip >= self.bytes.len() as u64 {
                trace!("[TRACER] HaltResason[0x{:016X}]: Out Of Bounds Address", ip);
                return Ok(HaltResason::AddressOutOfBounds);
            }

            let mut decoder = Decoder::with_ip(
                self.bitness,
                &self.bytes[ip as usize..],
                ip,
                DecoderOptions::NONE,
            );
            let mut inst = Instruction::default();
            decoder.decode_out(&mut inst);

            // First check if it is an invalid instruction or declared value...
            if inst.is_invalid()
                || matches!(
                    inst.code(),
                    Code::DeclareByte | Code::DeclareWord | Code::DeclareDword | Code::DeclareQword
                )
            {
                trace!("[TRACER] HaltResason[0x{:016X}]: Invalid Instruction", ip);
                return Ok(HaltResason::InvalidInstruction);
            }

            // Check if this address is already exists in the flow map
            if self.cf_addr_map.contains(&ip) {
                trace!("[TRACER] HaltResason[0x{:016X}]: Loop Contition", ip);
                return Ok(HaltResason::LoopCondition);
            }

            // Adjust stack and context for each stack instruction
            if inst.is_stack_instruction() {
                self.handle_stack_operation(inst)?;
            }

            // Add instruction address to control flow map and register active offsets
            trace!("[TRACER] 0x{:016X}:\t{}", ip, inst);
            self.cf_addr_map.push(ip);
            self.set_active_offsets(ip, ip + inst.len() as u64);

            if is_return_instruction(inst) {
                trace!("[TRACER] HaltResason[0x{:016X}]: Return", ip);
                return Ok(HaltResason::Return);
            }

            if is_conditional_branch(inst) {
                match get_branch_target(&inst) {
                    Ok(ip) => self.trace_code_paths(ip)?,
                    Err(_) => {
                        if inst.op0_kind() == OpKind::Register {
                            if let Some(val) = self.context.get(&inst.op0_register()) {
                                self.trace_code_paths(*val)?
                            } else {
                                trace!(
                                    "[TRACER] HaltResason[0x{:016X}]: Dynamic Branch Target",
                                    ip
                                );
                                return Ok(HaltResason::DynamicBranch);
                            }
                        } else {
                            return Err(TracerError::UnexpectedOperandType);
                        }
                    }
                };
            }

            if inst.mnemonic() == Mnemonic::Call {
                match get_branch_target(&inst) {
                    Ok(bt) => {
                        self.stack.push(inst.next_ip());
                        let hr = self.trace_code_paths(bt)?;
                        if hr != HaltResason::Return
                            && self.possible_string_offsets.contains(&inst.next_ip())
                        {
                            return Ok(hr);
                        }
                    }
                    Err(_) => {
                        if inst.op0_kind() == OpKind::Register {
                            if let Some(val) = self.context.get(&inst.op0_register()) {
                                self.stack.push(*val);
                                let hr = self.trace_code_paths(*val)?;
                                if hr != HaltResason::Return
                                    && self.possible_string_offsets.contains(&inst.next_ip())
                                {
                                    return Ok(hr);
                                }
                            }
                        } else {
                            return Err(TracerError::UnexpectedOperandType);
                        }
                    }
                };
            }
            ip = inst.next_ip();
            if ip == self.bytes.len() as u64 {
                break;
            }
        }
        trace!("[TRACER] HaltResason[0x{:016X}]: End Of Block", ip);
        Ok(HaltResason::EndOfBlock)
    }

    fn handle_stack_operation(&mut self, inst: Instruction) -> Result<(), TracerError> {
        match inst.mnemonic() {
            Mnemonic::Pop => {
                if !self.stack.is_empty() {
                    if let Some(val) = self.stack.pop() {
                        trace!("Poped 0x{:016X} into {:?}", val, inst.op0_register());
                        self.context.insert(inst.op0_register(), val);
                    }
                }
            }
            Mnemonic::Push => {
                if is_immediate_operand(inst.op0_kind()) {
                    trace!("Pushed 0x{:016X} to stack", inst.immediate(0));
                    self.stack.push(inst.immediate(0));
                } else {
                    self.stack.push(u64::MAX);
                }
            }
            _ => (),
        };
        Ok(())
    }
}

fn is_return_instruction(inst: Instruction) -> bool {
    matches!(
        inst.mnemonic(),
        Mnemonic::Ret
            | Mnemonic::Retf
            | Mnemonic::Leave
            | Mnemonic::Iret
            | Mnemonic::Iretd
            | Mnemonic::Iretq
    )
}

fn is_conditional_branch(inst: Instruction) -> bool {
    inst.is_jcc_short_or_near()
        || inst.is_jmp_near_indirect()
        || inst.is_jmp_far_indirect()
        || inst.is_jmp_far()
        || inst.is_loop()
        || inst.is_loopcc()
}

pub fn trace(bytes: &[u8], bitness: u32, start_addr: u64) -> Result<TraceResults, TracerError> {
    let mut tracer = Tracer::new(bytes, bitness);
    tracer.trace_code_paths(start_addr)?;
    tracer.active_offsets.sort_unstable();
    tracer.active_offsets.dedup();

    let total_coverage = (tracer.active_offsets.len() as f64 / bytes.len() as f64) * 100.0;
    let coverage_whitout_strings = (tracer.active_offsets.len() as f64
        / (bytes.len() - tracer.possible_string_offsets.len()) as f64)
        * 100.0;

    Ok(TraceResults {
        bytes: bytes.to_vec(),
        cf_addr_map: tracer.cf_addr_map,
        active_offsets: tracer.active_offsets,
        possible_string_offsets: tracer.possible_string_offsets,
        possible_strings: tracer.possible_strings,
        total_coverage,
        coverage_whitout_strings,
    })
}
