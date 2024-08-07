use crate::x86_64::*;
use iced_x86::code_asm::*;
use iced_x86::*;
use log::{error, trace};
use regex::bytes::Regex;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TracerError {
    #[error("Branch target not found!")]
    BranchTargetNotFound,
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
    stack: Vec<Option<u64>>,
    context: HashMap<Register, Option<u64>>,
    cflags: HashMap<u32, usize>,
    cf_addr_map: Vec<u64>,
    cf_critical_addrs: Vec<u64>,
    active_offsets: Vec<u64>,
    possible_strings: Vec<String>,
    possible_string_offsets: Vec<u64>,
}

pub struct TraceResults {
    pub bytes: Vec<u8>,
    pub cf_addr_map: Vec<u64>,
    pub cf_critical_addrs: Vec<u64>,
    pub active_offsets: Vec<u64>,
    pub possible_strings: Vec<String>,
    pub possible_string_offsets: Vec<u64>,
    pub total_coverage: f64,
    pub coverage_whitout_strings: f64,
}

const RFLAG_BIT_VALUES: [u32; 9] = [
    RflagsBits::OF,
    RflagsBits::SF,
    RflagsBits::ZF,
    RflagsBits::AF,
    RflagsBits::CF,
    RflagsBits::PF,
    RflagsBits::DF,
    RflagsBits::IF,
    RflagsBits::AC,
];

// Very primitive tracer :P
impl Tracer {
    fn new(bytes: &[u8], bitness: u32) -> Self {
        let re = match bitness {
            64 => Regex::new(r"(?<str>[\x20-\x7E]{8,}\x00)").unwrap(),
            _ => Regex::new(r"(?<str>[\x20-\x7E]{4,}\x00)").unwrap(),
        };
        let mut ps = Vec::new();
        let mut pso = Vec::new();
        for mat in re.find_iter(bytes) {
            ps.push(String::from_utf8_lossy(mat.as_bytes()).to_string());
            for o in mat.start()..mat.start() + mat.len() {
                pso.push(o as u64);
            }
        }
        Self {
            bytes: bytes.to_vec(),
            bitness,
            stack: Vec::new(),
            context: HashMap::new(),
            cflags: HashMap::new(),
            cf_addr_map: Vec::new(),
            cf_critical_addrs: Vec::new(),
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

            // Check if this address is already exists in the flow map
            if self.cf_addr_map.contains(&ip) {
                trace!("[TRACER] HaltResason[0x{:016X}]: Loop Contition", ip);
                return Ok(HaltResason::LoopCondition);
            }

            // Add instruction address to control flow map and register active offsets
            if inst.flow_control() != FlowControl::Exception {
                trace!("[TRACER] 0x{:016X}:\t{}", ip, inst);
                self.cf_addr_map.push(ip);
                self.set_active_offsets(ip, ip + inst.len() as u64);
                self.handle_condition_flags(inst);
            }

            match inst.flow_control() {
                FlowControl::Next | FlowControl::Interrupt => {
                    // Adjust stack and context for each stack instruction
                    if inst.is_stack_instruction() {
                        self.handle_stack_operation(inst)?;
                    }
                }
                FlowControl::UnconditionalBranch => {
                    if let Ok(bt) = get_branch_target(&inst) {
                        return self.trace_code_paths(bt);
                    } else {
                        return Err(TracerError::BranchTargetNotFound);
                    }
                }
                FlowControl::ConditionalBranch => {
                    if let Ok(bt) = get_branch_target(&inst) {
                        let _ = self.trace_code_paths(bt);
                    } else {
                        return Err(TracerError::BranchTargetNotFound);
                    }
                }
                FlowControl::IndirectBranch => {
                    if self.context.contains_key(&inst.op0_register()) {
                        if let Some(val) = self.context[&inst.op0_register()] {
                            return self.trace_code_paths(val);
                        } else {
                            trace!("[TRACER] HaltResason[0x{:016X}]: Dynamic Branch Target", ip);
                            return Ok(HaltResason::DynamicBranch);
                        }
                    } else {
                        return Ok(HaltResason::DynamicBranch);
                    }
                }
                FlowControl::Return => {
                    trace!("[TRACER] HaltResason[0x{:016X}]: Return", ip);
                    self.stack.pop();
                    return Ok(HaltResason::Return);
                }
                FlowControl::Call => {
                    if let Ok(bt) = get_branch_target(&inst) {
                        self.stack.push(Some(inst.next_ip()));
                        let hr = self.trace_code_paths(bt)?;
                        if hr != HaltResason::Return
                            && self.possible_string_offsets.contains(&inst.next_ip())
                        {
                            return Ok(hr);
                        }
                    } else {
                        return Err(TracerError::BranchTargetNotFound);
                    }
                }
                FlowControl::IndirectCall => {
                    if self.context.contains_key(&inst.op0_register()) {
                        if let Some(val) = self.context[&inst.op0_register()] {
                            self.stack.push(Some(val));
                            let hr = self.trace_code_paths(val)?;
                            if hr != HaltResason::Return
                                && self.possible_string_offsets.contains(&inst.next_ip())
                            {
                                return Ok(hr);
                            }
                        }
                    } else {
                        return Ok(HaltResason::DynamicBranch);
                    }
                }
                FlowControl::Exception | FlowControl::XbeginXabortXend => {
                    trace!("[TRACER] HaltResason[0x{:016X}]: Invalid Instruction", ip);
                    return Ok(HaltResason::InvalidInstruction);
                }
            };

            ip = inst.next_ip();
            if ip == self.bytes.len() as u64 {
                break;
            }
        }
        trace!("[TRACER] HaltResason[0x{:016X}]: End Of Block", ip);
        Ok(HaltResason::EndOfBlock)
    }

    fn handle_condition_flags(&mut self, inst: Instruction) {
        let cleared = inst.rflags_cleared();
        let modified = inst.rflags_written() | inst.rflags_set();
        let read = inst.rflags_read();

        if cleared != RflagsBits::NONE {
            for flag in RFLAG_BIT_VALUES.iter() {
                if (cleared & flag) > 0 {
                    self.cflags.remove(flag);
                }
            }
        }

        if modified != RflagsBits::NONE {
            for flag in RFLAG_BIT_VALUES.iter() {
                if (modified & flag) > 0 {
                    self.cflags.insert(*flag, self.cf_addr_map.len());
                }
            }
        }

        if read != RflagsBits::NONE {
            for flag in RFLAG_BIT_VALUES.iter() {
                if (read & flag) > 0 {
                    if let Some(val) = self.cflags.get(flag) {
                        for addr in &self.cf_addr_map[*val..] {
                            self.cf_critical_addrs.push(*addr);
                        }
                    }
                }
            }
        }
    }

    fn handle_stack_operation(&mut self, inst: Instruction) -> Result<(), TracerError> {
        match inst.mnemonic() {
            Mnemonic::Pop => {
                if !self.stack.is_empty() {
                    if let Some(val) = self.stack.pop().unwrap() {
                        trace!("Poped 0x{:016X} into {:?}", val, inst.op0_register());
                        self.context.insert(inst.op0_register(), Some(val));
                    }
                }
            }
            Mnemonic::Push => {
                if is_immediate_operand(inst.op0_kind()) {
                    trace!("Pushed 0x{:016X} to stack", inst.immediate(0));
                    self.stack.push(Some(inst.immediate(0)));
                } else {
                    self.stack.push(None);
                }
            }
            // Mnemonic::Pusha => {
            //     self.stack
            //         .push(*self.context.get(&Register::AX).unwrap_or(&None));
            //     self.stack
            //         .push(*self.context.get(&Register::CX).unwrap_or(&None));
            //     self.stack
            //         .push(*self.context.get(&Register::DX).unwrap_or(&None));
            //     self.stack
            //         .push(*self.context.get(&Register::BX).unwrap_or(&None));
            //     self.stack.push(None);
            //     self.stack
            //         .push(*self.context.get(&Register::BP).unwrap_or(&None));
            //     self.stack
            //         .push(*self.context.get(&Register::SI).unwrap_or(&None));
            //     self.stack
            //         .push(*self.context.get(&Register::DI).unwrap_or(&None));
            // }
            // Mnemonic::Popa => {}
            // Mnemonic::Pushad => {}
            // Mnemonic::Popad => {}
            // Mnemonic::Pushf => {}
            // Mnemonic::Pushfd => {}
            // Mnemonic::Pushfq => {}
            _ => (),
        };
        Ok(())
    }
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
        cf_critical_addrs: tracer.cf_critical_addrs,
        active_offsets: tracer.active_offsets,
        possible_string_offsets: tracer.possible_string_offsets,
        possible_strings: tracer.possible_strings,
        total_coverage,
        coverage_whitout_strings,
    })
}
