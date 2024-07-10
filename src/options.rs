use clap::crate_version;
use clap::CommandFactory;
use clap::Parser;
use colored::Colorize;
use hex::FromHexError;
use log::error;
use std::fs;
use std::num::ParseIntError;
use std::process;
use thiserror::Error;

const VERSION: &str = crate_version!();

#[derive(Error, Debug)]
pub enum ArgParseError {
    #[error("Target file not found.")]
    FileNotFound,
    #[error("Invalid offset values.")]
    InvalidOffsetValues,
    #[error("Invalid formatter syntax.")]
    InvalidSyntax,
    #[error("Address parsing failed: {0}")]
    AddressParseError(#[from] FromHexError),
    #[error("Integer parsing failed: {0}")]
    IntegerParseError(#[from] ParseIntError),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Deoptimizer options.
#[derive(Parser, PartialEq, Debug)]
#[command(name = "Deoptimizer")]
#[command(version = VERSION)]
#[command(about = "Machine code deoptimizer.", long_about = None)]
pub struct Options {
    /// Target architecture (x86/arm).
    #[arg(long, short = 'a', default_value_t = String::from("x86"))]
    pub arch: String,

    /// Target binary file name.
    #[arg(long, short = 'f', default_value_t = String::new())]
    pub file: String,

    /// Output file name.
    #[arg(long, short = 'o', default_value_t = String::new())]
    pub outfile: String,

    /// Source assembly file.
    #[arg(long, short = 's', default_value_t = String::new())]
    pub source: String,

    /// Assembler formatter syntax (nasm/masm/intel/gas).
    #[arg(long, default_value_t = String::from("keystone"))]
    pub syntax: String,

    /// Bitness of the binary file (16/32/64).
    #[arg(long, short = 'b', default_value_t = 64)]
    pub bitness: u32,

    /// Start address in hexadecimal form.
    #[arg(long, short = 'A', default_value_t = String::from("0x0000000000000000"))]
    pub addr: String,

    /// File offset range for skipping deoptimization (eg: 0-10 for skipping first ten bytes).
    #[arg(long, value_parser=parse_offset, num_args = 1.., value_delimiter = ',')]
    pub skip_offsets: Vec<(u64, u64)>,

    /// Auto-skip dead-code and strings by control flow tracing.
    #[arg(long, short = 'T')]
    pub trace: bool,

    /// Total number of deoptimization cycles.
    #[arg(long, short = 'c', default_value_t = 1)]
    pub cycle: u32,

    /// Deoptimization frequency.
    #[arg(long, short = 'F', default_value_t = 0.5)]
    pub freq: f32,

    /// Allowed transform routines (ap/li/lp/om/rs).
    #[arg(long, default_value_t = String::from("ap,li,lp,om,rs"))]
    pub transforms: String,

    /// Allow processing of invalid instructions.
    #[arg(long)]
    pub allow_invalid: bool,

    /// Verbose output mode.
    #[arg(long, short = 'v')]
    pub verbose: bool,

    /// Debug output mode.
    #[arg(long)]
    pub debug: bool,
}
pub fn parse_options() -> Result<Options, ArgParseError> {
    // let mut opts: Options = argh::from_env();
    let mut opts = Options::parse();
    if opts.file.is_empty() {
        println!();
        error!("The '-f' parameter is mandatory.\n");
        Options::command().print_help()?;
        process::exit(0x01);
    }
    if fs::metadata(opts.file.clone()).is_err() {
        return Err(ArgParseError::FileNotFound);
    }
    if !opts.addr.is_empty() {
        let _ = hex::decode(opts.addr.trim_start_matches("0x"))?;
    }
    if !opts.source.is_empty() {
        opts.outfile = opts.source.clone();
    }

    if !matches!(
        opts.syntax.to_uppercase().as_str(),
        "KEYSTONE" | "NASM" | "MASM" | "INTEL" | "GAX"
    ) {
        return Err(ArgParseError::InvalidSyntax);
    }

    if opts.outfile.is_empty() {
        opts.outfile = format!("{}_deopt.bin", opts.file);
    }

    if opts.verbose {
        log::set_max_level(log::LevelFilter::Debug);
    }
    if opts.debug {
        log::set_max_level(log::LevelFilter::Trace);
    }
    Ok(opts)
}

pub fn parse_offset(offsets: &str) -> Result<(u64, u64), ArgParseError> {
    if offsets.matches('-').count() != 1 {
        return Err(ArgParseError::InvalidOffsetValues);
    }
    let mut off: Vec<u64> = Vec::new();
    for part in offsets.split('-') {
        if part.starts_with("0x") {
            off.push(u64::from_str_radix(part.trim_start_matches("0x"), 16)?)
        } else {
            off.push(part.parse()?)
        }
    }
    if off[0] > off[1] {
        return Err(ArgParseError::InvalidOffsetValues);
    }
    Ok((off[0], off[1]))
}

pub fn print_summary(opts: &Options) {
    let mut wspace = 48;
    if opts.file.len() > wspace {
        wspace = opts.file.len() + (wspace / 4)
    }
    if opts.outfile.len() > wspace {
        wspace = opts.outfile.len() + (wspace / 4)
    }

    let freq_str = format!("%{:.4}", opts.freq * 100.0);
    let trace_str = format!("{:?}", opts.trace);
    println!(
        "\n[ {} {} {} ]",
        "#".repeat(wspace / 2 + 2).yellow().bold(),
        "OPTIONS".green().bold(),
        "#".repeat(wspace / 2 + 2).yellow().bold()
    );
    println!(
        "| {} {}{}|",
        "Architecture:".blue().bold(),
        opts.arch,
        " ".repeat(wspace - opts.arch.len())
    ); // 17 chars
    println!(
        "| {} {}{}|",
        "Input File:  ".blue().bold(),
        opts.file,
        " ".repeat(wspace - opts.file.len())
    );
    println!(
        "| {} {}{}|",
        "Output File: ".blue().bold(),
        opts.outfile,
        " ".repeat(wspace - opts.outfile.len())
    );
    println!(
        "| {} {}{}|",
        "Bitness:     ".blue().bold(),
        opts.bitness,
        " ".repeat(wspace - 2)
    );
    println!(
        "| {} {}{}|",
        "Start Addr:  ".blue().bold(),
        opts.addr,
        " ".repeat(wspace - opts.addr.len())
    );
    println!(
        "| {} {}{}|",
        "Frequency:   ".blue().bold(),
        freq_str,
        " ".repeat(wspace - freq_str.len())
    );
    println!(
        "| {} {}{}|",
        "Cycle Count: ".blue().bold(),
        opts.cycle,
        " ".repeat(wspace - 1)
    );
    println!(
        "[ {} {}{}]",
        "Transforms:  ".blue().bold(),
        opts.transforms,
        " ".repeat(wspace - opts.transforms.len())
    );
    println!(
        "[ {} {}{}]",
        "Auto Trace:  ".blue().bold(),
        opts.trace,
        " ".repeat(wspace - trace_str.len())
    );
    println!();
}
