use clap::CommandFactory;
use clap::Parser;
use colored::Colorize;
use hex::FromHexError;
use log::error;
use std::fs;
use std::process;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArgParseError {
    #[error("Target file not found.")]
    FileNotFound,
    #[error("Invalid offset values.")]
    InvalidOffsetValues,
    #[error("Address parsing failed: {0}")]
    AddressParseError(#[from] FromHexError),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
}

/// QSocket toolkit options.
#[derive(Parser, PartialEq, Debug)]
#[command(name = "Deoptimizer")]
#[command(version = "1.0.0")]
#[command(about = "Machine code deoptimizer.", long_about = None)]
pub struct Options {
    /// Target architecture (x86/arm).
    #[arg(long, short = 'a', default_value_t = String::from("x86"))]
    pub arch: String,

    /// target binary file name.
    #[arg(long, short = 'f', default_value_t = String::new())]
    pub file: String,

    /// output file name.
    #[arg(long, short = 'o', default_value_t = String::new())]
    pub outfile: String,

    /// source assembly file.
    #[arg(long, short = 's', default_value_t = String::new())]
    pub source: String,

    /// assembler formatter syntax (nasm/masm/intel/gas).
    #[arg(long, default_value_t = String::from("keystone"))]
    pub syntax: String,

    /// bitness of the binary file (16/32/64).
    #[arg(long, short = 'b', default_value_t = 64)]
    pub bitness: u32,

    /// start address in hexadecimal form.
    #[arg(long, short = 'A', default_value_t = String::from("0x0000000000000000"))]
    pub addr: String,

    /// File offset range for skipping deoptimization (eg: 0-10 for skipping first ten bytes).
    #[arg(long, value_parser, num_args = 1.., value_delimiter = '-')]
    pub skip_offsets: Vec<u32>,

    /// total number of deoptimization cycles.
    #[arg(long, short = 'c', default_value_t = 1)]
    pub cycle: u32,

    /// deoptimization frequency.
    #[arg(long, short = 'F', default_value_t = 0.5)]
    pub freq: f32,

    /// allowed transform routines (ap/li/lp/om/rs).
    #[arg(long, default_value_t = String::from("ap,li,lp,om,rs"))]
    pub transforms: String,

    /// allow processing of invalid instructions.
    #[arg(long)]
    pub allow_invalid: bool,

    /// verbose output mode.
    #[arg(long, short = 'v')]
    pub verbose: bool,

    /// debug output mode.
    #[arg(long)]
    pub debug: bool,
}
pub fn parse_options() -> Result<Options, ArgParseError> {
    // let mut opts: Options = argh::from_env();
    let mut opts = Options::parse();
    if opts.file.is_empty() {
        print!("\n");
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

    if opts.outfile.is_empty() {
        opts.outfile = format!("{}_deopt.bin", opts.file);
    }

    if opts.skip_offsets.len() > 0 {
        if opts.skip_offsets.len() % 2 != 0 {
            return Err(ArgParseError::InvalidOffsetValues);
        }

        let mut i = 0;
        while i < opts.skip_offsets.len() - 1 {
            if opts.skip_offsets[i] >= opts.skip_offsets[i + 1] {
                return Err(ArgParseError::InvalidOffsetValues);
            }
            i += 2;
        }
    }

    if opts.verbose {
        log::set_max_level(log::LevelFilter::Debug);
    }
    if opts.debug {
        log::set_max_level(log::LevelFilter::Trace);
    }
    Ok(opts)
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
    print!("\n");
}
