use clap::CommandFactory;
use clap::Parser;
use hex::FromHexError;
use log::error;
use std::fs;
use std::process;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArgParseError {
    #[error("Target file not found")]
    FileNotFound,
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

    if opts.verbose {
        log::set_max_level(log::LevelFilter::Debug);
    }
    Ok(opts)
}

// pub fn summarize_options(opts: &Options) {
//     if opts.quiet {
//         return;
//     }
//     let mut mode = String::from("client");
//     let mut enc_mode = DEFAULT_E2E_CIPHER.to_string();
//
//     if opts.listen {
//         mode = String::from("server");
//     }
//     if opts.no_encryption {
//         enc_mode = "DISABLED".red().bold().to_string();
//     } else if opts.no_e2e {
//         enc_mode = String::from("TLS");
//     }
//
//     println!(
//         "{} {}",
//         "[#]".yellow().bold(),
//         ".:: QSocket Lite ::.".blue().bold()
//     );
//     println!("{} Secret: {}", " ├──>".yellow(), opts.secret.red());
//     println!("{} Mode: {}", " ├──>".yellow(), mode);
//     if !opts.cert_fingerprint.is_empty() {
//         println!("{} Cert. Pinning: true", " ├──>".yellow());
//     }
//     println!("{} Probe Interval: {}", " ├──>".yellow(), opts.probe);
//     if !opts.proxy_addr.is_empty() {
//         println!("{} Proxy: {}", " ├──>".yellow(), opts.proxy_addr);
//     }
//     if !opts.forward_addr.is_empty() {
//         println!("{} Forward: {}", " ├──>".yellow(), opts.forward_addr);
//     }
//     println!("{} Encryption: {}", " └──>".yellow(), enc_mode);
//     println!();
// }
