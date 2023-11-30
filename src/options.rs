use clap::Parser;
use std::fs;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArgParseError {
    #[error("Target file not found")]
    FileNotFound,
}

/// QSocket toolkit options.
#[derive(Parser, Debug)]
#[command(name = "Deoptimizer")]
#[command(version = "1.0.0")]
#[command(about = "Deoptimizer.", long_about = None)]
pub struct Options {
    /// target x86 binary file name.
    #[arg(long, short = 'f', default_value_t = String::new())]
    pub file: String,

    /// source assembly file.
    #[arg(long, short = 's', default_value_t = String::new())]
    pub source: String,

    /// assembler formatter syntax (nasm/masm/intel/gas).
    #[arg(long, default_value_t = String::from("keystone"))]
    pub syntax: String,

    /// bitness of the binary file (16/32/64).
    #[arg(long, short = 'b', default_value_t = 64)]
    pub bitness: u32,

    /// total number of deoptimization cycles.
    #[arg(long, short = 'c', default_value_t = 1)]
    pub cycle: u32,

    /// deoptimization frequency.
    #[arg(long, short = 'F', default_value_t = 0.5)]
    pub freq: f64,

    /// allow processing of invalid instructions.
    #[arg(long)]
    pub allow_invalid: bool,

    /// verbose output mode.
    #[arg(long, short = 'v')]
    pub verbose: bool,
}

pub fn parse_options() -> Result<Options, ArgParseError> {
    // let mut opts: Options = argh::from_env();
    let opts = Options::parse();

    if fs::metadata(opts.file.clone()).is_err() {
        return Err(ArgParseError::FileNotFound);
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
