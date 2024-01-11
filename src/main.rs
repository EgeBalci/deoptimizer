use base64::prelude::*;
use colored::Colorize;
use log::{error, info, warn, LevelFilter};
use std::error;
use std::fs::File;
use std::io::Write;

mod options;
mod utils;
mod x86_64;

// const TIMEOUT: u64 = 30;
static LOGGER: utils::Logger = utils::Logger;

fn main() {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(LevelFilter::Info);
    let opts = match options::parse_options() {
        Ok(o) => o,
        Err(e) => {
            error!("{e}");
            return;
        }
    };

    print_banner();
    print_summary(&opts);

    if opts.arch.to_lowercase() != "x86" {
        error!("Currently only x86 architecture is supported.");
        return;
    }

    if opts.freq > 0.8 || opts.cycle > 2 {
        warn!("Deoptimization parameters are too aggressive!");
        warn!("The output size will drasstically increase.")
    }

    let file = match utils::read_file(opts.file.clone()) {
        Ok(f) => f,
        Err(e) => {
            error!("{}", e);
            return;
        }
    };
    let mut out_file = match File::create(opts.outfile.clone()) {
        Ok(f) => f,
        Err(e) => {
            error!("{}", e);
            return;
        }
    };

    info!("Input file size: {}", file.len());
    let mut deopt = x86_64::Deoptimizer::new();
    deopt.freq = opts.freq;
    if let Err(e) = deopt.set_transform_gadgets(opts.transforms) {
        error!("{}", e);
        return;
    }
    if let Err(e) = deopt.set_syntax(opts.syntax) {
        error!("{}", e);
        return;
    }
    let start_addr = match u64::from_str_radix(opts.addr.trim_start_matches("0x"), 16) {
        Ok(addr) => addr,
        Err(e) => {
            error!("{}", e);
            return;
        }
    };
    info!("Analyzing input binary...");
    let acode = match deopt.analyze(&file, opts.bitness, start_addr) {
        Ok(ac) => ac,
        Err(e) => {
            error!("{}", e);
            return;
        }
    };
    info!("Deoptimizing...");
    let bin = deopt.deoptimize(&acode);
    let bytes = match bin {
        Ok(b) => b,
        Err(e) => {
            error!("{}", e);
            return;
        }
    };
    if opts.source.is_empty() {
        match out_file.write_all(&bytes) {
            Ok(()) => (),
            Err(e) => {
                error!("{}", e);
                return;
            }
        }
        info!("De-optimized binary written into {}", opts.outfile);
    } else {
        let source = match deopt.disassemble(opts.bitness, start_addr, bytes) {
            Ok(s) => s,
            Err(e) => {
                error!("{}", e);
                return;
            }
        };
        match out_file.write_all(source.as_bytes()) {
            Ok(()) => (),
            Err(e) => {
                error!("{}", e);
                return;
            }
        }
        info!("De-optimized assembly source written into {}", opts.outfile);
    }

    println!("{} All done!", "[✔]".green().bold());
}

fn print_summary(opts: &options::Options) {
    let mut wspace = 48;
    if opts.file.len() > wspace {
        wspace = opts.file.len() + (wspace / 4)
    }
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
        format!("%{}", opts.freq),
        " ".repeat(wspace - 4)
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

fn print_banner() {
    let banner_b64 = b"ICBfX19fXyAgICAgICAgICAgICAgIF9fX18gICAgICAgIF8gICAgICAgICAgICAgICAgICAgICAgICAgICAgCiB8ICBfXyBcICAgICAgICAgICAgIC8gX18gXCAgICAgIHwgfCAo4piiKSAgICAgICAgICjimKIpICAgICAgICAgICAgIAogfCB8ICB8IHwgX19fIF9fX19fX3wgfCAgfCB8XyBfXyB8IHxfIF8gXyBfXyBfX18gIF8gX19fX19fXyBfIF9fIAogfCB8ICB8IHwvIF8gXF9fX19fX3wgfCAgfCB8ICdfIFx8IF9ffCB8ICdfIGAgXyBcfCB8XyAgLyBfIFwgJ19ffAogfCB8X198IHwgIF9fLyAgICAgIHwgfF9ffCB8IHxfKSB8IHxffCB8IHwgfCB8IHwgfCB8LyAvICBfXy8gfCAgIAogfF9fX19fLyBcX19ffCAgICAgICBcX19fXy98IC5fXy8gXF9ffF98X3wgfF98IHxffF8vX19fXF9fX3xffCAgIAo9PT09PT09PT09PT09PT09PT09PT09PT09PT18X3wgKOODjiDjgpzQlOOCnCnjg44g77i1IMK/cMedeuG0icmv4bSJyodkbyBvcyDKjsmlyo0KICAgICAgICAgRGUtT3B0aW1pemVyIOKYoyBDb3B5cmlnaHQgKGMpIDIwMjQgRUdFIEJBTENJIA==";

    println!(
        "{}",
        String::from_utf8(
            BASE64_STANDARD
                .decode(banner_b64)
                .expect("base64 decode failed!")
        )
        .expect("can not convert to utf8")
    );
}
