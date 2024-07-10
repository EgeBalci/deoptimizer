// use crate::x86_64::disassembler;
use crate::x86_64::disassembler::disassemble;
use base64::prelude::*;
use colored::Colorize;
use log::{error, info, warn, LevelFilter};
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
    options::print_summary(&opts);

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
    deopt.trace = opts.trace;
    deopt.allow_invalid = opts.allow_invalid;
    deopt.set_skipped_offsets(opts.skip_offsets);
    if let Err(e) = deopt.set_transform_gadgets(opts.transforms) {
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

    let mut input = file.clone();
    let mut output = Vec::new();
    for _ in 0..opts.cycle {
        info!("Analyzing input binary...");
        let acode = match deopt.analyze(&input, opts.bitness, start_addr) {
            Ok(ac) => ac,
            Err(e) => {
                error!("{}", e);
                return;
            }
        };
        info!("Deoptimizing...");
        output = match deopt.deoptimize(&acode) {
            Ok(b) => b,
            Err(e) => {
                error!("{}", e);
                return;
            }
        };
        input = output.clone();
    }

    if opts.source.is_empty() {
        match out_file.write_all(&output) {
            Ok(()) => (),
            Err(e) => {
                error!("{}", e);
                return;
            }
        }
        info!("De-optimized binary written into {}", opts.outfile);
    } else {
        let source = match disassemble(&output, opts.bitness, start_addr, opts.syntax) {
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
