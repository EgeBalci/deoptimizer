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

    if opts.freq > 0.8 || opts.cycle > 2 {
        warn!("Deoptimization parameters are too aggressive!");
        warn!("The output size will drasstically increase.")
    }

    let file = utils::read_file(opts.file.clone()).expect("failed reading target file!");
    let mut out_file = File::create(opts.outfile).expect("source file creation failed!");
    info!("File size: {}", file.len());
    let mut deopt = x86_64::Deoptimizer::new();
    deopt.freq = opts.freq;
    deopt.set_syntax(opts.syntax).expect("invalid syntax");
    let start_addr = u64::from_str_radix(opts.addr.trim_start_matches("0x"), 16)
        .expect("Start address decoding failed!");
    let acode = deopt
        .analyze(&file, opts.bitness, start_addr)
        .expect("code analysis failed!");
    // let out = deopt.disassemble(&acode).expect("disassembly failed!");
    // println!("{}", out);
    info!("Deoptimizing...");
    let bin = deopt.deoptimize(&acode);
    let bytes = match bin {
        Ok(b) => b,
        Err(e) => {
            error!("{}", e);
            return;
        }
    };
    let _ = out_file.write_all(&bytes);
    info!("All done!");
}
