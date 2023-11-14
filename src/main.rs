use log::{error, info, warn, LevelFilter};
use std::io::Write;

mod options;
mod utils;
mod x86;

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
    let file = utils::read_file(opts.file.clone()).expect("failed reading target file");
    info!("File size: {}", file.len());
    let mut deopt = x86::Deoptimizer::new();
    deopt.set_syntax(opts.syntax).expect("invalid syntax");
    let out = deopt
        .disassemble(&file, opts.mode, 0x401000)
        .expect("disassembly failed!");
    println!("{}", out);
    match deopt.assemble(out.clone(), opts.mode, 0x401000) {
        Ok(b) => {
            let mut f2 = std::fs::File::create("success.bin").expect("failed opening file!");
            f2.write_all(&b.bytes).expect("failed writing!");
        }
        Err(e) => {
            error!("{}", e);
            let mut f2 = std::fs::File::create("error.asm").expect("failed opening file!");
            let _ = f2.write_all(b"[BITS 32]\n");
            f2.write_all(out.as_bytes()).expect("failed writing!");
        }
    };
    // hexdump::hexdump(&bin.bytes);
}
