use chrono::offset::Local;
use colored::Colorize;
use core::time;
use log::warn;
use log::{Level, Metadata, Record};
use std::fs::File;
// use std::io;
use std::io::BufReader;
use std::io::Read;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering::SeqCst;
use std::thread;
// use std::sync::mpsc::Receiver;
// use std::sync::{Arc, Mutex};

#[allow(dead_code)]
static SIGINT_COUNTER: AtomicU8 = AtomicU8::new(0);

pub struct Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() < Level::Trace
    }
    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let now = Local::now();
            match record.level() {
                Level::Trace => println!(
                    "[{}] {} {}",
                    now.format("%Y-%m-%d %H:%M:%S"),
                    "TRACE".bold(),
                    record.args()
                ),
                Level::Debug => println!(
                    "[{}] {} {}",
                    now.format("%Y-%m-%d %H:%M:%S"),
                    "DEBUG".bold(),
                    record.args()
                ),
                Level::Info => println!(
                    "[{}] {} {}",
                    now.format("%Y-%m-%d %H:%M:%S"),
                    "INFO".blue().bold(),
                    record.args()
                ),
                Level::Warn => println!(
                    "[{}] {} {}",
                    now.format("%Y-%m-%d %H:%M:%S"),
                    "WARN".yellow().bold(),
                    record.args()
                ),
                Level::Error => println!(
                    "[{}] {} {}",
                    now.format("%Y-%m-%d %H:%M:%S"),
                    "ERROR".red().bold(),
                    record.args()
                ),
            }
            // println!("{} - {}", record.level(), record.args());
        }
    }
    fn flush(&self) {}
}

#[allow(dead_code)]
pub fn wait_for_sigint(limit: u8) {
    let _ = ctrlc::set_handler(move || {
        let mut counter = SIGINT_COUNTER.load(SeqCst);
        if counter == limit {
            warn!("Exiting...");
            std::process::exit(0x00);
        }
        counter += 1;
        SIGINT_COUNTER.store(counter, SeqCst);
    });

    thread::spawn(|| loop {
        SIGINT_COUNTER.store(0, SeqCst);
        thread::sleep(time::Duration::from_secs(2));
    });
}

pub fn read_file(fname: String) -> Result<Vec<u8>, std::io::Error> {
    let f = File::open(fname)?;
    let mut reader = BufReader::new(f);
    let mut buffer = Vec::new();
    // Read file into vector.
    reader.read_to_end(&mut buffer)?;
    Ok(buffer)
}

// #[allow(dead_code)]
// pub fn wait_for_sigint(limit: u8) -> Result<(), anyhow::Error> {
//     let mut signals = Signals::new(&[SIGINT])?;
//     thread::spawn(move || {
//         for _sig in signals.forever() {
//             println!("Got new sig: {_sig}");
//             let mut counter = SIGINT_COUNTER.load(SeqCst);
//             if counter == limit {
//                 warn!("Exiting...");
//                 std::process::exit(0x00);
//             }
//             counter += 1;
//             SIGINT_COUNTER.store(counter, SeqCst);
//         }
//     });
//
//     thread::spawn(|| loop {
//         SIGINT_COUNTER.store(0, SeqCst);
//         thread::sleep(time::Duration::from_secs(2));
//     });
//     Ok(())
// }
