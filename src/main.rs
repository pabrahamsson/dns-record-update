extern crate env_logger;

use chrono::Local;
use dns_record_update::{Config, LogMessage};
use env_logger::Builder;
use log::{error, LevelFilter};
use std::{env, io::Write, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    let config = Config::new(&args).unwrap_or_else(|err| {
        error!("Failed to parse arguments: {}", err);
        process::exit(1)
    });
    Builder::new()
        .format(|buf, record| {
            let log_message = LogMessage {
                timestamp: format!("{}", Local::now().format("%Y-%m-%dT%H:%M:%S")),
                loglevel: record.level().to_string(),
                message: record.args().to_string(),
            };
            writeln!(buf, "{}", serde_json::to_string(&log_message).unwrap())
        })
        .filter(None, LevelFilter::Warn)
        .init();

    if let Err(e) = dns_record_update::run(config) {
        println!("Application error: {}", e);
        process::exit(1);
    }
}
