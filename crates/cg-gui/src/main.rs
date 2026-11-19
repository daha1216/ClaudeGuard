#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use cg_gui::app::{USAGE, parse_args, run};

fn main() {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(msg) if msg == USAGE => {
            println!("{msg}");
            return;
        }
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };
    run(args);
}
