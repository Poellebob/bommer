// Contracts are intentionally not all consumed until the execution pipeline exists.
#![allow(dead_code)]

mod bom;
mod cli;
mod collectors;
mod config;
mod model;
mod output;
mod plan;
mod process;
mod runner;

#[cfg(test)]
mod behavior_tests;

use std::process::ExitCode;

fn main() -> ExitCode {
    match cli::Request::parse(std::env::args_os().skip(1)) {
        Ok(cli::Request::Version) => {
            println!("bommer {} (Rust scaffold)", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(cli::Request::Help) => {
            println!(
                "Usage: bommer <scan|doctor|version>\n\nThe Rust scan pipeline is not implemented yet."
            );
            ExitCode::SUCCESS
        }
        Ok(cli::Request::Scan | cli::Request::Doctor) => {
            eprintln!("The Rust scan pipeline is not implemented yet; use the Go prototype.");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
