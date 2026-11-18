mod bom;
mod cli;
mod collectors;
mod config;
mod json;
mod model;
mod output;
mod plan;
mod process;
mod runner;

#[cfg(test)]
mod architecture_tests;
#[cfg(test)]
mod behavior_tests;
#[cfg(test)]
mod bom_tests;
#[cfg(test)]
mod cli_tests;
#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod external_tests;
#[cfg(test)]
mod import_tests;
#[cfg(test)]
mod native_tests;
#[cfg(test)]
mod process_tests;
#[cfg(test)]
mod runner_tests;

use std::process::ExitCode;
use std::sync::{Arc, atomic::AtomicBool};

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err((code, error)) => {
            // Escape controls from paths and other untrusted diagnostic context.
            let safe: String = error
                .to_string()
                .chars()
                .flat_map(char::escape_default)
                .collect();
            eprintln!("{safe}");
            ExitCode::from(code)
        }
    }
}

fn run() -> Result<u8, (u8, Box<dyn std::error::Error>)> {
    let request = cli::Request::parse(std::env::args_os().skip(1)).map_err(|error| {
        (
            error.exit_code() as u8,
            Box::new(error) as Box<dyn std::error::Error>,
        )
    })?;
    let (config_path, only, application, doctor) = match request {
        cli::Request::Version => {
            println!("bommer {}", env!("CARGO_PKG_VERSION"));
            return Ok(0);
        }
        cli::Request::Help => {
            println!(
                "Usage: bommer <scan|doctor|version>\n\nOptions for scan and doctor:\n  --config <PATH>       YAML configuration (default: /etc/bommer/config.yaml)\n  --only <KIND>         hbom, sbom, or cbom\n  --application <NAME>  Select one application"
            );
            return Ok(0);
        }
        cli::Request::Scan {
            config,
            only,
            application,
        } => (config, only, application, false),
        cli::Request::Doctor {
            config,
            only,
            application,
        } => (config, only, application, true),
    };
    let config = config::Config::load(&config_path)
        .map_err(|error| (2, Box::new(error) as Box<dyn std::error::Error>))?;
    let kind = only.map(|kind| match kind {
        cli::Only::Hbom => model::InventoryKind::Hbom,
        cli::Only::Sbom => model::InventoryKind::Sbom,
        cli::Only::Cbom => model::InventoryKind::Cbom,
    });
    let application = application
        .map(model::Name::new)
        .transpose()
        .map_err(|error| (2, Box::new(error) as Box<dyn std::error::Error>))?;
    let plan = plan::Plan::build(&config, &plan::Selection::new(kind, application))
        .map_err(|error| (2, Box::new(error) as Box<dyn std::error::Error>))?;
    if doctor {
        let report = runner::DoctorReport::check(plan.jobs());
        for readiness in report.results() {
            match readiness.result() {
                Ok(()) => println!("ready {}", readiness.name()),
                Err(error) => {
                    let safe: String = error
                        .to_string()
                        .chars()
                        .flat_map(char::escape_default)
                        .collect();
                    eprintln!("not ready {}: {safe}", readiness.name());
                }
            }
        }
        return Ok(u8::from(report.is_unsuccessful()));
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(signal, Arc::clone(&cancelled))
            .map_err(|error| (1, Box::new(error) as Box<dyn std::error::Error>))?;
    }
    let runner = runner::Runner::new()
        .map_err(|error| (1, Box::new(error) as Box<dyn std::error::Error>))?;
    let report = runner
        .execute(
            plan.jobs(),
            config.output_directory(),
            config.timeout(),
            cancelled,
        )
        .map_err(|error| (1, Box::new(error) as Box<dyn std::error::Error>))?;
    println!("{}", report.directory().display());
    Ok(u8::from(report.is_unsuccessful()))
}
