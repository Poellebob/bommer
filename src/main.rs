mod bom;
mod collection;
mod collectors;
mod config;
mod doctor;
mod job;
mod json;
mod output;
mod path_encoding;
mod plan;
mod process;
mod scan;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, PartialEq, Eq, Parser)]
#[command(
    name = "bommer",
    version,
    about = "Collect CycloneDX inventories",
    long_about = concat!(
        "Bommer collects CycloneDX software bills of materials (SBOM),\n",
        "hardware bills of materials (HBOM), and cryptographic bills of materials (CBOM)\n",
        "from configured sources and writes them to an output directory with a run manifest."
    ),
    after_help = concat!(
        "Examples:\n",
        "  bommer scan --config /etc/bommer/config.yaml\n",
        "  bommer scan --only sbom --application api\n",
        "  bommer doctor --config local.yaml\n",
        "  bommer version"
    )
)]
pub(crate) struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, PartialEq, Eq, Subcommand)]
pub(crate) enum Command {
    /// Collect and write the selected inventories.
    Scan(Options),

    /// Check collector readiness without collecting inventories.
    Doctor(Options),

    /// Print the installed package version.
    Version,
}

#[derive(Debug, PartialEq, Eq, clap::Args)]
pub(crate) struct Options {
    /// Path to the inventory configuration.
    #[arg(long, default_value = "/etc/bommer/config.yaml")]
    config: PathBuf,

    /// Collect or check only this inventory kind.
    #[arg(long, value_enum)]
    only: Option<InventoryFilter>,

    /// Select a configured application instead of host inventories.
    #[arg(long)]
    application: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum InventoryFilter {
    Hbom,
    Sbom,
    Cbom,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Config(#[from] config::ConfigError),

    #[error(transparent)]
    Application(#[from] job::NameError),

    #[error(transparent)]
    Plan(#[from] plan::PlanError),

    #[error(transparent)]
    Scan(#[from] scan::ScanError),
}

impl Options {
    fn load_plan(self) -> Result<(config::Config, plan::Plan), CliError> {
        let config = config::Config::load(&self.config)?;

        let kind = self.only.map(|kind| match kind {
            InventoryFilter::Hbom => job::InventoryKind::Hbom,
            InventoryFilter::Sbom => job::InventoryKind::Sbom,
            InventoryFilter::Cbom => job::InventoryKind::Cbom,
        });
        let application = self.application.map(job::Name::new).transpose()?;
        let plan = plan::Plan::build(&config, &plan::Selection { kind, application })?;

        Ok((config, plan))
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {}", terminal_error(&error));
            match error {
                CliError::Config(_) | CliError::Application(_) | CliError::Plan(_) => {
                    ExitCode::from(2)
                }
                CliError::Scan(_) => ExitCode::FAILURE,
            }
        }
    }
}

fn run() -> Result<ExitCode, CliError> {
    match Args::parse().command {
        Command::Scan(options) => {
            let (config, plan) = options.load_plan()?;
            let report = scan::run(&config, &plan)?;

            println!("{}", report.directory.display());

            Ok(ExitCode::from(u8::from(report.unsuccessful)))
        }

        Command::Doctor(options) => {
            let (_config, plan) = options.load_plan()?;
            let report = doctor::check(&plan.jobs);

            for readiness in &report.results {
                match &readiness.result {
                    Ok(()) => println!("ready {}", readiness.name),
                    Err(error) => {
                        eprintln!("not ready {}: {}", readiness.name, terminal_error(error));
                    }
                }
            }

            Ok(ExitCode::from(u8::from(report.is_unsuccessful())))
        }

        Command::Version => {
            println!("bommer {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn terminal_error(error: &dyn std::error::Error) -> String {
    error
        .to_string()
        .chars()
        .flat_map(char::escape_default)
        .collect()
}

#[cfg(test)]
mod architecture_tests;
#[cfg(test)]
mod bom_tests;
#[cfg(test)]
mod cli_tests;
#[cfg(test)]
mod collection_context_tests;
#[cfg(test)]
mod collection_outcome_tests;
#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod doctor_tests;
#[cfg(test)]
mod duration_tests;
#[cfg(test)]
mod external_tests;
#[cfg(test)]
mod import_tests;
#[cfg(test)]
mod job_tests;
#[cfg(test)]
mod native_tests;
#[cfg(test)]
mod path_encoding_tests;
#[cfg(test)]
mod plan_tests;
#[cfg(test)]
mod process_tests;
#[cfg(test)]
mod scan_tests;
