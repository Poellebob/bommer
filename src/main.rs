mod bom;
mod collection;
mod collectors;
mod config;
mod doctor;
mod job;
mod json;
mod manifest;
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
            let report = scan::run(&plan.jobs, &config.output_directory, config.timeout)?;

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
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use clap::Parser;

    use crate::{Args, Command, InventoryFilter};

    fn parse(input: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(
            std::iter::once(OsString::from("bommer")).chain(input.iter().map(OsString::from)),
        )
    }

    #[test]
    fn cli_defaults_and_explicit_selectors() {
        for (command, expect_doctor) in [("scan", false), ("doctor", true)] {
            let args = parse(&[command]).unwrap();

            match &args.command {
                Command::Scan(options) if !expect_doctor => {
                    assert_eq!(options.config, PathBuf::from("/etc/bommer/config.yaml"));
                    assert_eq!(options.only, None);
                    assert_eq!(options.application, None);
                }
                Command::Doctor(options) if expect_doctor => {
                    assert_eq!(options.config, PathBuf::from("/etc/bommer/config.yaml"));
                    assert_eq!(options.only, None);
                    assert_eq!(options.application, None);
                }
                other => panic!("unexpected command: {other:?}"),
            }
        }

        let args = parse(&[
            "scan",
            "--config",
            "local.yaml",
            "--only",
            "cbom",
            "--application",
            "api",
        ])
        .unwrap();

        match &args.command {
            Command::Scan(options) => {
                assert_eq!(options.config, PathBuf::from("local.yaml"));
                assert_eq!(options.only, Some(InventoryFilter::Cbom));
                assert_eq!(options.application.as_deref(), Some("api"));
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let args = parse(&["doctor", "--only=sbom", "--config=other.yaml"]).unwrap();

        match &args.command {
            Command::Doctor(options) => {
                assert_eq!(options.config, PathBuf::from("other.yaml"));
                assert_eq!(options.only, Some(InventoryFilter::Sbom));
                assert_eq!(options.application, None);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let args = parse(&["scan", "--only", "hbom"]).unwrap();

        match &args.command {
            Command::Scan(options) => {
                assert_eq!(options.only, Some(InventoryFilter::Hbom));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn help_and_version_are_typed_clap_errors() {
        for input in [
            vec!["--help"],
            vec!["-h"],
            vec!["help"],
            vec!["scan", "--help"],
            vec!["doctor", "-h"],
            vec!["help", "scan"],
            vec!["help", "doctor"],
            vec!["version", "--help"],
            vec!["help", "version"],
        ] {
            let error = parse(&input).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        }

        let error = parse(&["--version"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);

        assert!(matches!(
            parse(&["version"]).unwrap(),
            Args {
                command: Command::Version
            }
        ));
    }

    #[test]
    fn invalid_arguments_are_typed_usage_errors() {
        for input in [
            vec!["unknown"],
            vec!["scan", "--unexpected"],
            vec!["doctor", "positional"],
            vec!["scan", "--config"],
            vec!["scan", "--only", "unknown"],
            vec!["version", "extra"],
            vec!["help", "unknown"],
            vec!["help", "scan", "extra"],
            vec!["--config", "local.yaml", "scan"],
        ] {
            let error = parse(&input).unwrap_err();
            assert_eq!(error.exit_code(), 2);
        }
    }

    #[cfg(unix)]
    #[test]
    fn config_paths_preserve_non_unicode_bytes() {
        use std::os::unix::ffi::OsStringExt;

        let path = OsString::from_vec(vec![b'/', b't', b'm', b'p', b'/', 0xff]);

        let args = Args::try_parse_from([
            OsString::from("bommer"),
            OsString::from("scan"),
            OsString::from("--config"),
            path.clone(),
        ])
        .unwrap();

        match args.command {
            Command::Scan(options) => assert_eq!(options.config, path),
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
