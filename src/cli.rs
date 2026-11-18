use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Only {
    Hbom,
    Sbom,
    Cbom,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Request {
    Help,
    Version,
    Scan {
        config: PathBuf,
        only: Option<Only>,
        application: Option<String>,
    },
    Doctor {
        config: PathBuf,
        only: Option<Only>,
        application: Option<String>,
    },
}

#[derive(Debug, Error)]
pub(crate) enum CliError {
    #[error(transparent)]
    Arguments(#[from] clap::Error),
}

impl CliError {
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Self::Arguments(error) => error.exit_code(),
        }
    }
}

#[derive(Parser)]
#[command(
    name = "bommer",
    version,
    about = "Collect CycloneDX inventories",
    disable_help_subcommand = true
)]
struct Arguments {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Scan(Options),
    Doctor(Options),
    Version,
    Help {
        #[arg(value_enum)]
        command: Option<HelpCommand>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum HelpCommand {
    Scan,
    Doctor,
    Version,
    Help,
}

#[derive(Args)]
struct Options {
    #[arg(long, default_value = "/etc/bommer/config.yaml")]
    config: PathBuf,
    #[arg(long, value_enum)]
    only: Option<Only>,
    #[arg(long)]
    application: Option<String>,
}

impl Request {
    // Callers supply arguments without argv[0]; clap still receives a program name.
    pub(crate) fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, CliError> {
        let args = std::iter::once(OsString::from("bommer")).chain(args);
        let parsed = match Arguments::try_parse_from(args) {
            Ok(parsed) => parsed,
            Err(error) => {
                return match error.kind() {
                    clap::error::ErrorKind::DisplayHelp => Ok(Self::Help),
                    clap::error::ErrorKind::DisplayVersion => Ok(Self::Version),
                    _ => Err(error.into()),
                };
            }
        };
        Ok(match parsed.command {
            None | Some(Command::Help { .. }) => Self::Help,
            Some(Command::Version) => Self::Version,
            Some(Command::Scan(options)) => Self::Scan {
                config: options.config,
                only: options.only,
                application: options.application,
            },
            Some(Command::Doctor(options)) => Self::Doctor {
                config: options.config,
                only: options.only,
                application: options.application,
            },
        })
    }
}
