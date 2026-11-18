use std::path::PathBuf;
use std::time::Duration;

use crate::model::Job;

#[derive(Debug)]
pub(crate) struct Config {
    output_directory: PathBuf,
    timeout: Duration,
    enabled_inventories: Vec<Job>,
}

#[derive(Debug)]
pub(crate) enum ConfigError {
    Io(std::io::Error),
    InvalidYaml,
    UnknownField { field: String },
    DuplicateKey { key: String },
    MultipleDocuments,
    UnsupportedVersion { version: u64 },
    MissingOutputDirectory,
    InvalidTimeout,
    InvalidInventory { name: String },
}
