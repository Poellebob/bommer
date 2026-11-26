use std::path::PathBuf;

use serde::{Deserialize, Deserializer};

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Document {
    #[serde(deserialize_with = "null_default")]
    pub(crate) version: i64,
    #[serde(deserialize_with = "null_default")]
    pub(crate) output: Output,
    #[serde(deserialize_with = "null_default")]
    pub(crate) timeout: String,
    #[serde(deserialize_with = "null_default")]
    pub(crate) host: Host,
    #[serde(deserialize_with = "null_default")]
    pub(crate) applications: Vec<Application>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Output {
    #[serde(deserialize_with = "null_default")]
    pub(crate) directory: String,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Host {
    #[serde(deserialize_with = "null_default")]
    pub(crate) hbom: Collector,
    #[serde(deserialize_with = "null_default")]
    pub(crate) sbom: Collector,
    #[serde(deserialize_with = "null_default")]
    pub(crate) inventories: Vec<Inventory>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Application {
    #[serde(deserialize_with = "null_default")]
    pub(crate) name: String,
    #[serde(deserialize_with = "null_default")]
    pub(crate) version: String,
    #[serde(deserialize_with = "null_default")]
    pub(crate) target: RawTarget,
    #[serde(deserialize_with = "null_default")]
    pub(crate) sbom: Collector,
    #[serde(deserialize_with = "null_default")]
    pub(crate) cbom: Collector,
    #[serde(deserialize_with = "null_default")]
    pub(crate) inventories: Vec<Inventory>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct RawTarget {
    #[serde(rename = "type", deserialize_with = "null_default")]
    pub(crate) kind: String,
    #[serde(deserialize_with = "null_default")]
    pub(crate) path: String,
    #[serde(deserialize_with = "null_default")]
    pub(crate) image: String,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Inventory {
    #[serde(deserialize_with = "null_default")]
    pub(crate) name: String,
    #[serde(deserialize_with = "null_default")]
    pub(crate) kind: String,
    #[serde(deserialize_with = "null_default")]
    pub(crate) collector: Collector,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Collector {
    #[serde(deserialize_with = "null_default")]
    pub(crate) enabled: bool,
    #[serde(deserialize_with = "null_default")]
    pub(crate) backend: String,
    #[serde(deserialize_with = "null_default")]
    pub(crate) command: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub(crate) exclude: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub(crate) respect_gitignore: bool,
    pub(crate) nix: Option<NixOptions>,
    pub(crate) certificates: Option<CertificateOptions>,
    pub(crate) import: Option<ImportOptions>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct NixOptions {
    #[serde(deserialize_with = "null_default")]
    pub(crate) roots: Vec<PathBuf>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct CertificateOptions {
    #[serde(deserialize_with = "null_default")]
    pub(crate) paths: Vec<PathBuf>,
    #[serde(deserialize_with = "null_default")]
    pub(crate) max_file_bytes: i64,
    #[serde(deserialize_with = "null_default")]
    pub(crate) include_identity: bool,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ImportOptions {
    #[serde(deserialize_with = "null_default")]
    pub(crate) path: PathBuf,
}

// YAML null has the same zero-value behavior as an omitted Go configuration field.
fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}
