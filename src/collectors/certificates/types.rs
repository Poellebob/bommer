use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde_json::Value;

use crate::bom::document::Document;
use crate::collection::outcome::Diagnostic;

pub(in crate::collectors::certificates) struct Observation {
    pub(in crate::collectors::certificates) der: Vec<u8>,
    pub(in crate::collectors::certificates) sources: BTreeSet<PathBuf>,
}

pub(in crate::collectors::certificates) struct Discovery {
    pub(in crate::collectors::certificates) target: Option<PathBuf>,
    pub(in crate::collectors::certificates) observations: BTreeMap<String, Observation>,
    pub(in crate::collectors::certificates) diagnostics: Vec<Diagnostic>,
}

pub(in crate::collectors::certificates) struct Assets {
    pub(in crate::collectors::certificates) document: Document,
    pub(in crate::collectors::certificates) evidence: Value,
}
