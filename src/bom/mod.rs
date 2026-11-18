mod decode;
pub(crate) mod document;
mod schemas;

#[derive(Debug)]
pub(crate) struct DocumentSummary {
    version: document::SpecVersion,
    component_count: usize,
}

#[derive(Debug)]
pub(crate) enum ValidationError {
    Decode(decode::DecodeError),
    UnsupportedSpecVersion {
        version: String,
    },
    SchemaViolation {
        instance_path: String,
        schema_path: String,
    },
    ExternalResourceRefused {
        uri: String,
    },
    MissingDocumentVersion,
    EmptyExternalInventory,
}
