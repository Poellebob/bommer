#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DecodeError {
    InvalidJson { line: usize, column: usize },
    DuplicateKey { key: String },
    MultipleDocuments,
    DepthExceeded { limit: usize },
}
