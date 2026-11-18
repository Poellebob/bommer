#[derive(Debug)]
pub(crate) enum ImportError {
    Read {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    PrivateMaterial,
    Cancelled,
    Output(std::io::Error),
}
