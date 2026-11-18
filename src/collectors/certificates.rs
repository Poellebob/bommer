#[derive(Debug)]
pub(crate) enum CertificateError {
    Cancelled,
    Output(std::io::Error),
}

// Individual path and certificate failures become model diagnostics, not fatal errors.
