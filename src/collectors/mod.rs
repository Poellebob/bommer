mod certificates;
mod external;
mod import;
mod nix;

#[derive(Debug)]
pub(crate) enum CollectionError {
    External(external::ExternalError),
    Nix(nix::NixError),
    Certificates(certificates::CertificateError),
    Import(import::ImportError),
}

// Dispatch belongs here; shared collector contracts belong in crate::model.
