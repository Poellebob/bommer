use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD};
use rustix::fs::{Dir, Mode, OFlags, openat};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use x509_parser::{
    parse_x509_certificate, public_key::PublicKey, signature_algorithm::RsaSsaPssParams,
    x509::AlgorithmIdentifier,
};

use crate::bom::document::Document;
use crate::model::{
    Backend, CollectionContext, CollectionOutcome, Coverage, Diagnostic, DiagnosticCode,
    Interrupted, Job, Target, path_text,
};

#[derive(Debug, Error)]
pub(crate) enum CertificateError {
    #[error("invalid certificate options")]
    Options,
    #[error("invalid certificate application target")]
    InvalidTarget { path: PathBuf },
    #[error(transparent)]
    Interrupted(#[from] Interrupted),
    #[error("certificate inventory I/O failed")]
    Io(#[from] io::Error),
}

const FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);

fn open_path(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }

    // Split raw bytes: Path::components would normalize '.' before no-follow checks.
    let parts: Vec<_> = path
        .as_os_str()
        .as_bytes()
        .split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty())
        .collect();
    let mut file = File::open("/")?;
    for (index, part) in parts.iter().enumerate() {
        if *part == b".." {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let flags = if index + 1 < parts.len() {
            FLAGS | OFlags::DIRECTORY
        } else {
            FLAGS
        };
        file = File::from(openat(
            &file,
            OsStr::from_bytes(part),
            flags,
            Mode::empty(),
        )?);
    }

    Ok(file)
}

fn open_code(error: &io::Error) -> DiagnosticCode {
    match error.raw_os_error() {
        Some(code)
            if code == rustix::io::Errno::LOOP.raw_os_error()
                || code == rustix::io::Errno::NOTDIR.raw_os_error() =>
        {
            DiagnosticCode::SymlinkRefused
        }
        Some(code) if code == rustix::io::Errno::NOENT.raw_os_error() => {
            DiagnosticCode::MissingPath
        }
        _ => DiagnosticCode::UnreadablePath,
    }
}

fn configured_paths(job: &Job, target: Option<&Path>) -> Result<Vec<PathBuf>, CertificateError> {
    let Backend::Certificates {
        paths,
        max_file_bytes,
        ..
    } = job.backend()
    else {
        return Err(CertificateError::Options);
    };
    if paths.is_empty() || *max_file_bytes == 0 || *max_file_bytes > 64 << 20 {
        return Err(CertificateError::Options);
    }

    paths
        .iter()
        .map(|path| {
            if path.is_absolute() {
                return Ok(path.clone());
            }
            let target = target.ok_or(CertificateError::Options)?;
            Ok(target.join(path))
        })
        .collect()
}

fn resolve_target(job: &Job) -> Result<Option<PathBuf>, CertificateError> {
    if job.scope().is_host() {
        Ok(None)
    } else {
        match job.target() {
            Target::Directory(path) => {
                if path.components().any(|part| part == Component::ParentDir) {
                    return Err(CertificateError::InvalidTarget { path: path.clone() });
                }

                // Make relative targets absolute without resolving any directory symlinks.
                let absolute = if path.is_absolute() {
                    path.clone()
                } else {
                    std::env::current_dir()?.join(path)
                };
                Ok(Some(absolute.components().collect::<PathBuf>()))
            }
            Target::NixClosure(path) => {
                // Only an explicitly declared Nix profile root may be resolved first.
                // Every subsequent certificate path is still opened with no-follow.
                let resolved = path.canonicalize()?;
                let valid = resolved
                    .to_str()
                    .and_then(|path| path.strip_prefix("/nix/store/"))
                    .is_some_and(|name| {
                        name.len() > 33
                            && !name.ends_with(".drv")
                            && name.as_bytes()[32] == b'-'
                            && name.as_bytes()[..32]
                                .iter()
                                .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(byte))
                            && name.as_bytes()[33..].iter().all(|byte| {
                                byte.is_ascii_alphanumeric() || b"+._?=-".contains(byte)
                            })
                    });
                let metadata = resolved.metadata()?;
                if !valid || (!metadata.is_file() && !metadata.is_dir()) {
                    return Err(CertificateError::InvalidTarget { path: path.clone() });
                }
                Ok(Some(resolved))
            }
            _ => Err(CertificateError::Options),
        }
    }
}

pub(crate) fn check(job: &Job) -> Result<(), CertificateError> {
    // Missing/refused paths are coverage diagnostics during collection, not fatal preflight.
    let target = resolve_target(job)?;
    configured_paths(job, target.as_deref()).map(|_| ())
}

struct Observation {
    der: Vec<u8>,
    sources: BTreeSet<PathBuf>,
}

struct Scan<'a> {
    context: &'a CollectionContext,
    max_file_bytes: u64,
    entry_limit: usize,
    depth_limit: usize,
    entries: usize,
    visited: BTreeSet<PathBuf>,
    observations: BTreeMap<String, Observation>,
    diagnostics: BTreeMap<(PathBuf, u8), Diagnostic>,
}

impl Scan<'_> {
    fn diagnostic(&mut self, code: DiagnosticCode, path: &Path) {
        if self.diagnostics.len() >= self.entry_limit {
            return;
        }
        self.diagnostics.insert(
            (path.to_path_buf(), code as u8),
            Diagnostic::new(code, Some(path.to_path_buf())),
        );
    }

    fn record(&mut self, der: &[u8], path: &Path, candidate: bool) {
        match parse_x509_certificate(der) {
            Ok(([], certificate)) if certificate.public_key().parsed().is_ok() => {
                let digest = hex::encode(Sha256::digest(der));
                self.observations
                    .entry(digest)
                    .or_insert_with(|| Observation {
                        der: der.to_vec(),
                        sources: BTreeSet::new(),
                    })
                    .sources
                    .insert(path.to_path_buf());
            }
            _ if candidate => self.diagnostic(DiagnosticCode::MalformedCertificate, path),
            _ => {}
        }
    }

    fn walk(&mut self, file: File, path: &Path, depth: usize) -> Result<(), CertificateError> {
        self.context.check()?;
        if self.entries >= self.entry_limit {
            self.diagnostic(DiagnosticCode::LimitExceeded, path);
            return Ok(());
        }
        self.entries += 1;
        if depth > self.depth_limit {
            self.diagnostic(DiagnosticCode::LimitExceeded, path);
            return Ok(());
        }
        if !self.visited.insert(path.to_path_buf()) {
            return Ok(());
        }

        let metadata = match file.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                self.diagnostic(DiagnosticCode::UnreadablePath, path);
                return Ok(());
            }
        };
        if metadata.is_dir() {
            let directory = match Dir::read_from(&file) {
                Ok(directory) => directory,
                Err(_) => {
                    self.diagnostic(DiagnosticCode::UnreadablePath, path);
                    return Ok(());
                }
            };
            for entry in directory {
                self.context.check()?;
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => {
                        self.diagnostic(DiagnosticCode::UnreadablePath, path);
                        break;
                    }
                };
                let name = entry.file_name().to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                if self.entries >= self.entry_limit {
                    self.diagnostic(DiagnosticCode::LimitExceeded, path);
                    break;
                }
                let name = OsString::from_vec(name.to_vec());
                let child_path = path.join(&name);
                match openat(&file, &name, FLAGS, Mode::empty()) {
                    Ok(descriptor) => self.walk(File::from(descriptor), &child_path, depth + 1)?,
                    Err(error) => {
                        self.entries += 1;
                        self.diagnostic(open_code(&error.into()), &child_path);
                    }
                }
            }

            return Ok(());
        }

        if !metadata.is_file() {
            self.diagnostic(DiagnosticCode::UnsupportedFile, path);
            return Ok(());
        }
        self.inspect_file(file, path, metadata.len())
    }

    fn inspect_file(
        &mut self,
        mut file: File,
        path: &Path,
        size: u64,
    ) -> Result<(), CertificateError> {
        let candidate = path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension| {
                ["pem", "crt", "cer", "der"].contains(&extension.to_ascii_lowercase().as_str())
            });
        if size > self.max_file_bytes {
            if candidate {
                self.diagnostic(DiagnosticCode::LimitExceeded, path);
            }
            return Ok(());
        }

        let mut data = Vec::new();
        let mut buffer = [0; 64 << 10];
        let mut reader = (&mut file).take(self.max_file_bytes + 1);
        loop {
            self.context.check()?;
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => data.extend_from_slice(&buffer[..count]),
                Err(_) => {
                    self.diagnostic(DiagnosticCode::UnreadablePath, path);
                    return Ok(());
                }
            }
        }
        if data.len() as u64 > self.max_file_bytes {
            if candidate {
                self.diagnostic(DiagnosticCode::LimitExceeded, path);
            }
            return Ok(());
        }

        let begin = b"-----BEGIN ";
        if data.windows(begin.len()).any(|window| window == begin) {
            let mut remaining = data.as_slice();
            while let Some(start) = remaining
                .windows(begin.len())
                .position(|window| window == begin)
            {
                self.context.check()?;
                remaining = &remaining[start..];
                let end = remaining[begin.len()..]
                    .windows(begin.len())
                    .position(|window| window == begin)
                    .map_or(remaining.len(), |index| index + begin.len());
                let block = &remaining[..end];
                remaining = &remaining[end..];
                if block.starts_with(b"-----BEGIN CERTIFICATE REQUEST-----")
                    || !block.starts_with(b"-----BEGIN CERTIFICATE")
                {
                    continue;
                }

                // Never decode non-certificate PEM blocks, including malformed private keys.
                let decoded = block
                    .strip_prefix(b"-----BEGIN CERTIFICATE-----")
                    .and_then(|body| {
                        let footer = b"-----END CERTIFICATE-----";
                        let end = body
                            .windows(footer.len())
                            .position(|window| window == footer)?;
                        STANDARD
                            .decode(
                                body[..end]
                                    .iter()
                                    .copied()
                                    .filter(|byte| !byte.is_ascii_whitespace())
                                    .collect::<Vec<_>>(),
                            )
                            .ok()
                    });
                match decoded {
                    Some(der) => self.record(&der, path, true),
                    None => self.diagnostic(DiagnosticCode::MalformedCertificate, path),
                }
            }
        } else if candidate || data.first() == Some(&0x30) {
            self.record(&data, path, candidate);
        }

        Ok(())
    }
}

fn algorithm(
    algorithms: &mut BTreeMap<String, Value>,
    role: &str,
    name: &str,
    properties: Value,
) -> String {
    let reference = format!(
        "algorithm:sha256:{}",
        hex::encode(Sha256::digest(format!("{role}:{name}")))
    );
    algorithms.insert(reference.clone(), json!({"type":"cryptographic-asset","bom-ref":reference,"name":name,"cryptoProperties":{"assetType":"algorithm","algorithmProperties":properties},"properties":[{"name":"bommer:certificate:algorithm-role","value":role}]}));
    reference
}

fn signature_name(identifier: &AlgorithmIdentifier<'_>) -> &'static str {
    match identifier.algorithm.to_id_string().as_str() {
        "1.2.840.113549.1.1.2" => "MD2-RSA",
        "1.2.840.113549.1.1.4" => "MD5-RSA",
        "1.2.840.113549.1.1.5" => "SHA1-RSA",
        "1.2.840.113549.1.1.11" => "SHA256-RSA",
        "1.2.840.113549.1.1.12" => "SHA384-RSA",
        "1.2.840.113549.1.1.13" => "SHA512-RSA",
        "1.2.840.10040.4.3" => "DSA-SHA1",
        "2.16.840.1.101.3.4.3.2" => "DSA-SHA256",
        "1.2.840.10045.4.1" => "ECDSA-SHA1",
        "1.2.840.10045.4.3.2" => "ECDSA-SHA256",
        "1.2.840.10045.4.3.3" => "ECDSA-SHA384",
        "1.2.840.10045.4.3.4" => "ECDSA-SHA512",
        "1.3.101.112" => "Ed25519",
        "1.2.840.113549.1.1.10" => {
            let Some(parameters) = identifier
                .parameters
                .as_ref()
                .and_then(|parameters| RsaSsaPssParams::try_from(parameters).ok())
            else {
                return "0";
            };
            let Ok(mask) = parameters.mask_gen_algorithm() else {
                return "0";
            };
            if parameters.trailer_field() != 1
                || mask.hash != *parameters.hash_algorithm_oid()
                || mask.mgf.to_id_string() != "1.2.840.113549.1.1.8"
            {
                return "0";
            }

            match (
                parameters.hash_algorithm_oid().to_id_string().as_str(),
                parameters.salt_length(),
            ) {
                ("2.16.840.1.101.3.4.2.1", 32) => "SHA256-RSAPSS",
                ("2.16.840.1.101.3.4.2.2", 48) => "SHA384-RSAPSS",
                ("2.16.840.1.101.3.4.2.3", 64) => "SHA512-RSAPSS",
                _ => "0",
            }
        }
        _ => "0",
    }
}

pub(crate) fn collect(
    job: &Job,
    context: &CollectionContext,
    output: &mut dyn Write,
) -> Result<CollectionOutcome, CertificateError> {
    collect_with_limits(job, context, output, 100_000, 128)
}

pub(crate) fn collect_with_limits(
    job: &Job,
    context: &CollectionContext,
    output: &mut dyn Write,
    entry_limit: usize,
    depth_limit: usize,
) -> Result<CollectionOutcome, CertificateError> {
    if entry_limit == 0 {
        return Err(CertificateError::Options);
    }
    context.check()?;
    let target = resolve_target(job)?;
    let paths = configured_paths(job, target.as_deref())?;
    let Backend::Certificates {
        max_file_bytes,
        include_identity,
        ..
    } = job.backend()
    else {
        return Err(CertificateError::Options);
    };

    let mut scan = Scan {
        context,
        max_file_bytes: *max_file_bytes,
        entry_limit,
        depth_limit,
        entries: 0,
        visited: BTreeSet::new(),
        observations: BTreeMap::new(),
        diagnostics: BTreeMap::new(),
    };
    for path in paths {
        context.check()?;
        if scan.entries >= scan.entry_limit {
            scan.diagnostic(DiagnosticCode::LimitExceeded, &path);
            break;
        }
        match open_path(&path) {
            Ok(file) => {
                let path = path.components().collect::<PathBuf>();
                scan.walk(file, &path, 0)?;
            }
            Err(error) => {
                scan.entries += 1;
                scan.diagnostic(open_code(&error), &path);
            }
        }
    }

    let mut components = BTreeMap::new();
    let mut algorithms = BTreeMap::new();
    let mut sources = BTreeMap::new();
    for (digest, observation) in &scan.observations {
        context.check()?;
        let (_, certificate) =
            parse_x509_certificate(&observation.der).map_err(|_| CertificateError::Options)?;

        let key = certificate.public_key();
        let mut key_properties = json!({"primitive":"unknown"});
        let key_name = match key.parsed() {
            Ok(PublicKey::RSA(rsa)) => {
                let modulus = rsa
                    .modulus
                    .iter()
                    .position(|byte| *byte != 0)
                    .map_or(&[][..], |start| &rsa.modulus[start..]);
                let bits = modulus
                    .first()
                    .map_or(0, |byte| modulus.len() * 8 - byte.leading_zeros() as usize);
                key_properties["parameterSetIdentifier"] = bits.to_string().into();
                format!("RSA-{bits}")
            }
            Ok(PublicKey::EC(_)) => {
                let oid = key
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|parameters| parameters.as_oid().ok())
                    .map(|oid| oid.to_id_string());
                let curve = match oid.as_deref() {
                    Some("1.2.840.10045.3.1.7") => "P-256",
                    Some("1.3.132.0.34") => "P-384",
                    Some("1.3.132.0.35") => "P-521",
                    Some("1.3.132.0.33") => "P-224",
                    _ => "unknown",
                };
                key_properties = json!({"primitive":"signature","curve":curve});
                format!("ECDSA-{curve}")
            }
            _ if key.algorithm.algorithm.to_id_string() == "1.3.101.112" => {
                key_properties = json!({"primitive":"signature","curve":"Ed25519"});
                "Ed25519".into()
            }
            Ok(PublicKey::DSA(_)) => "DSA".into(),
            _ => "0".into(),
        };
        let key_reference = algorithm(&mut algorithms, "public-key", &key_name, key_properties);
        let signature_reference = algorithm(
            &mut algorithms,
            "signature",
            signature_name(&certificate.signature_algorithm),
            json!({"primitive":"signature"}),
        );

        let mut certificate_properties = json!({"certificateFormat":"X.509","notValidBefore":certificate.validity().not_before.to_datetime().format(&Rfc3339).map_err(|_| CertificateError::Options)?,"notValidAfter":certificate.validity().not_after.to_datetime().format(&Rfc3339).map_err(|_| CertificateError::Options)?,"signatureAlgorithmRef":signature_reference});
        if *include_identity {
            certificate_properties["subjectName"] = certificate.subject().to_string().into();
            certificate_properties["issuerName"] = certificate.issuer().to_string().into();
        }

        let reference = format!("certificate:sha256:{digest}");
        let mut properties = vec![
            json!({"name":"bommer:certificate:sha256","value":digest}),
            json!({"name":"bommer:certificate:public-key-algorithm-ref","value":key_reference}),
            json!({"name":"bommer:certificate:expired","value":(OffsetDateTime::now_utc().unix_timestamp() > certificate.validity().not_after.timestamp()).to_string()}),
            json!({"name":"bommer:certificate:trust-evaluated","value":"false"}),
        ];
        let source_paths: Vec<_> = observation
            .sources
            .iter()
            .map(|path| path_text(path))
            .collect();
        for path in &source_paths {
            properties.push(json!({"name":"bommer:certificate:source","value":path}));
        }
        sources.insert(reference.clone(), source_paths);
        components.insert(reference.clone(), json!({"type":"cryptographic-asset","bom-ref":reference,"name":format!("X.509 SHA-256 {digest}"),"cryptoProperties":{"assetType":"certificate","certificateProperties":certificate_properties},"properties":properties}));
    }
    components.extend(algorithms);

    context.check()?;
    Document::new(components.into_values().collect(), vec![], vec![]).write(output)?;

    Ok(CollectionOutcome::observed(
        scan.observations.len(),
        Coverage::DeclaredScope,
        scan.diagnostics.into_values().collect(),
        json!({"sources":sources,"trust_evaluated":false}),
        Some("certificates/1".into()),
    )
    .with_target(target.as_deref().map(path_text).unwrap_or_default()))
}
