use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD};
use rustix::fs::{Dir, Mode, OFlags, openat};
use sha2::{Digest, Sha256};
use x509_parser::parse_x509_certificate;

use crate::collection::context::CollectionContext;
use crate::collection::outcome::{Diagnostic, DiagnosticCode};
use crate::collectors::certificates::error::CertificateError;
use crate::collectors::certificates::types::{Discovery, Observation};
use crate::job::{Backend, Job, Target};

struct Scan<'a> {
    context: &'a CollectionContext,
    maximum_file_bytes: u64,
    entry_limit: usize,
    depth_limit: usize,
    entries_scanned: usize,
    visited_paths: BTreeSet<PathBuf>,
    observations: BTreeMap<String, Observation>,
    diagnostics: BTreeMap<(PathBuf, u8), Diagnostic>,
}

const SAFE_OPEN_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);

fn open_path(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }

    // Split raw bytes: Path::components would normalize '.' before no-follow checks.
    let path_segments: Vec<_> = path
        .as_os_str()
        .as_bytes()
        .split(|byte| *byte == b'/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let mut file = File::open("/")?;
    for (index, segment) in path_segments.iter().enumerate() {
        if *segment == b".." {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let flags = if index + 1 < path_segments.len() {
            SAFE_OPEN_FLAGS | OFlags::DIRECTORY
        } else {
            SAFE_OPEN_FLAGS
        };
        file = File::from(openat(
            &file,
            OsStr::from_bytes(segment),
            flags,
            Mode::empty(),
        )?);
    }

    Ok(file)
}

fn open_error_code(error: &io::Error) -> DiagnosticCode {
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

pub(in crate::collectors::certificates) fn configured_paths(
    job: &Job,
    target: Option<&Path>,
) -> Result<Vec<PathBuf>, CertificateError> {
    let Backend::Certificates {
        paths,
        max_file_bytes,
        ..
    } = &job.backend
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

pub(in crate::collectors::certificates) fn resolve_target(
    job: &Job,
) -> Result<Option<PathBuf>, CertificateError> {
    if job.scope.is_host() {
        Ok(None)
    } else {
        match &job.target {
            Target::Directory(path) => {
                if path
                    .components()
                    .any(|component| component == Component::ParentDir)
                {
                    return Err(CertificateError::InvalidTarget { path: path.clone() });
                }

                // Make relative targets absolute without resolving any directory symlinks.
                let absolute_path = if path.is_absolute() {
                    path.clone()
                } else {
                    std::env::current_dir()?.join(path)
                };
                Ok(Some(absolute_path.components().collect::<PathBuf>()))
            }
            Target::NixClosure(path) => {
                // Only an explicitly declared Nix profile root may be resolved first.
                // Every subsequent certificate path is still opened with no-follow.
                let resolved_path = path.canonicalize()?;
                let is_store_output = resolved_path
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
                let metadata = resolved_path.metadata()?;
                if !is_store_output || (!metadata.is_file() && !metadata.is_dir()) {
                    return Err(CertificateError::InvalidTarget { path: path.clone() });
                }
                Ok(Some(resolved_path))
            }
            _ => Err(CertificateError::Options),
        }
    }
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

    fn record(&mut self, der: &[u8], path: &Path, report_malformed: bool) {
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
            _ if report_malformed => self.diagnostic(DiagnosticCode::MalformedCertificate, path),
            _ => {}
        }
    }

    fn walk(&mut self, file: File, path: &Path, depth: usize) -> Result<(), CertificateError> {
        self.context.check()?;
        if self.entries_scanned >= self.entry_limit {
            self.diagnostic(DiagnosticCode::LimitExceeded, path);
            return Ok(());
        }
        self.entries_scanned += 1;
        if depth > self.depth_limit {
            self.diagnostic(DiagnosticCode::LimitExceeded, path);
            return Ok(());
        }
        if !self.visited_paths.insert(path.to_path_buf()) {
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
                if self.entries_scanned >= self.entry_limit {
                    self.diagnostic(DiagnosticCode::LimitExceeded, path);
                    break;
                }
                let name = OsString::from_vec(name.to_vec());
                let child_path = path.join(&name);
                match openat(&file, &name, SAFE_OPEN_FLAGS, Mode::empty()) {
                    Ok(descriptor) => self.walk(File::from(descriptor), &child_path, depth + 1)?,
                    Err(error) => {
                        self.entries_scanned += 1;
                        self.diagnostic(open_error_code(&error.into()), &child_path);
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
        file_size: u64,
    ) -> Result<(), CertificateError> {
        let has_certificate_extension =
            path.extension()
                .and_then(OsStr::to_str)
                .is_some_and(|extension| {
                    ["pem", "crt", "cer", "der"].contains(&extension.to_ascii_lowercase().as_str())
                });
        if file_size > self.maximum_file_bytes {
            if has_certificate_extension {
                self.diagnostic(DiagnosticCode::LimitExceeded, path);
            }
            return Ok(());
        }

        let mut data = Vec::new();
        let mut buffer = [0; 64 << 10];
        let mut reader = (&mut file).take(self.maximum_file_bytes + 1);
        loop {
            self.context.check()?;
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(bytes_read) => data.extend_from_slice(&buffer[..bytes_read]),
                Err(_) => {
                    self.diagnostic(DiagnosticCode::UnreadablePath, path);
                    return Ok(());
                }
            }
        }

        if data.len() as u64 > self.maximum_file_bytes {
            if has_certificate_extension {
                self.diagnostic(DiagnosticCode::LimitExceeded, path);
            }
            return Ok(());
        }

        let pem_begin_marker = b"-----BEGIN ";
        if data
            .windows(pem_begin_marker.len())
            .any(|window| window == pem_begin_marker)
        {
            let mut remaining_bytes = data.as_slice();
            while let Some(block_start) = remaining_bytes
                .windows(pem_begin_marker.len())
                .position(|window| window == pem_begin_marker)
            {
                self.context.check()?;
                remaining_bytes = &remaining_bytes[block_start..];
                let block_end = remaining_bytes[pem_begin_marker.len()..]
                    .windows(pem_begin_marker.len())
                    .position(|window| window == pem_begin_marker)
                    .map_or(remaining_bytes.len(), |index| {
                        index + pem_begin_marker.len()
                    });
                let block = &remaining_bytes[..block_end];
                remaining_bytes = &remaining_bytes[block_end..];
                if block.starts_with(b"-----BEGIN CERTIFICATE REQUEST-----")
                    || !block.starts_with(b"-----BEGIN CERTIFICATE")
                {
                    continue;
                }

                // Never decode non-certificate PEM blocks, including malformed private keys.
                let decoded_certificate = block
                    .strip_prefix(b"-----BEGIN CERTIFICATE-----")
                    .and_then(|body| {
                        let pem_end_marker = b"-----END CERTIFICATE-----";
                        let body_end = body
                            .windows(pem_end_marker.len())
                            .position(|window| window == pem_end_marker)?;
                        STANDARD
                            .decode(
                                body[..body_end]
                                    .iter()
                                    .copied()
                                    .filter(|byte| !byte.is_ascii_whitespace())
                                    .collect::<Vec<_>>(),
                            )
                            .ok()
                    });
                match decoded_certificate {
                    Some(der) => self.record(&der, path, true),
                    None => self.diagnostic(DiagnosticCode::MalformedCertificate, path),
                }
            }
        } else if has_certificate_extension || data.first() == Some(&0x30) {
            self.record(&data, path, has_certificate_extension);
        }

        Ok(())
    }
}

pub(in crate::collectors::certificates) fn discover(
    job: &Job,
    context: &CollectionContext,
    entry_limit: usize,
    depth_limit: usize,
) -> Result<Discovery, CertificateError> {
    if entry_limit == 0 {
        return Err(CertificateError::Options);
    }
    context.check()?;
    let target = resolve_target(job)?;
    let paths = configured_paths(job, target.as_deref())?;
    let Backend::Certificates { max_file_bytes, .. } = &job.backend else {
        return Err(CertificateError::Options);
    };

    let mut scan = Scan {
        context,
        maximum_file_bytes: *max_file_bytes,
        entry_limit,
        depth_limit,
        entries_scanned: 0,
        visited_paths: BTreeSet::new(),
        observations: BTreeMap::new(),
        diagnostics: BTreeMap::new(),
    };
    for path in paths {
        context.check()?;
        if scan.entries_scanned >= scan.entry_limit {
            scan.diagnostic(DiagnosticCode::LimitExceeded, &path);
            break;
        }
        match open_path(&path) {
            Ok(file) => {
                let path = path.components().collect::<PathBuf>();
                scan.walk(file, &path, 0)?;
            }
            Err(error) => {
                scan.entries_scanned += 1;
                scan.diagnostic(open_error_code(&error), &path);
            }
        }
    }

    Ok(Discovery {
        target,
        observations: scan.observations,
        diagnostics: scan.diagnostics.into_values().collect(),
    })
}
