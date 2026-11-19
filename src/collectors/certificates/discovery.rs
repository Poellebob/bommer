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
    max_file_bytes: u64,
    entry_limit: usize,
    depth_limit: usize,
    entries: usize,
    visited: BTreeSet<PathBuf>,
    observations: BTreeMap<String, Observation>,
    diagnostics: BTreeMap<(PathBuf, u8), Diagnostic>,
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

    Ok(Discovery {
        target,
        observations: scan.observations,
        diagnostics: scan.diagnostics.into_values().collect(),
    })
}
