use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use thiserror::Error;

use crate::model::{
    Backend, CollectionContext, CollectionOutcome, InventoryKind, Job, Scope, Target,
};
use crate::process::{Process, ProcessError};

#[derive(Debug, Error)]
pub(crate) enum ExternalError {
    #[error("external collector process failed")]
    Process(#[from] ProcessError),
    #[error("external collector process failed")]
    Execution {
        #[source]
        source: ProcessError,
        exclusions: Vec<String>,
        target: String,
    },
    #[error("backend or target is unsupported by external collectors")]
    UnsupportedTarget,
    #[error("Syft cannot inventory a NixOS host closure")]
    NixosHost,
    #[error("cannot inspect target {path:?}")]
    TargetIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("target is not a directory: {path:?}")]
    NotDirectory { path: PathBuf },
}

pub(crate) fn check(job: &Job) -> Result<(), ExternalError> {
    let executable = match job.backend() {
        Backend::Hbom => OsStr::new("hbom"),
        Backend::Syft {
            respect_gitignore, ..
        } => {
            if job.scope().is_host() && std::path::Path::new("/run/current-system").exists() {
                return Err(ExternalError::NixosHost);
            }
            if *respect_gitignore {
                Process::find_executable(OsStr::new("git"))?;
            }
            OsStr::new("syft")
        }
        Backend::Command(command) => command.executable(),
        _ => return Err(ExternalError::UnsupportedTarget),
    };
    Process::find_executable(executable)?;

    if !job.scope().is_host()
        && let Target::Directory(path) = job.target()
    {
        let metadata = std::fs::metadata(path).map_err(|source| ExternalError::TargetIo {
            path: path.clone(),
            source,
        })?;
        if !metadata.is_dir() {
            return Err(ExternalError::NotDirectory { path: path.clone() });
        }
    }

    Ok(())
}

pub(crate) fn collect(
    job: &Job,
    context: &CollectionContext,
    output: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<CollectionOutcome, ExternalError> {
    check(job)?;
    let prepared = prepare_command(job, context)?;

    Process::stream(
        &prepared.executable,
        &prepared.arguments,
        context.deadline(),
        context.cancelled(),
        output,
        stderr,
    )
    .map_err(|source| ExternalError::Execution {
        source,
        exclusions: prepared.exclusions.clone(),
        target: prepared.target.clone(),
    })?;

    Ok(CollectionOutcome::external()
        .with_exclusions(prepared.exclusions)
        .with_target(prepared.target))
}

struct Prepared {
    executable: OsString,
    arguments: Vec<OsString>,
    exclusions: Vec<String>,
    target: String,
}

#[cfg(test)]
pub(crate) fn prepare(
    job: &Job,
    context: &CollectionContext,
) -> Result<(OsString, Vec<OsString>, Vec<String>, String), ExternalError> {
    let prepared = prepare_command(job, context)?;
    Ok((
        prepared.executable,
        prepared.arguments,
        prepared.exclusions,
        prepared.target,
    ))
}

fn prepare_command(job: &Job, context: &CollectionContext) -> Result<Prepared, ExternalError> {
    let target = match job.target() {
        Target::Host if matches!(job.kind(), InventoryKind::Sbom) => OsString::from("dir:/"),
        Target::Directory(path) | Target::NixClosure(path) => path.as_os_str().to_owned(),
        target => OsString::from(target.display()),
    };
    let (executable, mut arguments) = command(job, &target)?;

    let mut patterns: Vec<OsString> = match job.backend() {
        Backend::Syft { exclusions, .. } => exclusions.iter().map(OsString::from).collect(),
        _ => Vec::new(),
    };
    if let Backend::Syft {
        respect_gitignore: true,
        ..
    } = job.backend()
    {
        let Target::Directory(path) = job.target() else {
            return Err(ExternalError::UnsupportedTarget);
        };
        let git_arguments = [
            OsString::from("-C"),
            path.as_os_str().to_owned(),
            OsString::from("ls-files"),
            OsString::from("--others"),
            OsString::from("--ignored"),
            OsString::from("--exclude-standard"),
            OsString::from("--directory"),
            OsString::from("-z"),
        ];
        let ignored = Process::capture(
            OsStr::new("git"),
            &git_arguments,
            context.deadline(),
            context.cancelled(),
            64 << 20,
            1 << 20,
        )?;

        patterns.extend([OsString::from("./.git"), OsString::from("./.git/**")]);
        for path in ignored
            .stdout()
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
        {
            let directory = path.ends_with(b"/");
            let path = if directory {
                &path[..path.len() - 1]
            } else {
                path
            };
            let mut pattern = b"./".to_vec();
            for byte in path {
                if b"\\*?[]{}".contains(byte) {
                    pattern.push(b'\\');
                }
                pattern.push(*byte);
            }
            if directory {
                pattern.extend_from_slice(b"/**");
            }
            patterns.push(OsString::from_vec(pattern));
        }
    }

    let mut exclusions = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for pattern in patterns {
        if seen.insert(pattern.clone()) {
            exclusions.push(crate::model::path_text(std::path::Path::new(&pattern)));
            arguments.extend([OsString::from("--exclude"), pattern]);
        }
    }

    Ok(Prepared {
        executable,
        arguments,
        exclusions,
        target: crate::model::path_text(std::path::Path::new(&target)),
    })
}

fn command(
    job: &Job,
    effective_target: &OsStr,
) -> Result<(OsString, Vec<OsString>), ExternalError> {
    match job.backend() {
        Backend::Hbom => Ok(("hbom".into(), vec!["-p".into()])),
        Backend::Syft { .. } => {
            let target = match job.target() {
                Target::Host => OsString::from("dir:/"),
                Target::Directory(path) => {
                    let mut value = OsString::from("dir:");
                    value.push(path);
                    value
                }
                Target::RegistryImage(image) => OsString::from(format!("registry:{image}")),
                _ => return Err(ExternalError::UnsupportedTarget),
            };
            let mut arguments = vec!["scan".into(), target, "-o".into(), "cyclonedx-json".into()];
            if let Scope::Application { name, version } = job.scope() {
                arguments.extend(["--source-name".into(), name.as_str().into()]);
                if let Some(version) = version {
                    arguments.extend(["--source-version".into(), version.into()]);
                }
            }

            Ok(("syft".into(), arguments))
        }
        Backend::Command(spec) => {
            let arguments = spec
                .arguments()
                .iter()
                .map(|argument| {
                    let mut replaced = Vec::new();
                    let mut remaining = argument.as_bytes();
                    while let Some(index) =
                        remaining.windows(8).position(|part| part == b"{target}")
                    {
                        replaced.extend_from_slice(&remaining[..index]);
                        replaced.extend_from_slice(effective_target.as_bytes());
                        remaining = &remaining[index + 8..];
                    }
                    replaced.extend_from_slice(remaining);
                    OsString::from_vec(replaced)
                })
                .collect();
            Ok((spec.executable().to_owned(), arguments))
        }
        _ => Err(ExternalError::UnsupportedTarget),
    }
}
