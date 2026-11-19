mod assets;
mod discovery;
pub(crate) mod error;

use std::io::Write;

use self::error::CertificateError;
use crate::collection::context::CollectionContext;
use crate::collection::outcome::{CollectionOutcome, Coverage, ExecutionScope};
use crate::job::{Backend, Job};
use crate::path_encoding::path_text;

pub(crate) fn check(job: &Job) -> Result<(), CertificateError> {
    // Missing/refused paths are coverage diagnostics during collection, not fatal preflight.
    let target = discovery::resolve_target(job)?;
    discovery::configured_paths(job, target.as_deref()).map(|_| ())
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
    let discovery = discovery::discover(job, context, entry_limit, depth_limit)?;
    let Backend::Certificates {
        include_identity, ..
    } = &job.backend
    else {
        return Err(CertificateError::Options);
    };
    let assets = assets::build(&discovery.observations, *include_identity, context)?;

    context.check()?;
    assets.document.write(output)?;

    Ok(CollectionOutcome {
        scope: ExecutionScope {
            target: Some(
                discovery
                    .target
                    .as_deref()
                    .map(path_text)
                    .unwrap_or_default(),
            ),
            exclusions: None,
        },
        ..CollectionOutcome::observed(
            discovery.observations.len(),
            Coverage::DeclaredScope,
            discovery.diagnostics,
            assets.evidence,
            Some("certificates/1".into()),
        )
    })
}
