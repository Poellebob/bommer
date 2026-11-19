use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, flock};
use sha2::{Digest, Sha256};
use tempfile::{NamedTempFile, TempDir};
use time::OffsetDateTime;

use crate::job::Job;
use crate::manifest::{ArtifactRecord, Manifest};

#[derive(Debug, thiserror::Error)]
pub(crate) enum OutputError {
    #[error("another scan holds the output lock")]
    Locked,
    #[error("output I/O failed")]
    Io(#[from] io::Error),

    #[error("cannot serialize manifest")]
    Serialize(#[from] serde_json::Error),
    #[error("cannot format timestamp")]
    Timestamp(#[from] time::error::Format),
}

pub(crate) struct RunOutput {
    _lock: File,
    directory: PathBuf,
}

impl RunOutput {
    pub(crate) fn create(root: &Path) -> Result<Self, OutputError> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)?;

        // Refuse a leaf symlink instead of locking an attacker-selected file.
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(root.join(".lock"))?;
        match flock(&lock, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(rustix::io::Errno::WOULDBLOCK) => return Err(OutputError::Locked),
            Err(error) => return Err(OutputError::Io(error.into())),
        }

        let prefix = OffsetDateTime::now_utc().format(time::macros::format_description!(
            "[year][month][day]T[hour][minute][second]Z-"
        ))?;
        let directory = tempfile::Builder::new().prefix(&prefix).tempdir_in(root)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;

        // Keep even an interrupted run for inspection. Individual temporary artifacts are RAII-owned.
        let directory = TempDir::keep(directory);

        Ok(Self {
            _lock: lock,
            directory,
        })
    }

    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn candidate(&self) -> Result<NamedTempFile, OutputError> {
        Ok(tempfile::Builder::new()
            .prefix(".bom-")
            .tempfile_in(&self.directory)?)
    }

    pub(crate) fn log(&self, job: &Job) -> Result<File, OutputError> {
        Ok(OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.directory.join(format!("{}.stderr.log", job.stem())))?)
    }

    pub(crate) fn publish(
        &self,
        job: &Job,
        mut candidate: NamedTempFile,
        bytes: &[u8],
    ) -> Result<ArtifactRecord, OutputError> {
        candidate.flush()?;
        candidate.as_file().sync_all()?;

        let name = format!("{}.cdx.json", job.stem());
        let sha256 = hex::encode(Sha256::digest(bytes));
        candidate
            .persist_noclobber(self.directory.join(&name))
            .map_err(|error| error.error)?;

        Ok(ArtifactRecord { name, sha256 })
    }

    pub(crate) fn checkpoint(&self, manifest: &Manifest) -> Result<(), OutputError> {
        let mut temporary = tempfile::Builder::new()
            .prefix(".manifest-")
            .tempfile_in(&self.directory)?;
        serde_json::to_writer_pretty(&mut temporary, manifest)?;
        temporary.write_all(b"\n")?;
        temporary.as_file().sync_all()?;

        temporary
            .persist(self.directory.join("manifest.json"))
            .map_err(|error| error.error)?;
        File::open(&self.directory)?.sync_all()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;

    use rustix::fs::{FlockOperation, flock};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    use crate::collection::failure::{Failure, FailureKind};
    use crate::collection::outcome::ExecutionScope;
    use crate::job::{Backend, InventoryKind, Job, Name, Scope, Target};
    use crate::manifest::{JobResult, Manifest};
    use crate::output::{OutputError, RunOutput};

    fn job() -> Job {
        Job::new(
            Scope::Host,
            Some(Name::new("pending".into()).unwrap()),
            InventoryKind::Sbom,
            Target::Directory("/".into()),
            Backend::Command(crate::process::CommandSpec::new("unused".into(), vec![]).unwrap()),
        )
        .unwrap()
    }

    fn entries(directory: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn held_output_lock_returns_typed_error_without_creating_a_run() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("output");
        fs::create_dir(&root).unwrap();
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(root.join(".lock"))
            .unwrap();
        flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();

        assert!(matches!(RunOutput::create(&root), Err(OutputError::Locked)));
        assert_eq!(entries(&root), [".lock"]);
        drop(lock);

        let output = RunOutput::create(&root).unwrap();
        output.checkpoint(&Manifest::new()).unwrap();
        let document: Value =
            serde_json::from_slice(&fs::read(output.directory().join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(document["results"], json!([]));
    }

    #[test]
    fn checkpoints_replace_complete_manifests_and_unpublished_candidates_are_cleaned_up() {
        let temporary = tempfile::tempdir().unwrap();
        let output = RunOutput::create(&temporary.path().join("output")).unwrap();
        let mut checkpoint = Manifest::new();
        output.checkpoint(&checkpoint).unwrap();
        let initial = fs::read(output.directory().join("manifest.json")).unwrap();
        let mut old_reader = File::open(output.directory().join("manifest.json")).unwrap();
        let candidate = output.candidate().unwrap();
        let candidate_path = candidate.path().to_owned();
        assert!(candidate_path.exists());
        assert!(
            !output
                .directory()
                .join("host.pending.sbom.cdx.json")
                .exists()
        );
        drop(candidate);
        assert!(!candidate_path.exists());

        let mut result = JobResult::pending(&job()).unwrap();
        result.fail(
            &"test-owned failure",
            Failure::new(FailureKind::Collection),
            ExecutionScope::default(),
        );
        result.finish().unwrap();
        checkpoint.record(result);
        output.checkpoint(&checkpoint).unwrap();

        let mut old_bytes = Vec::new();
        old_reader.read_to_end(&mut old_bytes).unwrap();
        // An already-open reader sees the old, complete inode, not an in-place rewrite.
        assert_eq!(old_bytes, initial);
        let latest: Value =
            serde_json::from_slice(&fs::read(output.directory().join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&initial).unwrap()["results"],
            json!([])
        );
        assert_eq!(latest["version"], 2);
        assert_eq!(latest["results"].as_array().unwrap().len(), 1);
        assert_eq!(latest["results"][0]["status"], "failed");
        assert_eq!(
            latest["results"][0]["failure"],
            json!({"kind": "collection"})
        );
        assert_eq!(entries(output.directory()), ["manifest.json"]);
        assert_eq!(
            fs::metadata(output.directory().join("manifest.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }

    #[test]
    fn publication_hashes_bytes_and_refuses_to_clobber_artifacts_or_logs() {
        let temporary = tempfile::tempdir().unwrap();
        let output = RunOutput::create(temporary.path()).unwrap();
        let job = job();
        let bytes = b"first artifact";
        let mut candidate = output.candidate().unwrap();
        candidate.write_all(bytes).unwrap();
        let artifact = output.publish(&job, candidate, bytes).unwrap();
        assert_eq!(artifact.name, "host.pending.sbom.cdx.json");
        assert_eq!(artifact.sha256, hex::encode(Sha256::digest(bytes)));
        let mut candidate = output.candidate().unwrap();
        candidate.write_all(b"replacement").unwrap();
        let path = candidate.path().to_owned();
        assert!(matches!(
            output.publish(&job, candidate, b"replacement"),
            Err(OutputError::Io(_))
        ));
        assert!(!path.exists());
        assert_eq!(
            fs::read(output.directory().join(&artifact.name)).unwrap(),
            bytes
        );
        output
            .log(&job)
            .unwrap()
            .write_all(b"original log")
            .unwrap();
        assert!(matches!(output.log(&job), Err(OutputError::Io(_))));
        assert_eq!(
            fs::read(output.directory().join("host.pending.sbom.stderr.log")).unwrap(),
            b"original log"
        );
    }

    #[test]
    fn lock_symlink_is_refused_without_touching_its_target() {
        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target");
        fs::write(&target, b"untouched").unwrap();
        symlink(&target, temporary.path().join(".lock")).unwrap();
        assert!(matches!(
            RunOutput::create(temporary.path()),
            Err(OutputError::Io(_))
        ));
        assert_eq!(fs::read(target).unwrap(), b"untouched");
        assert_eq!(entries(temporary.path()), [".lock", "target"]);
    }
}
