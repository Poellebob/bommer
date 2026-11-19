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
