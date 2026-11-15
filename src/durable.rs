//! Filesystem primitives shared by system transactions. An acknowledgement is
//! durable only after both the file and its containing directory are synced.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::Path,
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileMetadata {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl FileMetadata {
    pub fn private() -> Self {
        Self {
            mode: 0o600,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        }
    }

    pub fn from_fs(value: &fs::Metadata) -> Self {
        Self {
            mode: value.mode() & 0o777,
            uid: value.uid(),
            gid: value.gid(),
        }
    }
}

pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn directory(path: &Path) -> Result<()> {
    let created: Vec<_> = path
        .ancestors()
        .take_while(|p| !p.exists())
        .map(Path::to_path_buf)
        .collect();
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_dir() && info.uid() == unsafe { libc::geteuid() } && info.mode() & 0o022 == 0,
        "FORBIDDEN: unsafe transaction directory"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    sync_directory(path)?;
    for directory in created {
        if let Some(parent) = directory.parent() {
            sync_directory(parent)?;
        }
    }
    Ok(())
}

/// Refuse links and special files before reading any transaction-controlled bytes.
pub fn read(path: &Path, limit: u64) -> Result<(Vec<u8>, FileMetadata)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let info = file.metadata()?;
    ensure!(
        info.is_file() && info.nlink() == 1 && info.len() <= limit,
        "CONFLICT: unsafe or oversized transaction file"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "RESOURCE_EXHAUSTED: transaction file"
    );
    Ok((bytes, FileMetadata::from_fs(&info)))
}

pub fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all().map_err(Into::into)
}

pub fn write(path: &Path, bytes: &[u8], metadata: FileMetadata) -> Result<()> {
    write_with_policy(path, bytes, metadata, false)
}

/// Publish a new snapshot/upload without ever replacing a concurrently created
/// destination. Both links live in the destination filesystem.
pub fn publish_new(path: &Path, bytes: &[u8], metadata: FileMetadata) -> Result<()> {
    write_with_policy(path, bytes, metadata, true)
}

fn write_with_policy(
    path: &Path,
    bytes: &[u8],
    metadata: FileMetadata,
    create_only: bool,
) -> Result<()> {
    let parent = path
        .parent()
        .context("transaction file requires a directory")?;
    ensure!(
        fs::symlink_metadata(parent)?.is_dir(),
        "FORBIDDEN: symlink transaction directory"
    );
    if let Ok(info) = fs::symlink_metadata(path) {
        ensure!(
            info.is_file() && info.nlink() == 1,
            "CONFLICT: refusing to replace non-regular file"
        );
    }
    let temporary = parent.join(format!(".yofc-{}.new", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(bytes)?;
        let info = file.metadata()?;
        if info.uid() != metadata.uid || info.gid() != metadata.gid {
            ensure!(
                unsafe { libc::fchown(file.as_raw_fd(), metadata.uid, metadata.gid) } == 0,
                "FORBIDDEN: cannot preserve transaction file ownership"
            );
        }
        file.set_permissions(fs::Permissions::from_mode(metadata.mode & 0o777))?;
        file.sync_all()?;
        if create_only {
            fs::hard_link(&temporary, path)?;
            fs::remove_file(&temporary)?;
        } else {
            fs::rename(&temporary, path)?;
        }
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn json(path: &Path, value: &impl Serialize) -> Result<()> {
    write(path, &serde_json::to_vec(value)?, FileMetadata::private())
}

pub fn remove(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(info) => {
            ensure!(
                info.is_file() && info.nlink() == 1,
                "CONFLICT: unsafe removal target"
            );
            fs::remove_file(path)?;
            sync_directory(path.parent().context("removal directory")?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Atomically retain an existing file at a new name without replacing anything.
/// Cross-filesystem movement is intentionally refused: no copy/unlink crash gap.
pub fn move_new(source: &Path, destination: &Path) -> Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let source_parent = source.parent().context("retained source parent")?;
    let destination_parent = destination
        .parent()
        .context("retained destination parent")?;
    ensure!(
        fs::symlink_metadata(source)?.is_file() && fs::symlink_metadata(source)?.nlink() == 1,
        "CONFLICT: unsafe retained source"
    );
    ensure!(
        fs::symlink_metadata(destination_parent)?.is_dir()
            && fs::metadata(source_parent)?.dev() == fs::metadata(destination_parent)?.dev(),
        "CONFLICT: retention requires the same filesystem"
    );
    let old = CString::new(source.as_os_str().as_bytes())?;
    let new = CString::new(destination.as_os_str().as_bytes())?;
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            old.as_ptr(),
            libc::AT_FDCWD,
            new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe { libc::renamex_np(old.as_ptr(), new.as_ptr(), libc::RENAME_EXCL) };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let result = -1;
    ensure!(
        result == 0,
        "CONFLICT: retain move failed: {}",
        std::io::Error::last_os_error()
    );
    sync_directory(source_parent)?;
    sync_directory(destination_parent)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn atomic_write_preserves_metadata_and_refuses_links() {
        let root = std::env::temp_dir().join(format!("durable-{}", uuid::Uuid::new_v4()));
        directory(&root).unwrap();
        let target = root.join("record");
        let mut metadata = FileMetadata::private();
        metadata.mode = 0o640;
        write(&target, b"first", metadata).unwrap();
        write(&target, b"second", metadata).unwrap();
        assert_eq!(read(&target, 16).unwrap(), (b"second".to_vec(), metadata));
        let link = root.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read(&link, 16).is_err());
        assert!(write(&link, b"x", metadata).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"second");
        fs::remove_dir_all(root).unwrap();
    }
}
