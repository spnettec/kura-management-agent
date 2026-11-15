use anyhow::{Result, ensure};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

pub fn harden_process() -> Result<()> {
    unsafe {
        libc::umask(0o077);
    }
    // Set before creating runtime workers: the flag is inherited by new threads.
    #[cfg(target_os = "linux")]
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0,
        "cannot enable no_new_privs: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

fn private_file(path: &Path, uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.uid() == uid && metadata.mode() & 0o077 == 0,
        "private file must be a regular owned file without group/other access: {}",
        path.display()
    );
    Ok(())
}

pub fn prepare(key: &Path, state: &Path) -> Result<()> {
    private_file(key, unsafe { libc::geteuid() })?;
    prepare_state(state)
}

pub fn prepare_state(state: &Path) -> Result<()> {
    let uid = unsafe { libc::geteuid() };
    let parent = state
        .parent()
        .ok_or_else(|| anyhow::anyhow!("state requires private directory"))?;
    if !parent.exists() {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o077 == 0,
        "state directory must be owned and mode 0700"
    );
    for suffix in ["", "-wal", "-shm"] {
        let mut name = state.as_os_str().to_owned();
        name.push(suffix);
        let path = Path::new(&name);
        match fs::symlink_metadata(path) {
            Ok(_) => private_file(path, uid)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_exposed_key_state_and_symlink() {
        let root = std::env::temp_dir().join(format!("yofc-permissions-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let key = root.join("agent.key");
        fs::write(&key, "test-key").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        let db = root.join("state/results.sqlite");
        assert!(prepare(&key, &db).is_err());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        prepare(&key, &db).unwrap();
        fs::set_permissions(db.parent().unwrap(), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(prepare(&key, &db).is_err());
        fs::set_permissions(db.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&key, &db).unwrap();
        assert!(prepare(&key, &db).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
