//! A single OS-backed admission boundary for network, firewall, recovery and
//! online Kura writes. Persistent unresolved journals survive releasing the lock.
use anyhow::{Result, ensure};
use std::{
    fs::{File, OpenOptions},
    os::unix::{fs::OpenOptionsExt, io::AsRawFd},
    path::Path,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Subsystem {
    Network,
    Nm,
    Firewall,
    Recovery,
    Configuration,
    Identity,
    OrdinaryBoot,
    SystemControl,
}
pub struct Guard {
    _file: File,
}

impl Guard {
    pub(crate) fn native_boot_lock(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata()?;
        ensure!(
            m.is_file() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
            "FORBIDDEN: unsafe Core boot maintenance lock"
        );
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "CONFLICT: Core boot maintenance is executing"
        );
        Ok(Self { _file: file })
    }
    pub fn acquire(root: &Path, caller: Subsystem) -> Result<Self> {
        let guard = Self::observe(root)?;
        Self::admit(root, caller)?;
        Ok(guard)
    }
    /// Serialize a coherent observation without admitting a system write. This
    /// intentionally works while retained journals require recovery.
    pub(crate) fn observe(root: &Path) -> Result<Self> {
        let file = Self::open(root)?;
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "CONFLICT: another system change is executing"
        );
        Ok(Self { _file: file })
    }
    /// Coherent reads may overlap each other, but never a system writer. Wait
    /// only for this lock, before executing the read, and never retry an action.
    pub(crate) fn observe_shared(root: &Path, timeout: std::time::Duration) -> Result<Self> {
        let file = Self::open(root)?;
        let started = std::time::Instant::now();
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
                return Ok(Self { _file: file });
            }
            let error = std::io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)) {
                return Err(error.into());
            }
            ensure!(
                started.elapsed() < timeout,
                "CONFLICT: system observation lock timed out"
            );
            std::thread::sleep(
                std::time::Duration::from_millis(5).min(timeout.saturating_sub(started.elapsed())),
            );
        }
    }
    fn open(root: &Path) -> Result<File> {
        crate::durable::directory(root)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root.join("system-change.lock"))?;
        Ok(file)
    }
    fn admit(root: &Path, caller: Subsystem) -> Result<()> {
        let nm_settled = crate::nm::transaction::admission(root)?;
        ensure!(
            caller == Subsystem::Nm || nm_settled,
            "CONFLICT: unresolved joint NM transaction"
        );

        for (kind, name, terminal) in [
            (
                Subsystem::Network,
                "network",
                &["COMMITTED", "ROLLED_BACK"][..],
            ),
            (
                Subsystem::Firewall,
                "firewall",
                &["COMMITTED", "ROLLED_BACK"][..],
            ),
            (
                Subsystem::Recovery,
                "recovery",
                &[
                    "SUCCEEDED",
                    "FAILED",
                    "COMPLETED_APPROVED_CHECKS",
                    "ORDINARY_ACTIVE_APPROVED_CHECKS",
                    "ORDINARY_CANCELLED",
                ][..],
            ),
            (
                Subsystem::OrdinaryBoot,
                "ordinary-boot",
                &["BOOT_POLICY_COMMITTED", "CANCELLED"][..],
            ),
            (
                Subsystem::SystemControl,
                "system-control",
                &["COMPLETED", "CANCELLED"][..],
            ),
        ] {
            if caller == kind {
                continue;
            }
            // Configuration writes and ordinary network updates are independent;
            // recovery is the only writer allowed to stop/replace Kura state.
            if caller == Subsystem::Configuration
                && !matches!(
                    kind,
                    Subsystem::Recovery | Subsystem::OrdinaryBoot | Subsystem::SystemControl
                )
            {
                continue;
            }
            let path = root.join(name).join("transaction.json");
            if kind == Subsystem::SystemControl {
                crate::system_control::validate_retained(root)?;
            }
            if kind == Subsystem::Recovery && !path.exists() {
                ensure!(
                    !crate::recovery::ordinary_command_evidence(&root.join(name))?,
                    "CONFLICT: orphan ordinary handoff evidence; preserve state"
                );
            }
            if kind == Subsystem::Recovery && path.exists() {
                crate::recovery::validate_cancelled_handoff(&root.join(name))?;
            }
            if kind == Subsystem::OrdinaryBoot {
                crate::ordinary_boot::Boot::new(root.into())?.status()?;
            }
            if path.exists() {
                let (bytes, _) = crate::durable::read(&path, 1_048_576)?;
                let value: serde_json::Value = serde_json::from_slice(&bytes)?;
                ensure!(
                    value["state"]
                        .as_str()
                        .is_some_and(|s| terminal.contains(&s)),
                    "CONFLICT: unresolved {name} transaction"
                );
            }
        }
        Ok(())
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self._file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_observation_waits_for_writer_and_times_out_without_admission() {
        use std::time::{Duration, Instant};
        let root = std::env::temp_dir().join(format!("system-read-{}", uuid::Uuid::new_v4()));
        let writer = Guard::acquire(&root, Subsystem::Firewall).unwrap();
        let started = Instant::now();
        assert!(Guard::observe_shared(&root, Duration::from_millis(30)).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        let waiting_root = root.clone();
        let waiter = std::thread::spawn(move || {
            Guard::observe_shared(&waiting_root, Duration::from_secs(1))
        });
        drop(writer);
        let read = waiter.join().unwrap().unwrap();
        let other = Guard::observe_shared(&root, Duration::ZERO).unwrap();
        assert!(Guard::acquire(&root, Subsystem::Network).is_err());
        drop(read);
        drop(other);
        assert!(Guard::acquire(&root, Subsystem::Network).is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn writers_share_one_lock_and_recovery_required_blocks_admission() {
        let root = std::env::temp_dir().join(format!("system-change-{}", uuid::Uuid::new_v4()));
        let first = Guard::acquire(&root, Subsystem::Network).unwrap();
        assert!(Guard::acquire(&root, Subsystem::Firewall).is_err());
        drop(first);
        crate::durable::directory(&root.join("recovery")).unwrap();
        crate::durable::json(
            &root.join("recovery/transaction.json"),
            &serde_json::json!({"state":"RECOVERY_REQUIRED"}),
        )
        .unwrap();
        assert!(Guard::acquire(&root, Subsystem::Configuration).is_err());
        assert!(Guard::acquire(&root, Subsystem::Network).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
