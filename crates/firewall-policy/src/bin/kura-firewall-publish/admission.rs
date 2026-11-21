//! A kernel mutation shares the installation's package and boot-restore fences.
#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{Context, Result, ensure};
    use std::{
        fs::{self, File, OpenOptions},
        os::unix::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawFd,
        },
        path::Path,
    };

    fn exists(path: &Path) -> Result<bool> {
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    fn owner_dir(path: &Path) -> Result<()> {
        for dir in path.ancestors() {
            let m = fs::symlink_metadata(dir)?;
            ensure!(
                m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
                "UNPAIRED: firewall authority directory"
            );
        }
        Ok(())
    }
    pub struct Admission {
        _dpkg: Option<File>,
        _boot: File,
    }
    impl Admission {
        pub fn acquire() -> Result<Self> {
            let db = Path::new("/var/lib/dpkg");
            let dpkg = if exists(db)? {
                owner_dir(db)?;
                let path = db.join("lock");
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(&path)?;
                let m = file.metadata()?;
                ensure!(
                    m.is_file()
                        && m.uid() == 0
                        && m.gid() == 0
                        && m.nlink() == 1
                        && m.mode() & 0o002 == 0,
                    "UNPAIRED: package maintenance lock"
                );
                let mut lock: libc::flock = unsafe { std::mem::zeroed() };
                lock.l_type = libc::F_RDLCK as _;
                lock.l_whence = libc::SEEK_SET as _;
                if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) } < 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("BUSY: package maintenance");
                }
                let named = fs::symlink_metadata(path)?;
                ensure!(
                    m.dev() == named.dev() && m.ino() == named.ino(),
                    "UNPAIRED: package lock replaced"
                );
                Some(file)
            } else {
                None
            };
            let boot = Path::new("/var/lib/kura-legacy-firewall/boot-restore");
            owner_dir(boot)?;
            let file = File::open(boot)?;
            ensure!(
                file.metadata()?.mode() & 0o7777 == 0o700,
                "UNPAIRED: boot restore directory"
            );
            file.try_lock().context("BUSY: boot firewall restore")?;
            let held = Self {
                _dpkg: dpkg,
                _boot: file,
            };
            held.validate()?;
            Ok(held)
        }
        pub fn validate(&self) -> Result<()> {
            for path in [
                "/etc/kura/firewall-owner-agent",
                "/opt/eclipse/kura/framework/firewall-owner-agent",
            ] {
                ensure!(
                    !exists(Path::new(path))?,
                    "CONFLICT: firewall ownership belongs to agent"
                );
            }
            ensure!(
                !exists(Path::new(
                    "/var/lib/kura-legacy-firewall/boot-restore/pending.json"
                ))?,
                "UNKNOWN: unresolved original boot firewall restore"
            );
            Ok(())
        }
    }
}
#[cfg(target_os = "linux")]
pub use linux::Admission;
#[cfg(not(target_os = "linux"))]
pub struct Admission;
#[cfg(not(target_os = "linux"))]
impl Admission {
    pub fn acquire() -> anyhow::Result<Self> {
        anyhow::bail!("UNSUPPORTED: firewall publication requires Linux")
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::bail!("UNSUPPORTED: firewall publication requires Linux")
    }
}
