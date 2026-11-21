//! A kernel mutation shares the installation's package and boot-restore fences.
#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{Context, Result, ensure};
    use std::{
        fs::{self, File, OpenOptions},
        io::Read,
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
    const BOOT: &str = "/var/lib/kura-legacy-firewall/boot-restore";
    fn read_pending(path: &Path) -> Result<serde_json::Value> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file()
                && meta.uid() == 0
                && meta.gid() == 0
                && meta.nlink() == 1
                && meta.mode() & 0o7777 == 0o600
                && meta.len() <= 8192,
            "UNPAIRED: boot record metadata"
        );
        let mut bytes = Vec::new();
        file.take(8193).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == meta.len(),
            "UNPAIRED: boot record length"
        );
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn require_sender_receipt(operation: &str) -> Result<()> {
        let boot = Path::new(BOOT);
        let pending = boot.join("pending.json");
        if exists(&pending)? {
            owner_dir(boot)?;
            let record = read_pending(&pending)?;
            ensure!(record["schema"] == 1, "UNPAIRED: boot record schema");
            if let Some(ids) = record.get("nativeIds") {
                let ids = ids.as_object().context("UNPAIRED: boot operation IDs")?;
                ensure!(
                    !ids.values().any(|id| id.as_str() == Some(operation)),
                    "UNKNOWN: original boot receipt requires boot recovery"
                );
            }
        }
        Ok(())
    }
    struct BootStep {
        family: String,
        operation: String,
        scope: String,
        digest: String,
        forwarding: Option<(String, bool, [u64; 2])>,
    }
    pub struct Admission {
        _dpkg: Option<File>,
        boot: File,
        step: Option<BootStep>,
    }
    impl Admission {
        pub fn acquire(inherited: Option<i32>, request: &super::super::Request) -> Result<Self> {
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
            let boot = Path::new(BOOT);
            owner_dir(boot)?;
            let (file, step) = if let Some(fd) = inherited {
                ensure!(
                    fd >= 3
                        && !request.restore_forwarding_on_boot
                        && request.forwarding.is_some() == request.boot_forwarding_source.is_some()
                        && request.changes.len() == 1,
                    "UNPAIRED: boot request"
                );
                let change = &request.changes[0];
                ensure!(
                    matches!(change.family.as_str(), "ipv4" | "ipv6")
                        && change.previous == change.candidate,
                    "UNPAIRED: boot family model"
                );
                // Duplicate the inherited open description, retaining the parent's flock.
                // fcntl returns EBADF for an invalid descriptor without taking ownership of it.
                let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
                ensure!(duplicate >= 0, "UNPAIRED: boot directory descriptor");
                use std::os::fd::FromRawFd;
                let inherited = unsafe { File::from_raw_fd(duplicate) };
                let named = fs::symlink_metadata(boot)?;
                let held = inherited.metadata()?;
                ensure!(
                    held.is_dir() && (held.dev(), held.ino()) == (named.dev(), named.ino()),
                    "UNPAIRED: boot directory descriptor identity"
                );
                use sha2::{Digest, Sha256};
                let digest = super::super::hex(&Sha256::digest(change.candidate.as_bytes()));
                (
                    inherited,
                    Some(BootStep {
                        family: change.family.clone(),
                        operation: request.operation_id.clone(),
                        scope: request.root_scope.clone(),
                        digest,
                        forwarding: match (&request.forwarding, &request.boot_forwarding_source) {
                            (Some(transition), Some(source)) => {
                                ensure!(
                                    transition.family == change.family
                                        && super::super::is_uuid(source),
                                    "UNPAIRED: boot forwarding request"
                                );
                                Some((source.clone(), transition.before, transition.namespace))
                            }
                            _ => None,
                        },
                    }),
                )
            } else {
                (File::open(boot)?, None)
            };
            ensure!(
                file.metadata()?.mode() & 0o7777 == 0o700,
                "UNPAIRED: boot restore directory"
            );
            file.try_lock().context("BUSY: boot firewall restore")?;
            let held = Self {
                _dpkg: dpkg,
                boot: file,
                step,
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
            let dir = self.boot.metadata()?;
            let named = fs::symlink_metadata(BOOT)?;
            ensure!(
                (dir.dev(), dir.ino()) == (named.dev(), named.ino()),
                "UNPAIRED: replaced boot directory"
            );
            let pending = Path::new(BOOT).join("pending.json");
            if let Some(BootStep {
                family,
                operation,
                scope,
                digest,
                forwarding,
            }) = &self.step
            {
                let record = read_pending(&pending)?;
                let identity = |meta: &fs::Metadata| serde_json::json!([meta.dev(), meta.ino()]);
                let binding = &record["binding"];
                let grant = &binding["confirmed"]["forwarding"][family];
                if let Some((source, before, namespace)) = forwarding {
                    let index = usize::from(family == "ipv6");
                    ensure!(
                        grant == source
                            && binding["namespace"] == serde_json::json!(namespace)
                            && record["nativeForwarding"][index] == if *before { "1" } else { "0" },
                        "UNPAIRED: original boot forwarding transition"
                    );
                } else {
                    ensure!(
                        grant.is_null(),
                        "UNPAIRED: missing boot forwarding transition"
                    );
                }
                let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
                let site = if family == "ipv4" {
                    "/etc/sysconfig/iptables"
                } else {
                    "/etc/sysconfig/ip6tables"
                };
                ensure!(
                    !exists(Path::new(site))?
                        && binding["profile"] == "networking"
                        && binding["root"] == identity(&fs::metadata("/")?)
                        && binding["state"] == identity(&dir)
                        && binding["namespace"] == identity(&fs::metadata("/proc/self/ns/net")?)
                        && binding["bootId"] == boot_id.trim(),
                    "UNPAIRED: boot step installation, namespace or site"
                );
                ensure!(
                    record["schema"] == 1
                        && record["issued"] == format!("confirmed-{family}")
                        && record["nativeIds"][family] == *operation
                        && record["binding"]["confirmed"]["rootScope"] == *scope
                        && record["binding"]["confirmed"]["models"][family] == *digest,
                    "UNPAIRED: original boot step"
                );
            } else {
                ensure!(
                    !exists(&pending)?,
                    "UNKNOWN: unresolved original boot firewall restore"
                );
            }
            Ok(())
        }
    }
}
#[cfg(target_os = "linux")]
pub use linux::{Admission, require_sender_receipt};
#[cfg(not(target_os = "linux"))]
pub fn require_sender_receipt(_: &str) -> anyhow::Result<()> {
    anyhow::bail!("UNSUPPORTED: firewall publication requires Linux")
}
#[cfg(not(target_os = "linux"))]
pub struct Admission;
#[cfg(not(target_os = "linux"))]
impl Admission {
    pub fn acquire(_: Option<i32>, _: &super::Request) -> anyhow::Result<Self> {
        anyhow::bail!("UNSUPPORTED: firewall publication requires Linux")
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::bail!("UNSUPPORTED: firewall publication requires Linux")
    }
}
