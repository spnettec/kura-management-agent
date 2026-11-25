//! Fresh-domain publication. Existing operation namespaces are never converted.
use super::{hex, root_identity::RootIdentity};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub const DIRECTORY: &str = ".root-domain-v2";
const FINAL: &str = "binding.json";
const STAGED: &str = "binding.staged";
const WRITERS: &str = "/run/kura-key-service/writers/lease.lock";
const LIMIT: u64 = 8192;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Binding {
    schema: u8,
    purpose: &'static str,
    machine_sha256: String,
    identity: RootIdentity,
}

pub struct Current {
    raw: Vec<u8>,
    pub scope: String,
}

impl Current {
    pub fn observe(machine: &str, root: &File, journal: &File) -> Result<Self> {
        let binding = Binding {
            schema: 2,
            purpose: "kura-firewall-persistent-root-v2",
            machine_sha256: hex(&Sha256::digest(machine.as_bytes())),
            identity: RootIdentity::observe(root, journal)?,
        };
        // Sort explicitly, including builds where serde_json's preserve_order
        // feature is unified by another workspace member.
        let mut canonical = serde_json::to_value(binding)?;
        canonical.sort_all_objects();
        let raw = serde_json::to_vec(&canonical)?;
        ensure!(raw.len() as u64 <= LIMIT, "RESOURCE_EXHAUSTED: Root binding");
        let mut digest = Sha256::new();
        digest.update(b"kura-firewall-publication-v2\0");
        digest.update(&raw);
        Ok(Self { raw, scope: hex(&digest.finalize()) })
    }
}

fn directory(path: &Path) -> Result<File> {
    let named = fs::symlink_metadata(path)?;
    ensure!(named.is_dir() && named.uid() == 0 && named.gid() == 0
        && named.mode() & 0o7777 == 0o700, "UNPAIRED: Root binding directory");
    let file = OpenOptions::new().read(true).custom_flags(libc_no_follow()).open(path)?;
    let held = file.metadata()?;
    ensure!((held.dev(), held.ino()) == (named.dev(), named.ino()), "UNPAIRED: Root binding directory changed");
    Ok(file)
}

fn names(path: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(path)? {
        ensure!(names.len() < 12289, "RESOURCE_EXHAUSTED: Root domain entries");
        names.push(entry?.file_name().into_string()
            .map_err(|_| anyhow::anyhow!("UNPAIRED: Root binding filename"))?);
    }
    names.sort();
    Ok(names)
}

fn read(path: &Path, staged: bool) -> Result<Vec<u8>> {
    let named = fs::symlink_metadata(path)?;
    let modes: &[u32] = if staged { &[0o600, 0o400] } else { &[0o400] };
    ensure!(named.is_file() && named.uid() == 0 && named.gid() == 0 && named.nlink() == 1
        && modes.contains(&(named.mode() & 0o7777)) && (1..=LIMIT).contains(&named.len()),
        "UNPAIRED: Root binding metadata");
    let file = OpenOptions::new().read(true).custom_flags(libc_no_follow()).open(path)?;
    let held = file.metadata()?;
    ensure!((held.dev(), held.ino()) == (named.dev(), named.ino()), "UNPAIRED: Root binding changed");
    let mut raw = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut raw)?;
    ensure!(raw.len() as u64 == held.len(), "UNRESOLVED: incomplete Root binding");
    Ok(raw)
}

#[cfg(target_os = "linux")]
fn libc_no_follow() -> i32 { libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC }
#[cfg(not(target_os = "linux"))]
fn libc_no_follow() -> i32 { 0 }

pub fn selected(parent: &Path, machine: &str, root: &File, journal: &File) -> Result<Option<String>> {
    let path = parent.join(DIRECTORY);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(_) => (),
    }
    let _held = directory(&path)?;
    ensure!(names(&path)? == [FINAL], "UNRESOLVED: Root domain publication is incomplete");
    let current = Current::observe(machine, root, journal)?;
    ensure!(read(&path.join(FINAL), false)? == current.raw,
        "UNPAIRED: persistent firewall Root objects");
    Ok(Some(current.scope))
}

#[cfg(target_os = "linux")]
pub fn writer_fence() -> Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    ensure!(unsafe { libc::geteuid() == 0 && libc::getegid() == 0 }, "FORBIDDEN: Root domain initialization");
    // FD3 is an inherited descriptor, not a caller-selected identity or path.
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::zeroed();
    ensure!(unsafe { libc::fstat(3, metadata.as_mut_ptr()) } == 0, "UNPAIRED: inherited Core writer fence required");
    let file = unsafe { File::from_raw_fd(3) };
    for path in Path::new(WRITERS).ancestors().skip(1) {
        let info = fs::symlink_metadata(path)?;
        ensure!(info.is_dir() && info.uid() == 0 && info.gid() == 0 && info.mode() & 0o022 == 0,
            "UNPAIRED: Core writer fence hierarchy");
    }
    let named = fs::symlink_metadata(WRITERS)?;
    let held = file.metadata()?;
    ensure!(named.is_file() && held.is_file() && held.uid() == 0 && held.gid() == 0
        && held.mode() & 0o7777 == 0o600 && held.nlink() == 1 && held.len() == 0
        && (held.dev(), held.ino()) == (named.dev(), named.ino()), "UNPAIRED: Core writer fence");
    ensure!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "BUSY: Core writers are active");
    Ok(file)
}
#[cfg(not(target_os = "linux"))]
pub fn writer_fence() -> Result<File> { anyhow::bail!("UNSUPPORTED_ROOT_IDENTITY: Linux required") }

pub fn initialize(parent: &Path, machine: &str, root: &File, journal: &File) -> Result<(String, bool)> {
    let path = parent.join(DIRECTORY);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
        Ok(_) => {
            let _held = directory(&path)?;
            match names(&path)?.as_slice() {
                [name] if name == FINAL => return Ok((selected(parent, machine, root, journal)?
                    .context("Missing existing Root binding")?, false)),
                [] => (),
                [name] if name == STAGED => (),
                _ => anyhow::bail!("UNPAIRED: conflicting Root domain publication"),
            }
        }
    }
    ensure!(names(parent)?.iter().all(|name| name == DIRECTORY),
        "LEGACY_DOMAIN: existing firewall records cannot acquire a new Root binding");
    for name in ["rules", "boot-restore"] {
        let path = parent.parent().context("Missing firewall state parent")?.join(name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
            Ok(info) => ensure!(info.is_dir() && names(&path)?.is_empty(),
                "LEGACY_DOMAIN: retained firewall model, sender or boot state"),
        }
    }
    let current = Current::observe(machine, root, journal)?;
    match DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => journal.sync_all()?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    let held = directory(&path)?;
    let pending = path.join(STAGED);
    match names(&path)?.as_slice() {
        [] => {
            let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
                .custom_flags(libc_no_follow()).open(&pending)?;
            file.write_all(&current.raw)?;
            file.sync_all()?;
            held.sync_all()?;
        }
        [name] if name == STAGED => ensure!(read(&pending, true)? == current.raw,
            "UNRESOLVED: retained staged Root binding differs or is incomplete"),
        _ => anyhow::bail!("UNPAIRED: conflicting Root domain publication"),
    }
    // Validate the exact staged bytes before the only publication point.
    ensure!(read(&pending, true)? == current.raw, "UNRESOLVED: Root binding staging");
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o400))?;
    File::open(&pending)?.sync_all()?;
    publish_no_replace(&pending, &path.join(FINAL))?;
    held.sync_all()?;
    journal.sync_all()?;
    ensure!(selected(parent, machine, root, journal)?.as_deref() == Some(current.scope.as_str()),
        "UNRESOLVED: Root domain publication readback");
    Ok((current.scope, true))
}

#[cfg(target_os = "linux")]
fn publish_no_replace(from: &Path, to: &Path) -> Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let from = CString::new(from.as_os_str().as_bytes())?;
    let to = CString::new(to.as_os_str().as_bytes())?;
    ensure!(unsafe { libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, from.as_ptr(),
        libc::AT_FDCWD, to.as_ptr(), libc::RENAME_NOREPLACE) } == 0,
        "UNRESOLVED: publish Root binding: {}", std::io::Error::last_os_error());
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn publish_no_replace(_: &Path, _: &Path) -> Result<()> { anyhow::bail!("Linux required") }
