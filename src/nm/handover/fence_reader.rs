use super::*;

const FIREWALL: &str = "/etc/kura/firewall-owner-agent";

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Pair {
    schema_version: u8,
    pub(super) network: Option<MarkerIdentity>,
    pub(super) firewall: Option<MarkerIdentity>,
}

impl Pair {
    fn decode(bytes: &[u8]) -> Result<Self> {
        let pair: Self = serde_json::from_slice(bytes).context("CONFLICT: malformed Root fence observation")?;
        ensure!(pair.schema_version == 1 && [&pair.network, &pair.firewall].into_iter()
            .flatten().all(|marker| marker.inode != 0 && hex(&marker.sha256, 64)),
            "CONFLICT: malformed Root fence identity");
        ensure!(!matches!((&pair.network, &pair.firewall),
            (Some(n), Some(f)) if n.device == f.device && n.inode == f.inode),
            "CONFLICT: Root fence identities alias");
        Ok(pair)
    }
}

#[cfg(target_os = "linux")]
fn read_pair() -> Result<Pair> {
    use std::io::Write;
    use std::net::Shutdown;
    use std::os::unix::{fs::FileTypeExt, net::UnixStream};

    const SOCKET: &str = "/run/kura-management-nm-fence-reader.sock";
    let before = fs::symlink_metadata(SOCKET).context("UNSUPPORTED: paired Root fence reader socket unavailable")?;
    ensure!(before.file_type().is_socket() && before.uid() == 0 && before.gid() == 0 && before.mode() & 0o777 == 0o600,
        "FORBIDDEN: Root fence reader socket ownership or mode");
    let mut stream = UnixStream::connect(SOCKET).context("UNSUPPORTED: paired Root fence reader unavailable")?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut creds = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    ensure!(unsafe {
        libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED,
            creds.as_mut_ptr().cast(), &mut length)
    } == 0 && length as usize == std::mem::size_of::<libc::ucred>(),
        "FORBIDDEN: Root fence reader peer unavailable");
    let creds = unsafe { creds.assume_init() };
    // The accepted socket is created by the system manager in this PID namespace.
    ensure!(creds.pid == 1 && creds.uid == 0 && creds.gid == 0,
        "FORBIDDEN: Root fence reader is not the paired local systemd socket");
    stream.write_all(b"observe\n")?;
    stream.shutdown(Shutdown::Write)?;
    let mut data = Vec::new();
    stream.take(4097).read_to_end(&mut data).context("CONFLICT: Root fence observation unavailable")?;
    ensure!(!data.is_empty() && data.len() <= 4096 && data.ends_with(b"\n"),
        "CONFLICT: incomplete Root fence observation");
    let after = fs::symlink_metadata(SOCKET)?;
    ensure!((before.dev(), before.ino(), before.ctime(), before.ctime_nsec())
        == (after.dev(), after.ino(), after.ctime(), after.ctime_nsec()),
        "CONFLICT: Root fence reader socket changed during observation");
    Pair::decode(&data)
}

pub(super) fn needs_reader(path: &Path) -> Result<bool> {
    #[cfg(target_os = "linux")]
    if path == Path::new(MARKER) || path == Path::new(FIREWALL) {
        let directory = OpenOptions::new().read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/etc/kura")?;
        return readonly_filesystem(&directory);
    }
    let _ = path;
    Ok(false)
}

pub(super) fn readonly_filesystem(directory: &File) -> Result<bool> {
    let mut state = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(unsafe { libc::fstatvfs(directory.as_raw_fd(), state.as_mut_ptr()) } == 0,
        "UNSUPPORTED: cannot inspect the installed fence filesystem");
    Ok(unsafe { state.assume_init() }.f_flag & libc::ST_RDONLY != 0)
}

impl Store {
    pub(super) fn read_root_pair(&self) -> Result<Option<Pair>> {
        #[cfg(target_os = "linux")]
        if self.root.parent() == Some(Path::new(LEGACY_STATE_ROOT)) && fence_reader::needs_reader(&self.marker)? {
            return read_pair().map(Some);
        }
        Ok(None)
    }

    pub(super) fn network_marker_absent(&self) -> Result<bool> {
        if let Some(pair) = self.read_root_pair()? {
            return Ok(pair.network.is_none());
        }
        match fs::symlink_metadata(&self.marker) {
            Ok(_) => Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.into()),
        }
    }
}

pub(crate) fn observe_original(operation: &str) -> Result<Value> {
    let id = template::operation(operation)?;
    let root = Path::new(LEGACY_STATE_ROOT);
    let _guard = crate::system_change::Guard::observe_existing_shared(root)?;
    let store = Store::new(root);
    let (journal, _) = store.load()?.context("NOT_FOUND: original NM fence")?;
    ensure!(journal.operation_id == id, "NOT_FOUND: original NM fence");
    ensure!(matches!(journal.state, State::Fenced | State::LeaseIntent | State::Committed),
        "CONFLICT: original NM fence is not settled");
    Ok(json!({"operationId":id,"state":journal.state,"markerPairVerified":journal.firewall_marker.is_some(),
        "readThroughSandbox":needs_reader(Path::new(MARKER))?}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paired_root_reply_refuses_aliases_malformed_digests_or_authority_claims() {
        let left = json!({"device":1,"inode":8,"sha256":"a".repeat(64)});
        let right = json!({"device":1,"inode":9,"sha256":"b".repeat(64)});
        let valid = json!({"schemaVersion":1,"network":left,"firewall":right});
        assert_eq!(Pair::decode(valid.to_string().as_bytes()).unwrap().network.unwrap().inode, 8);
        for (field, value) in [("firewall",left), ("network",json!({"device":1,"inode":8,"sha256":"bad"})),
            ("schemaVersion",json!(2)), ("ownerLease", json!(true))] {
            let mut wrong = valid.clone(); wrong[field] = value;
            assert!(Pair::decode(wrong.to_string().as_bytes()).is_err());
        }
    }
}
