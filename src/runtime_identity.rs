//! Explicit native process identity. Legacy launches never select this profile
//! by inference, and a native launch cannot fall back to a Root process.
use anyhow::{Result, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub(crate) const IDENTITY: &str = "/etc/kura-management-runtime/agent.json";
pub(crate) const USER: &str = "kura-management-agent";
pub(crate) const STATE: &str = "/var/lib/kura-management-agent-runtime";
pub(crate) const SOCKET: &str = "/run/kura-management-agent-runtime/control.sock";
pub(crate) const UNIT: &str = "/usr/lib/systemd/system/kura-management-agent-v2.service";
pub(crate) const READER_SOCKET: &str = "/run/kura-management-agent-enrollment.sock";

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Identity {
    schema_version: u32,
    profile: String,
    user: String,
    uid: u32,
    gid: u32,
    reader_gid: u32,
    state_directory: String,
    socket: String,
    unit_sha256: String,
    binary_sha256: String,
    source_manifest_sha256: String,
}

fn protected(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    for parent in path.parent().into_iter().flat_map(Path::ancestors) {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "FORBIDDEN: native identity ancestry"
        );
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.gid() == 0
            && before.mode() & 0o7777 == 0o644
            && before.nlink() == 1
            && before.len() <= maximum,
        "FORBIDDEN: native identity file"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    ensure!(
        bytes.len() as u64 == before.len()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.uid() == after.uid()
            && before.gid() == after.gid()
            && before.mode() == after.mode()
            && before.nlink() == after.nlink()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "CONFLICT: native identity file changed"
    );
    Ok(bytes)
}

fn checksum(path: &Path, mode: u32, maximum: u64) -> Result<String> {
    for parent in path.parent().into_iter().flat_map(Path::ancestors) {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "FORBIDDEN: native program ancestry"
        );
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.gid() == 0
            && before.mode() & 0o7777 == mode
            && before.nlink() == 1
            && before.len() <= maximum,
        "FORBIDDEN: native program file"
    );
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        total += size as u64;
        ensure!(total <= maximum, "CONFLICT: native program size changed");
        digest.update(&buffer[..size]);
    }
    let after = file.metadata()?;
    ensure!(
        total == before.len()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.uid() == after.uid()
            && before.gid() == after.gid()
            && before.mode() == after.mode()
            && before.nlink() == after.nlink()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "CONFLICT: native program changed"
    );
    Ok(format!("{:x}", digest.finalize()))
}

impl Identity {
    fn validate(
        &self,
        uid: u32,
        gid: u32,
        state: &Path,
        socket: &Path,
        kura: u32,
        admin: u32,
    ) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.profile == "native-nonroot-v1"
                && self.user == USER
                && self.uid > 0
                && self.uid != u32::MAX
                && self.uid == uid
                && self.gid > 0
                && self.gid != u32::MAX
                && self.gid == gid
                && self.reader_gid > 0
                && self.reader_gid != u32::MAX
                && self.reader_gid != self.gid
                && self.state_directory == STATE
                && self.socket == SOCKET
                && state.as_os_str() == std::ffi::OsStr::new(&format!("{STATE}/results.sqlite"))
                && socket.as_os_str() == std::ffi::OsStr::new(SOCKET)
                && admin == 0
                && kura != 0
                && kura != uid,
            "FORBIDDEN: explicit native non-Root identity/path required"
        );
        for value in [
            &self.unit_sha256,
            &self.binary_sha256,
            &self.source_manifest_sha256,
        ] {
            ensure!(
                value.len() == 64
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "INVALID_ARGUMENT: native identity checksum"
            );
        }
        Ok(())
    }

    fn process(&self, status: &str) -> Result<()> {
        let fields = status
            .lines()
            .filter_map(|line| line.split_once(':'))
            .map(|(key, value)| (key, value.trim()))
            .collect::<BTreeMap<_, _>>();
        for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            ensure!(
                fields
                    .get(key)
                    .is_some_and(|value| u64::from_str_radix(value, 16) == Ok(0)),
                "FORBIDDEN: native agent capabilities require a separate broker"
            );
        }
        ensure!(
            fields.get("NoNewPrivs") == Some(&"1"),
            "FORBIDDEN: native agent requires NNP1"
        );
        let groups = fields
            .get("Groups")
            .ok_or_else(|| anyhow::anyhow!("UNAVAILABLE: native process groups"))?;
        for value in groups.split_whitespace() {
            let group: u32 = value.parse()?;
            ensure!(
                group == self.gid || group == self.reader_gid,
                "FORBIDDEN: unreviewed native agent group"
            );
        }
        Ok(())
    }
}

fn delegated_environment(values: impl Iterator<Item = (String, String)>) -> Result<()> {
    for (key, value) in values.filter(|(key, _)| key.starts_with("AGENT_")) {
        match key.as_str() {
            "AGENT_RUNTIME_IDENTITY"
            | "AGENT_STATE_DB"
            | "AGENT_SOCKET"
            | "AGENT_KURA_UID"
            | "AGENT_ADMIN_UID" => {}
            "AGENT_REMOTE_ENABLED" | "AGENT_KURA_REMOTE_MANAGEMENT" => ensure!(
                value == "0" || value == "1",
                "INVALID_ARGUMENT: native channel control"
            ),
            "AGENT_KURA_ENROLLMENT_DIR" => ensure!(
                value == crate::enrollment::reader::SOURCE,
                "FORBIDDEN: native enrollment source"
            ),
            "AGENT_KURA_ENROLLMENT_READER_SOCKET" => {
                ensure!(value == READER_SOCKET, "FORBIDDEN: native enrollment relay")
            }
            "AGENT_NETWORK_INTERFACES" | "AGENT_KURA_NETWORK_INTERFACES" => ensure!(
                value.is_empty(),
                "UNSUPPORTED: native network writing requires its typed broker"
            ),
            "AGENT_NETWORK_ALLOW_VIRTUAL_FIXTURE"
            | "AGENT_FIREWALL_WRITE"
            | "AGENT_SYSTEM_CONTROL_REMOTE" => ensure!(
                value == "0",
                "UNSUPPORTED: native privileged operation requires its typed broker"
            ),
            _ => {
                anyhow::bail!("UNSUPPORTED: native privilege delegation is not installed for {key}")
            }
        }
    }
    Ok(())
}

pub(crate) fn enforce(
    requested: Option<PathBuf>,
    state: &Path,
    socket: &Path,
    kura: u32,
    admin: u32,
) -> Result<Option<u32>> {
    let Some(path) = requested else {
        return Ok(None);
    };
    ensure!(
        cfg!(target_os = "linux") && path.as_os_str() == std::ffi::OsStr::new(IDENTITY),
        "FORBIDDEN: exact native runtime identity required"
    );
    let raw = protected(&path, 8192)?;
    let identity: Identity = serde_json::from_slice(&raw)
        .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: native runtime identity"))?;
    identity.validate(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        state,
        socket,
        kura,
        admin,
    )?;
    identity.process(&fs::read_to_string("/proc/self/status")?)?;
    ensure!(
        crate::durable::hash(&protected(Path::new(UNIT), 65536)?) == identity.unit_sha256,
        "CONFLICT: native runtime unit changed"
    );
    ensure!(
        checksum(
            Path::new("/usr/bin/yofc-management-agent"),
            0o755,
            512 * 1024 * 1024
        )? == identity.binary_sha256
            && checksum(
                Path::new("/usr/share/kura-management-agent/source-manifest.json"),
                0o644,
                2 * 1024 * 1024
            )? == identity.source_manifest_sha256,
        "CONFLICT: native runtime program/source pair changed"
    );
    let values = std::env::vars_os()
        .filter(|(key, _)| key.as_encoded_bytes().starts_with(b"AGENT_"))
        .map(|(key, value)| {
            Ok((
                key.into_string()
                    .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: native setting name"))?,
                value
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: native setting value"))?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    delegated_environment(values.into_iter())?;
    Ok(Some(identity.reader_gid))
}

pub(crate) fn enrollment_relay_group(root: &Path, kura: u32) -> Result<u32> {
    ensure!(
        root.as_os_str() == std::ffi::OsStr::new(STATE),
        "FORBIDDEN: native enrollment runtime root"
    );
    enforce(
        Some(IDENTITY.into()),
        &root.join("results.sqlite"),
        Path::new(SOCKET),
        kura,
        0,
    )?
    .ok_or_else(|| anyhow::anyhow!("FORBIDDEN: native enrollment identity missing"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn identity() -> Identity {
        serde_json::from_value(json!({"schemaVersion":1,"profile":"native-nonroot-v1","user":USER,
            "uid":995,"gid":993,"readerGid":994,"stateDirectory":STATE,"socket":SOCKET,
            "unitSha256":"a".repeat(64),"binarySha256":"b".repeat(64),"sourceManifestSha256":"c".repeat(64)})).unwrap()
    }
    fn check(
        id: &Identity,
        uid: u32,
        gid: u32,
        state: &str,
        socket: &str,
        kura: u32,
        admin: u32,
    ) -> bool {
        id.validate(uid, gid, Path::new(state), Path::new(socket), kura, admin)
            .is_ok()
    }
    #[test]
    fn explicit_profile_refuses_root_wrong_identity_paths_and_broad_authority() {
        let state = format!("{STATE}/results.sqlite");
        let id = identity();
        assert!(check(&id, 995, 993, &state, SOCKET, u32::MAX, 0));
        assert!(check(&id, 995, 993, &state, SOCKET, 997, 0));
        for (uid, gid, path, sock, kura, admin) in [
            (0, 993, state.as_str(), SOCKET, 997, 0),
            (995, 0, state.as_str(), SOCKET, 997, 0),
            (996, 993, state.as_str(), SOCKET, 997, 0),
            (
                995,
                993,
                "/var/lib/kura-management-agent/results.sqlite",
                SOCKET,
                997,
                0,
            ),
            (995, 993, state.as_str(), "/run/other.sock", 997, 0),
            (995, 993, state.as_str(), SOCKET, 995, 0),
            (995, 993, state.as_str(), SOCKET, 0, 0),
            (995, 993, state.as_str(), SOCKET, 997, 995),
        ] {
            assert!(!check(&id, uid, gid, path, sock, kura, admin));
        }
        let mut bad = identity();
        bad.uid = 0;
        assert!(!check(&bad, 0, 993, &state, SOCKET, 997, 0));
        bad = identity();
        bad.reader_gid = 0;
        assert!(!check(&bad, 995, 993, &state, SOCKET, 997, 0));
    }
    #[test]
    fn capabilities_and_additional_groups_do_not_hide_behind_nonroot_uid() {
        let status = "CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\nGroups:\t993 994\n";
        identity().process(status).unwrap();
        for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            assert!(
                identity()
                    .process(&status.replace(&format!("{key}:\t0"), &format!("{key}:\t1000")))
                    .is_err()
            );
        }
        assert!(
            identity()
                .process(&status.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"))
                .is_err()
        );
        assert!(
            identity()
                .process(&status.replace("993 994", "993 994 0"))
                .is_err()
        );
        assert!(
            identity()
                .process(&status.replace("993 994", "993 994 42"))
                .is_err()
        );
        assert!(identity().process("").is_err());
    }
    #[test]
    fn unavailable_brokers_never_turn_into_ambient_root_backends() {
        let test = |key: &str, value: &str| {
            delegated_environment(vec![(key.to_string(), value.to_string())].into_iter())
        };
        test("AGENT_KURA_REMOTE_MANAGEMENT", "1").unwrap();
        test("AGENT_KURA_ENROLLMENT_READER_SOCKET", READER_SOCKET).unwrap();
        for (key, value) in [
            ("AGENT_FIREWALL_WRITE", "1"),
            ("AGENT_SYSTEM_CONTROL_CONFIG", "/etc/grant.json"),
            ("AGENT_NETWORK_INTERFACES", "eth0"),
            ("AGENT_KURA_SNAPSHOT", "1"),
            ("AGENT_NM_CONFIG", "/etc/nm.json"),
            ("AGENT_KEY", "/etc/kura-management-agent/agent.key"),
            ("AGENT_CONSOLE_ENDPOINT", "https://a:1"),
            (
                "AGENT_KURA_ENROLLMENT_READER_SOCKET",
                crate::enrollment::reader::SOCKET,
            ),
            ("AGENT_UNKNOWN_FLAG", "0"),
        ] {
            assert!(test(key, value).is_err(), "{key}");
        }
    }
}
