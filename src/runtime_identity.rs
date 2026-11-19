//! Explicit native process identity. Legacy launches never select this profile
//! by inference, and a native launch cannot fall back to a Root process.
mod transport;
pub(crate) use transport::enrolled_transport_endpoint;

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
const PACKAGE_MARKER: &str = "/usr/share/kura-management-agent/package-v2";
const KURA_PEER: &str = "/etc/kura-management-runtime/kura-peer.json";
const CORE_NETWORKING_DROP_IN: &str = "/usr/lib/systemd/system/kura.service.d/kura-networking.conf";
const CORE_NETWORKING_TEMPLATE: &str = "/opt/eclipse/kura/libexec/addons/networking/kura-networking.conf";
const MATERIAL: &str = "/etc/kura-management-runtime/enrollment-reader.json";
const KURA_REMOTE_SWITCH: &str = "/etc/kura-management-runtime/kura-remote-switch.json";

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

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct KuraPeer {
    schema_version: u32,
    profile: String,
    request_id: String,
    initialization_id: String,
    native_identity_sha256: String,
    control_gid: u32,
    kura_uid: u32,
    kura_gid: u32,
    core_unit_sha256: String,
    core_networking_drop_in_sha256: Option<String>,
    core_loader_sha256: String,
    java_bridge_metadata_sha256: String,
}

/// Stable administrative delegation, distinct from a remote ON decision or a
/// certificate identity. Root source maintenance must preserve its original proof.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct KuraRemoteSwitch {
    schema_version: u32,
    profile: String,
    request_id: String,
    initialization_id: String,
    peer_authorization_id: String,
    peer_authorization_result_sha256: String,
    native_uid: u32,
    control_gid: u32,
    kura_uid: u32,
    kura_gid: u32,
    can_control: bool,
    unit_started: bool,
    remote_enabled: bool,
}

impl KuraRemoteSwitch {
    fn validate(&self, identity: &Identity, peer: &KuraPeer, kura: u32) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.profile == "local-kura-remote-switch-v1"
                && self.initialization_id == peer.initialization_id
                && self.peer_authorization_id == peer.request_id
                && self.native_uid == identity.uid
                && self.control_gid == identity.gid
                && self.kura_uid == kura
                && kura > 0
                && kura != u32::MAX
                && self.kura_uid == peer.kura_uid
                && self.kura_gid == peer.kura_gid
                && self.can_control
                && !self.unit_started
                && !self.remote_enabled,
            "FORBIDDEN: original Root Kura remote-switch authority required"
        );
        for operation in [
            &self.request_id,
            &self.initialization_id,
            &self.peer_authorization_id,
        ] {
            ensure!(
                uuid::Uuid::parse_str(operation)?.to_string() == *operation,
                "INVALID_ARGUMENT: original remote-switch UUID"
            );
        }
        ensure!(
            self.peer_authorization_result_sha256.len() == 64
                && self
                    .peer_authorization_result_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "INVALID_ARGUMENT: original remote-switch peer proof digest"
        );
        Ok(())
    }
}

fn remote_switch_selected(requested: &str, present: bool) -> Result<bool> {
    ensure!(
        matches!(requested, "0" | "1") && (requested == "1") == present,
        "FORBIDDEN: Kura remote-switch setting differs from its Root authority"
    );
    Ok(present)
}

fn kura_remote_switch(identity: &Identity, kura: u32) -> Result<()> {
    let path = Path::new(KURA_REMOTE_SWITCH);
    let present = match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let requested = std::env::var("AGENT_KURA_REMOTE_MANAGEMENT").unwrap_or_else(|_| "0".into());
    if !remote_switch_selected(&requested, present)? {
        return Ok(());
    }
    let grant: KuraRemoteSwitch = serde_json::from_slice(&protected(path, 8192)?)?;
    let peer: KuraPeer = serde_json::from_slice(&protected(Path::new(KURA_PEER), 8192)?)?;
    grant.validate(identity, &peer, kura)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Material {
    schema_version: u32,
    profile: String,
    request_id: String,
    peer_authorization_id: String,
    native_identity_sha256: String,
    agent_uid: u32,
    agent_gid: u32,
    reader_gid: u32,
    source_uid: u32,
    source_root: String,
    upstream_socket: String,
    socket: String,
    publisher_pair_sha256: String,
    relay_pair_sha256: String,
    relay_grant_sha256: String,
    remote_enabled: bool,
}

impl Material {
    fn validate(
        &self,
        identity: &Identity,
        peer: &KuraPeer,
        identity_sha: &str,
        kura: u32,
    ) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.profile == "staged-enrollment-reader-v1"
                && !self.remote_enabled
                && self.agent_uid == identity.uid
                && self.agent_gid == identity.gid
                && self.reader_gid == identity.reader_gid
                && self.source_uid == kura
                && kura > 0
                && kura != u32::MAX
                && kura != identity.uid
                && self.peer_authorization_id == peer.request_id
                && self.native_identity_sha256 == identity_sha
                && self.source_root == crate::enrollment::reader::SOURCE
                && self.upstream_socket == crate::enrollment::reader::SOCKET
                && self.socket == READER_SOCKET,
            "FORBIDDEN: exact original staged-material authority required"
        );
        ensure!(
            uuid::Uuid::parse_str(&self.request_id)?.to_string() == self.request_id,
            "INVALID_ARGUMENT: original material UUID"
        );
        for digest in [
            &self.publisher_pair_sha256,
            &self.relay_pair_sha256,
            &self.relay_grant_sha256,
        ] {
            ensure!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "INVALID_ARGUMENT: original material pair checksum"
            );
        }
        Ok(())
    }
}

fn material(identity: &Identity, raw: &[u8], kura: u32) -> Result<Option<Material>> {
    match fs::symlink_metadata(MATERIAL) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let grant: Material = serde_json::from_slice(&protected(Path::new(MATERIAL), 8192)?)?;
    let peer: KuraPeer = serde_json::from_slice(&protected(Path::new(KURA_PEER), 8192)?)?;
    let identity_sha = crate::durable::hash(raw);
    peer.validate(identity, &identity_sha, kura)?;
    grant.validate(identity, &peer, &identity_sha, kura)?;
    ensure!(
        crate::durable::hash(&protected(
            Path::new("/usr/share/kura-management-agent/enrollment-reader.json"),
            8192
        )?) == grant.publisher_pair_sha256
            && crate::durable::hash(&protected(
                Path::new("/usr/share/kura-management-agent/native-profile.json"),
                32768
            )?) == grant.relay_pair_sha256,
        "CONFLICT: original publisher/relay pair changed"
    );
    Ok(Some(grant))
}

pub(crate) fn enrollment_paths(
    native: bool,
    kura: u32,
    source: Option<PathBuf>,
    socket: Option<PathBuf>,
) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    if !native {
        return Ok((source, socket));
    }
    ensure!(
        source.is_none() && socket.is_none(),
        "FORBIDDEN: native material capability comes only from its Root grant"
    );
    let raw = protected(Path::new(IDENTITY), 8192)?;
    let identity: Identity = serde_json::from_slice(&raw)?;
    Ok(match material(&identity, &raw, kura)? {
        Some(grant) => (Some(grant.source_root.into()), Some(grant.socket.into())),
        None => (None, None),
    })
}

impl KuraPeer {
    fn validate(&self, identity: &Identity, identity_sha: &str, kura: u32) -> Result<()> {
        ensure!(
            matches!(
                (self.schema_version, self.profile.as_str(), self.core_networking_drop_in_sha256.as_ref()),
                (1, "local-kura-v1", None) | (2, "local-kura-v2", Some(_))
            )
                && self.kura_uid == kura
                && kura > 0
                && kura != u32::MAX
                && kura != identity.uid
                && self.kura_gid > 0
                && self.kura_gid != u32::MAX
                && self.kura_gid != identity.gid
                && self.kura_gid != identity.reader_gid
                && self.control_gid == identity.gid
                && self.native_identity_sha256 == identity_sha,
            "FORBIDDEN: original Root Kura peer binding required"
        );
        for operation in [&self.request_id, &self.initialization_id] {
            ensure!(
                uuid::Uuid::parse_str(operation)?.to_string() == *operation,
                "INVALID_ARGUMENT: original Kura peer UUID"
            );
        }
        for digest in [
            &self.native_identity_sha256,
            &self.core_unit_sha256,
            &self.core_loader_sha256,
            &self.java_bridge_metadata_sha256,
        ].into_iter().chain(self.core_networking_drop_in_sha256.iter()) {
            ensure!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "INVALID_ARGUMENT: original Kura peer checksum"
            );
        }
        Ok(())
    }
}

fn kura_peer(identity: &Identity, raw: &[u8], kura: u32) -> Result<()> {
    let path = Path::new(KURA_PEER);
    let present = match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if kura == u32::MAX {
        ensure!(
            !present,
            "CONFLICT: original Kura peer configuration is missing"
        );
        return Ok(());
    }
    let peer: KuraPeer = serde_json::from_slice(&protected(path, 8192)?)?;
    peer.validate(identity, &crate::durable::hash(raw), kura)?;
    ensure!(
        checksum(
            Path::new("/usr/lib/systemd/system/kura.service"),
            0o644,
            65536
        )? == peer.core_unit_sha256,
        "CONFLICT: authorized Core unit changed"
    );
    if let Some(expected) = &peer.core_networking_drop_in_sha256 {
        for path in [CORE_NETWORKING_DROP_IN, CORE_NETWORKING_TEMPLATE] {
            ensure!(
                checksum(Path::new(path), 0o644, 4096)? == *expected,
                "CONFLICT: authorized Core Networking unit changed"
            );
        }
    } else {
        ensure!(
            matches!(fs::symlink_metadata(CORE_NETWORKING_DROP_IN), Err(error)
                if error.kind() == std::io::ErrorKind::NotFound),
            "CONFLICT: Core Networking drop-in requires its original authorization"
        );
    }
    let bridge_raw = protected(
        Path::new("/usr/share/kura-management-agent/java-bridge.json"),
        4096,
    )?;
    ensure!(
        crate::durable::hash(&bridge_raw) == peer.java_bridge_metadata_sha256,
        "CONFLICT: authorized Core adapter metadata changed"
    );
    let bridge: serde_json::Value = serde_json::from_slice(&bridge_raw)?;
    ensure!(
        bridge
            .get("coreLoaderProtocol")
            .and_then(serde_json::Value::as_u64)
            == Some(1)
            && bridge
                .get("coreLoaderSha256")
                .and_then(serde_json::Value::as_str)
                == Some(peer.core_loader_sha256.as_str()),
        "CONFLICT: authorized Core loader pair changed"
    );
    let continuity: serde_json::Value = serde_json::from_slice(&protected(
        Path::new("/etc/kura-management-runtime/continuity.json"),
        8192,
    )?)?;
    ensure!(
        continuity
            .get("operationId")
            .and_then(serde_json::Value::as_str)
            == Some(peer.initialization_id.as_str()),
        "CONFLICT: Kura peer original initialization changed"
    );
    Ok(())
}

pub(crate) fn protected(path: &Path, maximum: u64) -> Result<Vec<u8>> {
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

/// A source-maintenance inspector is a separate read-only native process. Its
/// candidate code is authenticated by the Root package controller, including
/// during publication when installed and public source pins are transitioning.
/// This grants no daemon socket, backend, or write authority; `enforce` retains
/// all of its existing runtime code/peer/material checks.
pub(crate) fn inspection_role() -> Result<()> {
    ensure!(
        cfg!(target_os = "linux") && unsafe { libc::geteuid() } != 0,
        "FORBIDDEN: retained inspection requires the dedicated non-Root identity"
    );
    let identity: Identity = serde_json::from_slice(&protected(Path::new(IDENTITY), 8192)?)?;
    identity.validate(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        Path::new(&format!("{STATE}/results.sqlite")),
        Path::new(SOCKET),
        u32::MAX,
        0,
    )?;
    identity.process(&fs::read_to_string("/proc/self/status")?)
}

pub(crate) fn enforce(
    requested: Option<PathBuf>,
    state: &Path,
    socket: &Path,
    kura: u32,
    admin: u32,
) -> Result<Option<u32>> {
    let present = |path: &Path| -> Result<bool> {
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    };
    let marker = present(Path::new(PACKAGE_MARKER))?;
    let selected = marker || present(Path::new("/etc/kura-management-runtime"))?;
    ensure!(
        requested.is_some() || !selected,
        "FORBIDDEN: selected native profile cannot fall back to a legacy launch"
    );
    if marker {
        ensure!(
            protected(Path::new(PACKAGE_MARKER), 128)? == b"kura-management-agent-v2\n",
            "FORBIDDEN: exact packaged native profile marker required"
        );
    }
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
    kura_peer(&identity, &raw, kura)?;
    material(&identity, &raw, kura)?;
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
    kura_remote_switch(&identity, kura)?;
    Ok(Some(identity.reader_gid))
}

pub(crate) fn enrollment_relay_group(root: &Path, kura: u32) -> Result<u32> {
    ensure!(
        root.as_os_str() == std::ffi::OsStr::new(STATE),
        "FORBIDDEN: native enrollment runtime root"
    );
    let group = enforce(
        Some(IDENTITY.into()),
        &root.join("results.sqlite"),
        Path::new(SOCKET),
        kura,
        0,
    )?
    .ok_or_else(|| anyhow::anyhow!("FORBIDDEN: native enrollment identity missing"))?;
    ensure!(
        enrollment_paths(true, kura, None, None)?.0.is_some(),
        "FORBIDDEN: original Root material grant missing"
    );
    Ok(group)
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

    fn peer_value() -> serde_json::Value {
        json!({"schemaVersion":1,"profile":"local-kura-v1",
            "requestId":"3dc75f3a-e51b-41ae-bb92-b5ea4d832304",
            "initializationId":"a121a02a-a445-4380-b4a3-05b627e90630",
            "nativeIdentitySha256":"d".repeat(64),"controlGid":993,"kuraUid":991,"kuraGid":992,
            "coreUnitSha256":"e".repeat(64),"coreLoaderSha256":"f".repeat(64),
            "javaBridgeMetadataSha256":"a".repeat(64)})
    }

    #[test]
    fn local_kura_grant_binds_exact_nonroot_peer_identity_and_source() {
        let value = peer_value();
        let peer: KuraPeer = serde_json::from_value(value.clone()).unwrap();
        peer.validate(&identity(), &"d".repeat(64), 991).unwrap();
        for uid in [0, 995, 990, u32::MAX] {
            assert!(peer.validate(&identity(), &"d".repeat(64), uid).is_err());
        }
        assert!(peer.validate(&identity(), &"0".repeat(64), 991).is_err());
        for (key, bad) in [
            ("controlGid", json!(994)),
            ("kuraUid", json!(0)),
            ("kuraGid", json!(0)),
            ("coreUnitSha256", json!("e".repeat(63))),
            ("coreLoaderSha256", json!("F".repeat(64))),
            ("requestId", json!("3DC75F3A-E51B-41AE-BB92-B5EA4D832304")),
            ("initializationId", json!("missing")),
        ] {
            let mut changed = value.clone();
            changed[key] = bad;
            let peer: KuraPeer = serde_json::from_value(changed).unwrap();
            assert!(
                peer.validate(&identity(), &"d".repeat(64), 991).is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn networking_peer_requires_its_own_versioned_drop_in_evidence() {
        let mut value = peer_value();
        value["schemaVersion"] = json!(2);
        value["profile"] = json!("local-kura-v2");
        let check = |value| {
            serde_json::from_value::<KuraPeer>(value)
                .unwrap().validate(&identity(), &"d".repeat(64), 991)
        };
        assert!(check(value.clone()).is_err());
        value["coreNetworkingDropInSha256"] = json!("E".repeat(64));
        assert!(check(value.clone()).is_err());
        value["coreNetworkingDropInSha256"] = json!("e".repeat(64));
        check(value.clone()).unwrap();
        value["schemaVersion"] = json!(1);
        value["profile"] = json!("local-kura-v1");
        assert!(check(value).is_err());
    }

    #[test]
    fn local_kura_grant_json_rejects_duplicate_unknown_or_noninteger_authority() {
        let value = peer_value();
        for (key, bad) in [
            ("schemaVersion", json!(true)),
            ("kuraUid", json!(991.0)),
            ("controlGid", json!("993")),
            ("arbitraryPath", json!("/tmp/other")),
        ] {
            let mut changed = value.clone();
            changed[key] = bad;
            assert!(
                serde_json::from_value::<KuraPeer>(changed).is_err(),
                "{key}"
            );
        }
        let text = serde_json::to_string(&value).unwrap();
        let duplicate = format!("{},\"kuraUid\":991}}", &text[..text.len() - 1]);
        assert!(serde_json::from_str::<KuraPeer>(&duplicate).is_err());
    }

    fn remote_switch_value() -> serde_json::Value {
        json!({"schemaVersion":1,"profile":"local-kura-remote-switch-v1",
            "requestId":"191b138c-bebc-4f95-bdac-2aff1e369039",
            "initializationId":"a121a02a-a445-4380-b4a3-05b627e90630",
            "peerAuthorizationId":"3dc75f3a-e51b-41ae-bb92-b5ea4d832304",
            "peerAuthorizationResultSha256":"e".repeat(64),"nativeUid":995,
            "controlGid":993,"kuraUid":991,"kuraGid":992,"canControl":true,
            "unitStarted":false,"remoteEnabled":false})
    }

    #[test]
    fn kura_remote_switch_permission_is_a_separate_root_grant_and_never_an_on_decision() {
        let peer: KuraPeer = serde_json::from_value(peer_value()).unwrap();
        let value = remote_switch_value();
        let grant: KuraRemoteSwitch = serde_json::from_value(value.clone()).unwrap();
        grant.validate(&identity(), &peer, 991).unwrap();
        for (key, bad) in [
            (
                "initializationId",
                json!("21002425-6c2d-421b-82f3-f84b950b46f8"),
            ),
            (
                "peerAuthorizationId",
                json!("a6968da4-9ed2-4fc2-9243-3793287f7ce7"),
            ),
            ("nativeUid", json!(0)),
            ("controlGid", json!(994)),
            ("kuraUid", json!(0)),
            ("kuraGid", json!(993)),
            ("canControl", json!(false)),
            ("unitStarted", json!(true)),
            ("remoteEnabled", json!(true)),
            ("peerAuthorizationResultSha256", json!("F".repeat(64))),
        ] {
            let mut changed = value.clone();
            changed[key] = bad;
            let grant: KuraRemoteSwitch = serde_json::from_value(changed).unwrap();
            assert!(grant.validate(&identity(), &peer, 991).is_err(), "{key}");
        }
    }

    #[test]
    fn missing_or_contradictory_root_remote_switch_grant_never_falls_back_to_an_env_flag() {
        assert!(!remote_switch_selected("0", false).unwrap());
        assert!(remote_switch_selected("1", true).unwrap());
        for (flag, present) in [
            ("1", false),
            ("0", true),
            ("true", true),
            ("", false),
            ("2", false),
        ] {
            assert!(remote_switch_selected(flag, present).is_err());
        }
    }

    #[test]
    fn remote_switch_json_rejects_extra_duplicate_boolean_and_noninteger_authority() {
        let value = remote_switch_value();
        for (key, bad) in [
            ("nativeUid", json!(995.0)),
            ("kuraUid", json!(true)),
            ("controlGid", json!("993")),
            ("canControl", json!(1)),
            ("arbitraryPermission", json!(true)),
        ] {
            let mut changed = value.clone();
            changed[key] = bad;
            assert!(
                serde_json::from_value::<KuraRemoteSwitch>(changed).is_err(),
                "{key}"
            );
        }
        let text = serde_json::to_string(&value).unwrap();
        let duplicate = format!("{},\"canControl\":true}}", &text[..text.len() - 1]);
        assert!(serde_json::from_str::<KuraRemoteSwitch>(&duplicate).is_err());
    }

    fn material_value() -> serde_json::Value {
        json!({"schemaVersion":1,"profile":"staged-enrollment-reader-v1",
            "requestId":"299296df-fc8e-4acb-a858-901d1dba6889",
            "peerAuthorizationId":"3dc75f3a-e51b-41ae-bb92-b5ea4d832304",
            "nativeIdentitySha256":"d".repeat(64),"agentUid":995,"agentGid":993,
            "readerGid":994,"sourceUid":991,"sourceRoot":crate::enrollment::reader::SOURCE,
            "upstreamSocket":crate::enrollment::reader::SOCKET,"socket":READER_SOCKET,
            "publisherPairSha256":"a".repeat(64),"relayPairSha256":"b".repeat(64),
            "relayGrantSha256":"c".repeat(64),"remoteEnabled":false})
    }

    #[test]
    fn material_capability_is_fixed_readonly_and_cannot_enable_a_channel_or_change_roles() {
        let value = material_value();
        let peer: KuraPeer = serde_json::from_value(peer_value()).unwrap();
        let grant: Material = serde_json::from_value(value.clone()).unwrap();
        grant
            .validate(&identity(), &peer, &"d".repeat(64), 991)
            .unwrap();
        for (key, bad) in [
            ("agentUid", json!(0)),
            ("sourceUid", json!(995)),
            ("readerGid", json!(993)),
            ("sourceRoot", json!("/etc/kura/credentials")),
            ("socket", json!(crate::enrollment::reader::SOCKET)),
            ("remoteEnabled", json!(true)),
            ("peerAuthorizationId", json!("other")),
            ("relayPairSha256", json!("F".repeat(64))),
        ] {
            let mut changed = value.clone();
            changed[key] = bad;
            let grant: Material = serde_json::from_value(changed).unwrap();
            assert!(
                grant
                    .validate(&identity(), &peer, &"d".repeat(64), 991)
                    .is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn material_json_and_native_env_cannot_supply_an_unsealed_capability() {
        let value = material_value();
        for (key, bad) in [
            ("agentUid", json!(995.0)),
            ("readerGid", json!("994")),
            ("arbitraryPath", json!("/tmp/other")),
            ("remoteEnabled", json!(1)),
        ] {
            let mut changed = value.clone();
            changed[key] = bad;
            assert!(
                serde_json::from_value::<Material>(changed).is_err(),
                "{key}"
            );
        }
        let text = serde_json::to_string(&value).unwrap();
        assert!(
            serde_json::from_str::<Material>(&format!(
                "{},\"sourceUid\":991}}",
                &text[..text.len() - 1]
            ))
            .is_err()
        );
        assert!(
            enrollment_paths(
                true,
                991,
                Some(crate::enrollment::reader::SOURCE.into()),
                None
            )
            .is_err()
        );
        let (source, socket) =
            enrollment_paths(false, 991, Some("/legacy-explicit".into()), None).unwrap();
        assert_eq!(source.unwrap(), PathBuf::from("/legacy-explicit"));
        assert!(socket.is_none());
    }
}
