//! Read-only Core RPC. The only transferred FD is the input snapshot, never a key.
use crate::{
    durable,
    snapshot_validation::{Mode, PasswordPolicy, Report},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{fs::OpenOptionsExt, net::UnixStream},
    },
    path::Path,
    time::Duration,
};

const SOCKET: &str = "/run/kura-key-service/control.sock";
const RECOVERY_INPUT_SOCKET: &str = "/run/kura-recovery-input.sock";
const RECOVERY_MAIN_SOCKET: &str = "/run/kura-recovery-main.sock";
const PURPOSE: &str = "yofc-kura-core-credential-validation-v1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Binding {
    pub schema: u32,
    pub purpose: String,
    pub active_key_sha256: String,
    #[serde(deserialize_with = "required_optional")]
    pub ring_sha256: Option<String>,
    pub cohort_sha256: String,
}

fn required_optional<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Ready {
    schema: u32,
    state: String,
    pub binding: Binding,
    pub binding_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Validated {
    schema: u32,
    state: String,
    binding: Binding,
    binding_sha256: String,
    report: Report,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Inventoried {
    schema: u32,
    state: String,
    binding: Binding,
    binding_sha256: String,
    inventory: Inventory,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Inventory {
    schema: u32,
    directory: SnapshotDirectory,
    retained_directory_present: bool,
    files: Vec<SnapshotEntry>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotDirectory {
    device: String,
    inode: String,
    mode: u32,
    uid: u32,
    gid: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotEntry {
    name: String,
    size: u64,
    sha256: String,
    metadata: durable::FileMetadata,
}

impl Inventory {
    fn verify(&self) -> Result<()> {
        let dir = &self.directory;
        let canonical = |v: &str| v.parse::<u64>().is_ok_and(|n| n > 0 && n.to_string() == v);
        ensure!(
            self.schema == 1
                && canonical(&dir.device)
                && canonical(&dir.inode)
                && dir.uid > 0
                && dir.gid > 0
                && dir.mode == 0o700
                && self.files.len() <= 128,
            "invalid Core snapshot directory"
        );
        let mut total = 0;
        let mut previous = "";
        for file in &self.files {
            ensure!(
                file.name.as_str() > previous
                    && file.name.len() <= 128
                    && !file.name.starts_with('.')
                    && file
                        .name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                    && file.size <= 32 << 20
                    && digest(&file.sha256)
                    && file.metadata.uid == dir.uid
                    && file.metadata.mode == 0o600,
                "invalid Core snapshot entry"
            );
            previous = &file.name;
            total += file.size;
            ensure!(total <= 64 << 20, "invalid Core snapshot inventory size");
        }
        Ok(())
    }
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Binding {
    fn hash(&self) -> Result<String> {
        ensure!(
            self.schema == 1
                && self.purpose == PURPOSE
                && digest(&self.active_key_sha256)
                && self.ring_sha256.as_deref().is_none_or(digest)
                && digest(&self.cohort_sha256),
            "invalid Core validation binding"
        );
        let value = serde_json::to_value(self)?;
        let sorted: std::collections::BTreeMap<_, _> = value.as_object().unwrap().iter().collect();
        Ok(durable::hash(&serde_json::to_vec(&sorted)?))
    }
}

#[cfg(target_os = "linux")]
fn require_peer(stream: &UnixStream, expected: u32) -> Result<()> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        } == 0
            && length as usize == std::mem::size_of::<libc::ucred>()
            && credentials.uid == expected
            && credentials.pid > 0,
        "untrusted Core socket peer"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn require_peer(stream: &UnixStream, expected: u32) -> Result<()> {
    let (mut uid, mut gid) = (0, 0);
    ensure!(
        unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0 && uid == expected,
        "untrusted Core socket peer"
    );
    Ok(())
}

fn send_input(stream: &mut UnixStream, bytes: &[u8], input: &File) -> Result<()> {
    // cmsghdr requires native alignment on both Linux and macOS.
    let size = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as _) } as usize;
    let mut control = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let mut vector = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size as _;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        ensure!(!header.is_null(), "input descriptor framing");
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as _) as _;
        std::ptr::write_unaligned(
            libc::CMSG_DATA(header).cast::<libc::c_int>(),
            input.as_raw_fd(),
        );
    }
    let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, 0) };
    ensure!(
        sent > 0 && sent as usize <= bytes.len(),
        "Core input transfer failed"
    );
    stream.write_all(&bytes[sent as usize..])?;
    Ok(())
}

fn request_at(
    socket: &Path,
    owner: u32,
    request: &serde_json::Value,
    input: Option<&File>,
) -> Result<Vec<u8>> {
    request_with_timeout(socket, owner, request, input, Duration::from_secs(45))
}

fn request_with_timeout(
    socket: &Path,
    owner: u32,
    request: &serde_json::Value,
    input: Option<&File>,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    require_peer(&stream, owner)?;
    let payload = serde_json::to_vec(request)?;
    ensure!(
        !payload.is_empty() && payload.len() <= 65536,
        "Core request bound"
    );
    let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
    frame.extend(payload);
    if let Some(input) = input {
        send_input(&mut stream, &frame, input)?;
    } else {
        stream.write_all(&frame)?;
    }
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let size = u32::from_be_bytes(header) as usize;
    ensure!((1..=65536).contains(&size), "Core response bound");
    let mut raw = vec![0; size];
    stream.read_exact(&mut raw)?;
    ensure!(
        stream.read(&mut [0u8; 1])? == 0,
        "Core response trailing bytes"
    );
    Ok(raw)
}

fn validation_socket() -> &'static Path {
    #[cfg(target_os = "linux")]
    if unsafe { libc::geteuid() } != 0 {
        return Path::new("/run/kura-snapshot-validation/control.sock");
    }
    Path::new(SOCKET)
}

pub(crate) fn info() -> Result<Ready> {
    let ready: Ready = serde_json::from_slice(&request_at(
        validation_socket(),
        0,
        &serde_json::json!({"schema":1,"action":"core-validation-info"}),
        None,
    )?)?;
    ensure!(
        ready.schema == 1
            && ready.state == "CORE_CREDENTIALS_READY"
            && ready.binding.hash()? == ready.binding_sha256,
        "Core validation identity"
    );
    Ok(ready)
}

pub(crate) fn validate(
    path: &Path,
    sha: &str,
    mode: &str,
    policy: &str,
    expected: &Ready,
) -> Result<Report> {
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let result: Validated = serde_json::from_slice(&request_at(
        validation_socket(),
        0,
        &serde_json::json!({"schema":1,"action":"core-snapshot-validate","snapshotSha256":sha,
            "mode":mode,"passwordPolicy":policy,"expectedBindingSha256":expected.binding_sha256}),
        Some(&input),
    )?)?;
    ensure!(
        result.schema == 1
            && result.state == "CORE_SNAPSHOT_VALIDATED"
            && result.binding == expected.binding
            && result.binding_sha256 == expected.binding_sha256
            && result.binding.hash()? == result.binding_sha256,
        "Core validation identity changed"
    );
    Ok(result.report)
}

pub(crate) fn native_inventory() -> Result<serde_json::Value> {
    ensure!(
        cfg!(target_os = "linux") && unsafe { libc::geteuid() } != 0,
        "UNSUPPORTED: native Core snapshot inventory requires the installed agent identity"
    );
    let expected = info()?;
    let result: Inventoried = serde_json::from_slice(&request_at(
        validation_socket(),
        0,
        &serde_json::json!({"schema":1,"action":"core-snapshot-inventory","expectedBindingSha256":expected.binding_sha256}),
        None,
    )?)?;
    ensure!(
        result.schema == 1
            && result.state == "CORE_SNAPSHOT_INVENTORIED"
            && result.binding == expected.binding
            && result.binding_sha256 == expected.binding_sha256
            && result.binding.hash()? == result.binding_sha256,
        "Core inventory identity changed"
    );
    result.inventory.verify()?;
    Ok(
        serde_json::json!({"snapshotInventory":result.inventory,"coreBindingSha256":result.binding_sha256,
        "kuraRecoveryVerified":false}),
    )
}

pub(crate) fn restore_id(value: &str) -> bool {
    value.strip_prefix("rec-").is_some_and(|text| {
        uuid::Uuid::parse_str(text).is_ok_and(|parsed| parsed.hyphenated().to_string() == text)
    })
}

fn delegated_result(id: &str, raw: &[u8]) -> std::result::Result<serde_json::Value, &'static str> {
    let result = delegated_response(id, raw)?;
    let expected_fields = match result["state"].as_str() {
        Some("RECOVERY_INPUT_STAGED" | "RECOVERY_INPUT_READY") => 9,
        Some("RECOVERY_INPUT_GRANTED" | "RECOVERY_INPUT_PENDING" | "RECOVERY_INPUT_ATTEMPTED") => 4,
        _ => return Err("UNKNOWN"),
    };
    if result
        .as_object()
        .is_none_or(|object| object.len() != expected_fields)
    {
        return Err("UNKNOWN");
    }
    if expected_fields == 9
        && (!["snapshotSha256", "bindingSha256"]
            .into_iter()
            .all(|key| result[key].as_str().is_some_and(digest))
            || !matches!(result["mode"].as_str(), Some("plain" | "aes-gcm"))
            || !matches!(
                result["passwordPolicy"].as_str(),
                Some("authenticated" | "legacy" | "logical-v1")
            )
            || result["size"]
                .as_u64()
                .is_none_or(|size| !(1..=32 << 20).contains(&size)))
    {
        return Err("UNKNOWN");
    }
    Ok(result)
}

fn delegated_response(
    id: &str,
    raw: &[u8],
) -> std::result::Result<serde_json::Value, &'static str> {
    let result: serde_json::Value = serde_json::from_slice(raw).map_err(|_| "UNKNOWN")?;
    if let Some(reason) = result["error"].as_str() {
        if result.as_object().is_none_or(|object| object.len() != 2) || result["schema"] != 1 {
            return Err("UNKNOWN");
        }
        return Err(match reason {
            "FORBIDDEN" => "FORBIDDEN",
            "INVALID_ARGUMENT" | "PROTOCOL_MISMATCH" => "INVALID_ARGUMENT",
            "RESOURCE_EXHAUSTED" => "RESOURCE_EXHAUSTED",
            "RECOVERY_INPUT_EXISTS"
            | "RECOVERY_INPUT_CHANGED"
            | "COHORT_CHANGED"
            | "BUSY"
            | "CONFLICT"
            | "VALIDATION_REJECTED"
            | "MAIN_COMMAND_EXISTS"
            | "MAIN_LAUNCH_USED"
            | "MAIN_SELECTION_EXISTS"
            | "CORE_NOT_DRAINED"
            | "UNMANAGED_CORE"
            | "UNSAFE_RECOVERY_INPUT"
            | "MAINTENANCE" => "CONFLICT",
            _ => "UNKNOWN",
        });
    }
    if result["schema"] != 1
        || result["restoreId"] != id
        || result["root"]
            .as_object()
            .is_none_or(|object| object.len() != 2)
        || ["device", "inode"].into_iter().any(|key| {
            result["root"][key].as_str().is_none_or(|text| {
                !text
                    .parse::<u64>()
                    .is_ok_and(|number| number > 0 && number.to_string() == text)
            })
        })
    {
        return Err("UNKNOWN");
    }
    Ok(result)
}

fn main_result(id: &str, raw: &[u8]) -> std::result::Result<serde_json::Value, &'static str> {
    let result = delegated_response(id, raw)?;
    let count = match result["state"].as_str() {
        Some("MAIN_COMMAND_ABSENT") => 4,
        Some("MAIN_START_UNKNOWN") => 7,
        Some("MAIN_START_JOB_ACCEPTED") => 8,
        Some("MAIN_STOP_UNKNOWN" | "MAIN_STOPPED") => 12,
        _ => return Err("UNKNOWN"),
    };
    let is_digits = |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    let hex = |text: &str| {
        text.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if result
        .as_object()
        .is_none_or(|object| object.len() != count)
        || count >= 7
            && (!["selectionSha256", "planSha256"]
                .into_iter()
                .all(|key| result[key].as_str().is_some_and(digest))
                || !result["bootId"]
                    .as_str()
                    .is_some_and(|text| restore_id(&format!("rec-{text}"))))
        || count >= 8
            && !result["jobPath"]
                .as_str()
                .and_then(|path| path.strip_prefix("/org/freedesktop/systemd1/job/"))
                .is_some_and(is_digits)
        || count == 12
            && (result["pid"]
                .as_u64()
                .is_none_or(|pid| !(2..=i32::MAX as u64).contains(&pid))
                || !result["invocationId"]
                    .as_str()
                    .is_some_and(|text| text.len() == 32 && hex(text))
                || !result["startTicks"].as_str().is_some_and(is_digits)
                || !result["receiptSha256"].as_str().is_some_and(digest))
    {
        return Err("UNKNOWN");
    }
    Ok(result)
}

pub(crate) fn native_main(
    id: &str,
    action: &str,
    expected: Option<&str>,
    snapshot: Option<&str>,
) -> std::result::Result<serde_json::Value, &'static str> {
    if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } == 0 {
        return Err("UNSUPPORTED");
    }
    let mut request = serde_json::json!({"schema":1,"action":action,"restoreId":id});
    if let Some(sha) = expected {
        request["expectedSha256"] = serde_json::json!(sha);
    }
    if let Some(snapshot) = snapshot {
        request["snapshotId"] = serde_json::json!(snapshot);
    }
    let raw = request_with_timeout(
        Path::new(RECOVERY_MAIN_SOCKET),
        0,
        &request,
        None,
        Duration::from_secs(100),
    )
    .map_err(|_| {
        if expected.is_some() {
            "UNKNOWN"
        } else {
            "CONFLICT"
        }
    })?;
    if matches!(action, "main-guarded-start" | "main-guarded-original") {
        return guarded_result(id, &raw, action == "main-guarded-start");
    }
    let reply = main_result(id, &raw)?;
    match (action, expected) {
        ("main-start", Some(sha))
            if reply["state"] == "MAIN_START_JOB_ACCEPTED" && reply["planSha256"] == sha => {}
        ("main-stop", Some(sha))
            if reply["state"] == "MAIN_STOPPED" && reply["receiptSha256"] == sha => {}
        ("main-original", None) => {}
        _ => return Err("UNKNOWN"),
    }
    Ok(reply)
}

fn guarded_result(id: &str, raw: &[u8], starting: bool) -> std::result::Result<serde_json::Value, &'static str> {
    let reply = delegated_response(id, raw)?;
    let keys = reply.as_object().ok_or("UNKNOWN")?;
    let state = reply["state"].as_str().ok_or("UNKNOWN")?;
    if !starting && keys.len() == 4 && matches!(state, "GUARDED_MAIN_ABSENT" | "GUARDED_MAIN_START_UNKNOWN") {
        return Ok(reply);
    }
    let accepted = state == "GUARDED_MAIN_START_JOB_ACCEPTED";
    if !reply["guardedSha256"].as_str().is_some_and(digest)
        || accepted && !reply["jobPath"].as_str()
            .and_then(|path| path.strip_prefix("/org/freedesktop/systemd1/job/"))
            .is_some_and(decimal_digits)
    {
        return Err("UNKNOWN");
    }
    if starting {
        return if accepted && keys.len() == 6 { Ok(reply) } else { Err("UNKNOWN") };
    }
    if (!accepted && !matches!(state, "GUARDED_MAIN_PREPARED" | "GUARDED_MAIN_START_UNKNOWN"))
        || keys.len() != if accepted { 8 } else { 7 }
    {
        return Err("UNKNOWN");
    }
    let previous = serde_json::to_vec(&reply["originalStop"]).map_err(|_| "UNKNOWN")?;
    let stop = main_result(id, &previous)?;
    let proof = &reply["outcome"];
    let phase = proof["state"].as_str().ok_or("UNKNOWN")?;
    let fields = match phase {
        "MAIN_LAUNCH_PREPARED" | "MAIN_LAUNCH_CONDITIONED" => 5,
        "MAIN_LAUNCH_CLAIMED" => 6,
        "NORMAL_BOOT_ADMITTED" | "RECOVERY_REQUIRED" => 7,
        _ => return Err("UNKNOWN"),
    };
    if stop["state"] != "MAIN_STOPPED" || stop["root"] != reply["root"]
        || proof.as_object().is_none_or(|object| object.len() != fields)
        || proof["schema"] != 1 || proof["root"] != reply["root"] || proof["restoreId"] != id
        || proof["planSha256"] != reply["guardedSha256"]
        || state == "GUARDED_MAIN_PREPARED" && phase != "MAIN_LAUNCH_PREPARED"
        || fields >= 6 && (!valid_invocation(id, proof)
            || proof["invocation"]["bootId"] != stop["bootId"]
            || proof["invocation"]["invocationId"] == stop["invocationId"])
        || fields == 7 && !proof["receiptSha256"].as_str().is_some_and(digest)
    {
        return Err("UNKNOWN");
    }
    Ok(reply)
}

fn decimal_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

pub(crate) fn native_application(id: &str, guarded: bool) -> std::result::Result<serde_json::Value, &'static str> {
    if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } == 0 {
        return Err("UNSUPPORTED");
    }
    let action = if guarded { "main-guarded-application-original" } else { "main-application-original" };
    let raw = request_at(
        Path::new(RECOVERY_MAIN_SOCKET),
        0,
        &serde_json::json!({"schema":1,"action":action,"restoreId":id}),
        None,
    )
    .map_err(|_| "KURA_UNAVAILABLE")?;
    let proof = delegated_response(id, &raw)?;
    let (state, count) = if guarded { ("NORMAL_BOOT_ADMITTED", 9) } else { ("CM_APPLIED", 8) };
    if proof.as_object().is_none_or(|object| object.len() != count)
        || proof["state"] != state
        || !["planSha256", "receiptSha256", "snapshotSha256"]
            .into_iter()
            .all(|key| proof[key].as_str().is_some_and(digest))
        || guarded && !proof["sourceReceiptSha256"].as_str().is_some_and(digest)
        || !valid_invocation(id, &proof)
    {
        return Err("CONFLICT");
    }
    Ok(proof)
}

fn valid_invocation(id: &str, proof: &serde_json::Value) -> bool {
    let invocation = &proof["invocation"];
    !(invocation
            .as_object()
            .is_none_or(|object| object.len() != 8)
        || invocation["schema"] != 1
        || invocation["state"] != "MAIN_LAUNCH_CLAIMED"
        || invocation["restoreId"] != id
        || invocation["planSha256"] != proof["planSha256"]
        || invocation["pid"]
            .as_u64()
            .is_none_or(|pid| !(2..=i32::MAX as u64).contains(&pid))
        || !invocation["bootId"]
            .as_str()
            .is_some_and(|value| restore_id(&format!("rec-{value}")))
        || !invocation["startTicks"].as_str().is_some_and(decimal_digits)
        || !invocation["invocationId"].as_str().is_some_and(|value| {
            value.len() == 32
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    )
}

pub(crate) fn native_stage(
    path: &Path,
    id: &str,
    sha: &str,
    size: usize,
    mode: Mode,
    policy: PasswordPolicy,
) -> std::result::Result<serde_json::Value, &'static str> {
    if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } == 0 {
        return Err("UNSUPPORTED");
    }
    let expected = info().map_err(|_| "CONFLICT")?;
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "INTERNAL")?;
    let request = serde_json::json!({"schema":1,"action":"recovery-input-stage","restoreId":id,
        "snapshotSha256":sha,"size":size,"mode":mode,"passwordPolicy":policy,
        "bindingSha256":expected.binding_sha256});
    let raw = request_at(Path::new(RECOVERY_INPUT_SOCKET), 0, &request, Some(&input))
        .map_err(|_| "UNKNOWN")?;
    let receipt = delegated_result(id, &raw)?;
    if receipt["state"] != "RECOVERY_INPUT_STAGED"
        || [
            "snapshotSha256",
            "size",
            "mode",
            "passwordPolicy",
            "bindingSha256",
        ]
        .into_iter()
        .any(|name| receipt[name] != request[name])
    {
        return Err("UNKNOWN");
    }
    Ok(receipt)
}

pub(crate) fn native_stage_original(
    id: &str,
) -> std::result::Result<serde_json::Value, &'static str> {
    if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } == 0 {
        return Err("UNSUPPORTED");
    }
    let raw = request_at(
        Path::new(RECOVERY_INPUT_SOCKET),
        0,
        &serde_json::json!({"schema":1,"action":"recovery-input-original","restoreId":id}),
        None,
    )
    .map_err(|_| "CONFLICT")?;
    delegated_result(id, &raw)
}

#[cfg(test)]
#[path = "core_validation_tests.rs"]
mod tests;
