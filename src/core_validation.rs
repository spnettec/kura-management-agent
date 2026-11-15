//! Read-only Core RPC. The only transferred FD is the input snapshot, never a key.
use crate::{durable, snapshot_validation::Report};
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
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(45)))?;
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

pub(crate) fn info() -> Result<Ready> {
    let ready: Ready = serde_json::from_slice(&request_at(
        Path::new(SOCKET),
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
        Path::new(SOCKET),
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

#[cfg(test)]
#[path = "core_validation_tests.rs"]
mod tests;
