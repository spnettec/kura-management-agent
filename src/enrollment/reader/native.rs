use super::*;
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashSet,
    fs::{self, File, Metadata},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            fs::{FileTypeExt, MetadataExt},
            net::UnixStream,
        },
    },
    path::Path,
    time::{Duration, Instant},
};
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
#[cfg(test)]
#[path = "nonroot_tests.rs"]
mod nonroot_tests;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Header {
    version: u32,
    ok: bool,
    request_id: String,
    stage_sha256: String,
    source_uid: u32,
    files: Vec<String>,
}

pub(super) fn snapshot(transport: Transport, id: &str, digest: &str, uid: u32) -> Result<Snapshot> {
    let (endpoint, group, mode) = transport.endpoint();
    let path = Path::new(endpoint);
    for parent in path.parent().into_iter().flat_map(Path::ancestors) {
        let m = fs::symlink_metadata(parent)
            .map_err(|_| anyhow::anyhow!("UNAVAILABLE: enrollment endpoint"))?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "FORBIDDEN: enrollment endpoint ancestry"
        );
    }
    let m = fs::symlink_metadata(path)
        .map_err(|_| anyhow::anyhow!("UNAVAILABLE: enrollment endpoint"))?;
    ensure!(
        m.file_type().is_socket()
            && m.uid() == 0
            && m.gid() == group
            && m.nlink() == 1
            && m.mode() & 0o7777 == mode,
        "FORBIDDEN: enrollment endpoint"
    );
    let mut stream = UnixStream::connect(path)
        .map_err(|_| anyhow::anyhow!("UNAVAILABLE: enrollment publisher"))?;
    // PID1 owns a socket-activated listening endpoint. The paired worker runs
    // as Kura's UID; every delivered file must independently have that UID.
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&peer) as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut length,
            )
        } == 0
            && length as usize == std::mem::size_of_val(&peer)
            && peer.uid == 0,
        "FORBIDDEN: enrollment publisher peer"
    );
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut request =
        serde_json::to_vec(&json!({"version":1,"requestId":id,"stageSha256":digest}))?;
    request.push(b'\n');
    stream
        .write_all(&request)
        .map_err(|_| anyhow::anyhow!("UNAVAILABLE: enrollment publisher"))?;
    receive(&mut stream, id, digest, uid)
}

fn identity(m: &Metadata) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn receive_bytes(
    stream: &UnixStream,
    bytes: &mut [u8],
    fds: &mut Vec<OwnedFd>,
    deadline: Instant,
) -> Result<usize> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| anyhow::anyhow!("UNAVAILABLE: enrollment response deadline"))?;
    ensure!(
        !remaining.is_zero(),
        "UNAVAILABLE: enrollment response deadline"
    );
    stream.set_read_timeout(Some(remaining))?;
    let size = unsafe { libc::CMSG_SPACE((16 * std::mem::size_of::<libc::c_int>()) as _) } as usize;
    let mut control = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size as _;
    let received =
        unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    ensure!(
        received >= 0,
        "UNAVAILABLE: enrollment response interrupted"
    );
    let mut unexpected = false;
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            let base = libc::CMSG_LEN(0) as usize;
            let length = (*header).cmsg_len as usize;
            if (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_RIGHTS
                && length >= base
            {
                let count = (length - base) / std::mem::size_of::<libc::c_int>();
                unexpected |= (length - base) % std::mem::size_of::<libc::c_int>() != 0;
                for index in 0..count {
                    let raw = std::ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                    );
                    fds.push(OwnedFd::from_raw_fd(raw));
                }
            } else {
                unexpected = true;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    // Adopt/close delivered rights even when the kernel reports truncation.
    ensure!(
        !unexpected
            && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
            && fds.len() <= FILES.len(),
        "PROTOCOL_MISMATCH: enrollment ancillary data"
    );
    Ok(received as usize)
}

fn exact(
    stream: &UnixStream,
    bytes: &mut [u8],
    fds: &mut Vec<OwnedFd>,
    deadline: Instant,
) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let received = receive_bytes(stream, &mut bytes[offset..], fds, deadline)?;
        ensure!(received > 0, "UNAVAILABLE: enrollment response truncated");
        offset += received;
    }
    Ok(())
}

fn receive(stream: &mut UnixStream, id: &str, digest: &str, uid: u32) -> Result<Snapshot> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut fds = Vec::new();
    let mut prefix = [0u8; 4];
    exact(stream, &mut prefix, &mut fds, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    ensure!(
        (1..=4096).contains(&length),
        "PROTOCOL_MISMATCH: enrollment response size"
    );
    let mut bytes = vec![0u8; length];
    exact(stream, &mut bytes, &mut fds, deadline)?;
    let mut trailing = [0u8; 1];
    ensure!(
        receive_bytes(stream, &mut trailing, &mut fds, deadline)? == 0,
        "PROTOCOL_MISMATCH: extra enrollment response"
    );
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("PROTOCOL_MISMATCH: enrollment response"))?;
    if value == json!({"version":1,"ok":false,"code":"REFUSED"}) && fds.is_empty() {
        bail!("FORBIDDEN: enrollment stage refused");
    }
    let header: Header = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("PROTOCOL_MISMATCH: enrollment response"))?;
    ensure!(
        header.version == 1
            && header.ok
            && header.request_id == id
            && header.stage_sha256 == digest
            && header.source_uid == uid
            && header
                .files
                .iter()
                .map(String::as_str)
                .eq(FILES.iter().map(|(name, _)| *name))
            && fds.len() == FILES.len(),
        "PROTOCOL_MISMATCH: enrollment binding"
    );
    let mut identities = HashSet::new();
    let mut contents = Vec::with_capacity(FILES.len());
    for (fd, (_, limit)) in fds.into_iter().zip(FILES) {
        let mut file = File::from(fd);
        let before = file.metadata()?;
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        let descriptor_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        ensure!(
            flags >= 0
                && flags & libc::O_ACCMODE == libc::O_RDONLY
                && flags & libc::O_PATH == 0
                && before.is_file()
                && before.uid() == uid
                && before.mode() & 0o7777 == 0o600
                && before.nlink() == 1
                && before.len() <= limit
                && descriptor_flags >= 0
                && descriptor_flags & libc::FD_CLOEXEC != 0
                && identities.insert((before.dev(), before.ino())),
            "FORBIDDEN: enrollment descriptor"
        );
        let mut content = Secret(Vec::new());
        Read::by_ref(&mut file)
            .take(limit + 1)
            .read_to_end(&mut content.0)?;
        ensure!(
            content.0.len() as u64 == before.len()
                && identity(&file.metadata()?) == identity(&before),
            "CONFLICT: enrollment descriptor changed"
        );
        contents.push(content);
    }
    Ok(Snapshot(contents))
}
