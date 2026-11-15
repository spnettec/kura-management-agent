//! Bind each busctl connection to the actual authentication server GUID.
//! org.freedesktop.DBus.GetId is a different, logical bus identifier.
use super::*;

fn socket_path(address: Option<&str>) -> Result<&str> {
    let path = address.unwrap_or("unix:path=/run/dbus/system_bus_socket")
        .strip_prefix("unix:path=")
        .context("UNSUPPORTED: fixed local NM bus address required")?;
    ensure!(
        path.starts_with('/') && path.len() < 108
            && path.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b)),
        "UNSUPPORTED: fixed local NM bus socket path required"
    );
    Ok(path)
}

pub(super) fn pinned_address(address: Option<&str>, guid: &str) -> Result<String> {
    ensure!(guid.len() == 32 && guid.bytes().all(|b| b.is_ascii_hexdigit()), "CONFLICT: NM authentication GUID");
    Ok(format!("unix:path={},guid={guid}", socket_path(address)?))
}

pub(super) fn probe(address: Option<&str>, deadline: Instant) -> Result<String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (address, deadline);
        anyhow::bail!("UNSUPPORTED: NM bus authentication requires Linux")
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::{Read, Write};
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::net::UnixStream;

        let path = socket_path(address)?.as_bytes();
        let deadline = deadline.min(Instant::now() + Duration::from_secs(2));
        let remaining = || deadline.checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero()).context("TIMEOUT: NM bus authentication deadline");
        let raw = unsafe {libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0)};
        ensure!(raw >= 0, "UNSUPPORTED: NM authentication socket unavailable");
        // The descriptor is owned exactly once from this point onward.
        let fd = unsafe {OwnedFd::from_raw_fd(raw)};
        let mut target: libc::sockaddr_un = unsafe {std::mem::zeroed()};
        target.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (slot, byte) in target.sun_path.iter_mut().zip(path) { *slot = *byte as libc::c_char; }
        let length = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1) as libc::socklen_t;
        let connected = unsafe {libc::connect(fd.as_raw_fd(), (&target as *const libc::sockaddr_un).cast(), length)};
        if connected != 0 {
            let error = std::io::Error::last_os_error();
            ensure!(error.raw_os_error() == Some(libc::EINPROGRESS), "UNSUPPORTED: NM authentication socket connection failed");
            loop {
                let mut poll = libc::pollfd {fd:fd.as_raw_fd(),events:libc::POLLOUT,revents:0};
                let ready = unsafe {libc::poll(&mut poll, 1, remaining()?.as_millis().clamp(1, i32::MAX as u128) as i32)};
                if ready < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) { continue; }
                ensure!(ready > 0, "TIMEOUT: NM authentication socket connection");
                let mut error: libc::c_int = 0;
                let mut size = std::mem::size_of_val(&error) as libc::socklen_t;
                let result = unsafe {libc::getsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_ERROR, (&mut error as *mut libc::c_int).cast(), &mut size)};
                ensure!(result == 0 && error == 0, "UNSUPPORTED: NM authentication socket connection failed");
                break;
            }
        }
        let mut stream = UnixStream::from(fd);
        stream.set_nonblocking(false)?;
        stream.set_write_timeout(Some(remaining()?))?;
        let uid = unsafe {libc::geteuid()}.to_string();
        let external: String = uid.bytes().map(|b| format!("{b:02x}")).collect();
        stream.write_all(format!("\0AUTH EXTERNAL {external}\r\n").as_bytes())?;
        let mut line = Vec::new();
        loop {
            ensure!(line.len() < 128, "CONFLICT: NM authentication response limit");
            stream.set_read_timeout(Some(remaining()?))?;
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).context("UNSUPPORTED: NM authentication response unavailable")?;
            line.push(byte[0]);
            if line.ends_with(b"\r\n") { break; }
        }
        let line = std::str::from_utf8(&line)?;
        let guid = line.strip_prefix("OK ").and_then(|s| s.strip_suffix("\r\n"))
            .context("UNSUPPORTED: NM EXTERNAL authentication rejected")?;
        ensure!(guid.len() == 32 && guid.bytes().all(|b| b.is_ascii_hexdigit()), "CONFLICT: NM authentication GUID");
        // No BEGIN or method is sent on this discovery connection.
        Ok(guid.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authentication_guid_is_pinned_without_substituting_the_logical_bus_id() {
        let server = "c".repeat(32);
        assert_eq!(pinned_address(Some("unix:path=/tmp/nm-proof/bus"), &server).unwrap(),
            format!("unix:path=/tmp/nm-proof/bus,guid={server}"));
        assert!(pinned_address(None, "bad,guid=other").is_err());
        assert!(pinned_address(Some("unix:path=/tmp/bus;unix:path=/other"), &server).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a newly created private D-Bus fixture address; no system bus"]
    fn private_guid_handshake_and_wrong_guid_rejection() {
        let address = std::env::var("YOFC_NM_PRIVATE_BUS_ADDRESS").expect("explicit private bus fixture required");
        ensure_private_test_address(&address);
        let wire = Busctl {address:Some(address.clone())};
        let deadline = Instant::now() + Duration::from_secs(20);
        let guid = probe(Some(&address),deadline).unwrap();
        let mut call = BusCall {destination:DBUS.into(),path:BUS_PATH.into(),interface:DBUS.into(),
            method:"GetId".into(),arguments:vec![],expected_server_guid:Some(guid.clone())};
        let result = fields(wire.call(&call,deadline).unwrap(),"s",1).unwrap();
        let logical = string(&result[0]).unwrap();
        let mut wrong = guid.clone().into_bytes();wrong[0] = if wrong[0] == b'0' {b'1'} else {b'0'};
        call.expected_server_guid = Some(String::from_utf8(wrong).unwrap());
        assert!(wire.call(&call,deadline).is_err());
        call.expected_server_guid = Some(guid.clone());
        assert_eq!(fields(wire.call(&call,deadline).unwrap(),"s",1).unwrap()[0],logical);
        println!("{}",json!({"authenticationServerGuid":guid,"logicalBusId":logical,
            "wrongGuidRejected":true,"correctGuidBeforeAndAfterPassed":true,"systemBusUsed":false}));
    }

    #[cfg(target_os = "linux")]
    fn ensure_private_test_address(address: &str) {
        assert!(address.starts_with("unix:path=/proof/private-bus/"), "new owned fixture required");
    }
}
