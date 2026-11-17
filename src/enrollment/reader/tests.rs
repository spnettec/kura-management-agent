use super::*;
use std::{fs::OpenOptions, os::unix::fs::PermissionsExt};

const ID: &str = "10000000-0000-4000-8000-000000000001";
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    root: std::path::PathBuf,
    files: Vec<File>,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("agent-reader-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let files = FILES
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let path = root.join(index.to_string());
                fs::write(&path, format!("synthetic file {index}")).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                File::open(path).unwrap()
            })
            .collect();
        Self { root, files }
    }

    fn header(&self) -> serde_json::Value {
        json!({"version":1,"ok":true,"requestId":ID,"stageSha256":DIGEST,
               "sourceUid":unsafe {libc::geteuid()},
               "files":FILES.iter().map(|(name,_)| *name).collect::<Vec<_>>()})
    }

    fn fds(&self) -> Vec<libc::c_int> {
        self.files.iter().map(AsRawFd::as_raw_fd).collect()
    }

    fn open_count(&self) -> usize {
        fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
            .filter(|path| path.starts_with(&self.root))
            .count()
    }

    fn response(&self, bytes: &[u8], fds: &[libc::c_int], fragmented: bool) -> Result<Snapshot> {
        self.response_as(bytes, fds, fragmented, unsafe { libc::geteuid() })
    }

    fn response_as(
        &self,
        bytes: &[u8],
        fds: &[libc::c_int],
        fragmented: bool,
        uid: u32,
    ) -> Result<Snapshot> {
        let before = self.open_count();
        let (mut consumer, mut publisher) = UnixStream::pair().unwrap();
        if fragmented {
            send(&publisher, &bytes[..1], fds);
            publisher.write_all(&bytes[1..]).unwrap();
        } else {
            send(&publisher, bytes, fds);
        }
        drop(publisher);
        let result = receive(&mut consumer, ID, DIGEST, uid);
        assert_eq!(
            self.open_count(),
            before,
            "received descriptors must close on success and every failure"
        );
        result
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn frame(value: &serde_json::Value) -> Vec<u8> {
    frame_bytes(&serde_json::to_vec(value).unwrap())
}
fn frame_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(bytes);
    frame
}

fn send(socket: &UnixStream, bytes: &[u8], fds: &[libc::c_int]) {
    if fds.is_empty() {
        (&*socket).write_all(bytes).unwrap();
        return;
    }
    let mut vector = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let size = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as _) } as usize;
    let mut control = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as _) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(header).cast(), fds.len());
        assert_eq!(
            libc::sendmsg(socket.as_raw_fd(), &message, 0),
            bytes.len() as isize
        );
    }
}

#[test]
fn reads_fragmented_readonly_descriptors_and_closes_every_received_fd() {
    let fixture = Fixture::new();
    let result = fixture
        .response(&frame(&fixture.header()), &fixture.fds(), true)
        .unwrap();
    for (index, (name, _)) in FILES.iter().enumerate() {
        assert_eq!(
            result.bytes(name).unwrap(),
            format!("synthetic file {index}").as_bytes()
        );
    }
    assert!(result.bytes("../private.pk8").is_err());
}

#[test]
fn refuses_missing_duplicate_extra_and_truncated_rights_without_leaks() {
    let fixture = Fixture::new();
    let valid = frame(&fixture.header());
    let fds = fixture.fds();
    assert!(fixture.response(&valid, &[], false).is_err());
    assert!(fixture.response(&valid, &fds[..9], false).is_err());
    let mut duplicate = fds.clone();
    duplicate[1] = duplicate[0];
    assert!(fixture.response(&valid, &duplicate, false).is_err());
    for count in [11, 20] {
        let extra = (0..count).map(|i| fds[i % fds.len()]).collect::<Vec<_>>();
        assert!(fixture.response(&valid, &extra, false).is_err());
    }
}

#[test]
fn refuses_writable_directory_linked_large_and_loose_descriptors() {
    let fixture = Fixture::new();
    let valid = frame(&fixture.header());
    let mut fds = fixture.fds();
    let writable = OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.root.join("0"))
        .unwrap();
    fds[0] = writable.as_raw_fd();
    assert!(fixture.response(&valid, &fds, false).is_err());
    let directory = File::open(&fixture.root).unwrap();
    fds[0] = directory.as_raw_fd();
    assert!(fixture.response(&valid, &fds, false).is_err());
    fds[0] = fixture.files[0].as_raw_fd();
    fs::hard_link(fixture.root.join("0"), fixture.root.join("linked")).unwrap();
    assert!(fixture.response(&valid, &fds, false).is_err());
    fs::remove_file(fixture.root.join("linked")).unwrap();
    fs::set_permissions(fixture.root.join("0"), fs::Permissions::from_mode(0o640)).unwrap();
    assert!(fixture.response(&valid, &fds, false).is_err());
    fs::set_permissions(fixture.root.join("0"), fs::Permissions::from_mode(0o600)).unwrap();
    writable.set_len(16385).unwrap();
    assert!(fixture.response(&valid, &fds, false).is_err());
}

#[test]
fn descriptor_uid_is_checked_independently_of_the_response_header() {
    let fixture = Fixture::new();
    let uid = unsafe { libc::geteuid() } + 1;
    let mut header = fixture.header();
    header["sourceUid"] = json!(uid);
    assert!(
        fixture
            .response_as(&frame(&header), &fixture.fds(), false, uid)
            .is_err()
    );
}

#[test]
fn refuses_wrong_binding_labels_unknown_and_duplicate_json_fields() {
    let fixture = Fixture::new();
    for key in [
        "version",
        "ok",
        "requestId",
        "stageSha256",
        "sourceUid",
        "files",
        "path",
    ] {
        let mut header = fixture.header();
        header[key] = match key {
            "version" => json!(2),
            "ok" => json!(false),
            "requestId" => json!("20000000-0000-4000-8000-000000000002"),
            "stageSha256" => json!("b".repeat(64)),
            "sourceUid" => json!(unsafe { libc::geteuid() } + 1),
            "files" => json!(["private.pk8"]),
            _ => json!("/etc/shadow"),
        };
        assert!(
            fixture
                .response(&frame(&header), &fixture.fds(), false)
                .is_err(),
            "{key}"
        );
    }
    let raw = serde_json::to_string(&fixture.header()).unwrap();
    let duplicate = format!("{{\"ok\":true,{}", &raw[1..]);
    assert!(
        fixture
            .response(&frame_bytes(duplicate.as_bytes()), &fixture.fds(), false)
            .is_err()
    );
    let mut header = fixture.header();
    header["files"].as_array_mut().unwrap().swap(0, 1);
    assert!(
        fixture
            .response(&frame(&header), &fixture.fds(), false)
            .is_err()
    );
}

#[test]
fn refuses_malformed_partial_extra_and_oversized_frames() {
    let fixture = Fixture::new();
    for bytes in [
        vec![0, 0],
        0u32.to_be_bytes().to_vec(),
        4097u32.to_be_bytes().to_vec(),
        frame_bytes(b"{"),
        frame_bytes(b"[1]"),
    ] {
        assert!(fixture.response(&bytes, &fixture.fds(), false).is_err());
    }
    let mut bytes = frame(&fixture.header());
    bytes.pop();
    assert!(fixture.response(&bytes, &fixture.fds(), false).is_err());
    let mut bytes = frame(&fixture.header());
    bytes.push(b'\n');
    assert!(fixture.response(&bytes, &fixture.fds(), false).is_err());
    let refused = frame(&json!({"version":1,"ok":false,"code":"REFUSED"}));
    assert!(
        format!("{}", fixture.response(&refused, &[], false).err().unwrap())
            .starts_with("FORBIDDEN:")
    );
    assert!(fixture.response(&refused, &fixture.fds(), false).is_err());
}

#[test]
fn receives_late_rights_and_rejects_rights_on_an_extra_frame() {
    let fixture = Fixture::new();
    let bytes = frame(&fixture.header());
    for extra in [false, true] {
        let before = fixture.open_count();
        let (mut consumer, mut publisher) = UnixStream::pair().unwrap();
        publisher.write_all(&bytes[..4]).unwrap();
        send(&publisher, &bytes[4..], &fixture.fds());
        if extra {
            send(&publisher, b"x", &fixture.fds());
        }
        drop(publisher);
        assert_eq!(
            receive(&mut consumer, ID, DIGEST, unsafe { libc::geteuid() }).is_err(),
            extra
        );
        assert_eq!(fixture.open_count(), before);
    }
}

// Explicitly selected only in a disposable Root Linux container. These fixed
// native paths must never be created on a developer's host or a running gateway.
#[test]
#[ignore = "requires a disposable Root Linux container with NET_ADMIN and setpriv"]
fn cross_uid_native_store_uses_readonly_publisher() {
    use std::{
        os::fd::OwnedFd,
        os::unix::net::UnixListener,
        process::{Command, Stdio},
    };
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let source = Path::new("/run/kura-enrollment-stage-input");
    assert!(!source.try_exists().unwrap() && !Path::new(SOCKET).try_exists().unwrap());
    let (store, input) = crate::enrollment::tests::fixture();
    let fixture_root = store.root.parent().unwrap().to_path_buf();
    struct Cleanup(Vec<std::path::PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for path in &self.0 {
                if path.is_dir() {
                    let _ = fs::remove_dir_all(path);
                } else {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }
    let mut cleanup = Cleanup(vec![fixture_root]);
    fs::rename(store.grant.unwrap(), source).unwrap();
    cleanup.0.push(source.to_path_buf());
    fn source_identity(path: &Path) -> Vec<(std::path::PathBuf, String, Vec<u64>)> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut rows = Vec::new();
        for entry in fs::read_dir(path).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                rows.extend(source_identity(&p));
            } else {
                let mut bytes = Vec::new();
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOATIME | libc::O_NOFOLLOW)
                    .open(&p)
                    .unwrap()
                    .read_to_end(&mut bytes)
                    .unwrap();
                let m = p.symlink_metadata().unwrap();
                rows.push((
                    p,
                    crate::durable::hash(&bytes),
                    vec![
                        m.dev(),
                        m.ino(),
                        m.uid() as _,
                        m.gid() as _,
                        m.mode() as _,
                        m.nlink(),
                        m.len(),
                        m.atime() as _,
                        m.atime_nsec() as _,
                        m.mtime() as _,
                        m.mtime_nsec() as _,
                        m.ctime() as _,
                        m.ctime_nsec() as _,
                    ],
                ));
            }
        }
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }
    fn own(path: &Path) {
        std::os::unix::fs::chown(path, Some(997), Some(997)).unwrap();
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                own(&entry.unwrap().path());
            }
        }
    }
    own(source);
    let before = source_identity(source);
    let listener = UnixListener::bind(SOCKET).unwrap();
    cleanup.0.push(SOCKET.into());
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let publisher = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("isolated reader accept: {e}"),
            }
        };
        let output = Command::new("setpriv")
            .args([
                "--reuid=997",
                "--regid=997",
                "--clear-groups",
                "--bounding-set=-all",
                "--no-new-privs",
                "/usr/bin/python3",
                "-I",
            ])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/packaging/enrollment_reader.py"
            ))
            .stdin(Stdio::from(OwnedFd::from(stream)))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "publisher failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    });
    let child = Command::new("setpriv")
        .args([
            "--bounding-set=-all,+net_admin",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
        ])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "enrollment::reader::native::tests::cross_uid_consumer",
            "--ignored",
            "--nocapture",
        ])
        .env("KURA_READER_TEST_STATE", &store.root)
        .env("KURA_READER_TEST_ID", &input.request_id)
        .env("KURA_READER_TEST_DIGEST", &input.expected_stage_sha256)
        .output()
        .unwrap();
    publisher.join().unwrap();
    assert!(
        child.status.success(),
        "consumer failed: {} {}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    assert_eq!(
        source_identity(source),
        before,
        "publisher and agent must preserve every source file"
    );
}

#[test]
#[ignore = "child of the isolated cross-UID native-store test only"]
fn cross_uid_consumer() {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    assert!(
        status
            .lines()
            .any(|line| line == "CapEff:\t0000000000001000")
    );
    assert!(
        status
            .lines()
            .any(|line| line == "CapBnd:\t0000000000001000")
    );
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
    let id = std::env::var("KURA_READER_TEST_ID").unwrap();
    let digest = std::env::var("KURA_READER_TEST_DIGEST").unwrap();
    let path = Path::new("/run/kura-enrollment-stage-input")
        .join(&id)
        .join("private.pk8");
    assert_eq!(
        fs::read(path).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(snapshot(Transport::RootPublisher, &id, &digest, 997).is_err());
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o600)).unwrap();
    let store = crate::enrollment::Store {
        root: std::env::var_os("KURA_READER_TEST_STATE").unwrap().into(),
        grant: Some(SOURCE.into()),
        kura_uid: 997,
        native_reader: Some(Transport::RootPublisher),
    };
    let input = crate::enrollment::BindInput {
        expected_revision: "unused".into(),
        request_id: id,
        expected_stage_sha256: digest,
        operator: "isolated-test".into(),
    };
    let candidate = store.prepare(&input, "isolated-root-agent".into()).unwrap();
    assert_eq!(candidate.receipt.source_uid, 997);
    assert_eq!(candidate.receipt.material.gateway_id, "enrollment-test");
    assert!(!store.pointer().exists() && !store.pending().exists());
    let key = candidate
        .path
        .join("private.pk8")
        .symlink_metadata()
        .unwrap();
    assert_eq!(key.uid(), 0);
    assert_eq!(key.mode() & 0o7777, 0o600);
}
