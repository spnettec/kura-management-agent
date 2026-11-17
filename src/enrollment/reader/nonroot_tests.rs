//! Explicit disposable-container interop, not an installed package/systemd test.
use super::*;
use std::{
    collections::BTreeMap,
    os::{
        fd::OwnedFd,
        unix::{fs::PermissionsExt, net::UnixListener},
    },
    process::{Command, Stdio},
};

const CHILD: &str = "enrollment::reader::native::nonroot_tests::dedicated_native_consumer";

#[test]
#[ignore = "explicit disposable Root Linux container only"]
fn dedicated_native_store_receives_the_root_relay() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_eq!(
        std::env::var("KURA_NATIVE_PROFILE_DISPOSABLE").as_deref(),
        Ok("1")
    );
    let input = Path::new("/run/kura-enrollment-stage-input");
    let grant_file = Path::new("/run/kura-enrollment-relay-grant.json");
    let public = Path::new(crate::runtime_identity::READER_SOCKET);
    let state = Path::new(crate::runtime_identity::STATE);
    let identity = Path::new(crate::runtime_identity::IDENTITY);
    let unit = Path::new(crate::runtime_identity::UNIT);
    let program = Path::new("/usr/bin/yofc-management-agent");
    let manifest = Path::new("/usr/share/kura-management-agent/source-manifest.json");
    for path in [
        input,
        grant_file,
        public,
        state,
        identity.parent().unwrap(),
        unit,
        program,
        manifest.parent().unwrap(),
        Path::new(SOCKET),
    ] {
        assert!(
            !path.try_exists().unwrap(),
            "fixture refuses retained native paths: {}",
            path.display()
        );
    }
    struct Cleanup(Vec<std::path::PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for path in self.0.iter().rev() {
                if path.is_dir() {
                    let _ = fs::remove_dir_all(path);
                } else {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }
    let mut cleanup = Cleanup(Vec::new());
    let (original, request) = crate::enrollment::tests::fixture();
    cleanup.0.push(original.root.parent().unwrap().into());
    fs::rename(original.grant.unwrap(), input).unwrap();
    cleanup.0.push(input.into());
    fn own(path: &Path) {
        std::os::unix::fs::chown(path, Some(997), Some(997)).unwrap();
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                own(&entry.unwrap().path());
            }
        }
    }
    own(input);
    let hashes = |path: &Path| -> BTreeMap<String, String> {
        fn visit(root: &Path, path: &Path, rows: &mut BTreeMap<String, String>) {
            use std::os::unix::fs::OpenOptionsExt;
            for entry in fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    visit(root, &path, rows);
                } else {
                    let mut bytes = Vec::new();
                    fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOATIME)
                        .open(&path)
                        .unwrap()
                        .read_to_end(&mut bytes)
                        .unwrap();
                    let m = path.symlink_metadata().unwrap();
                    rows.insert(
                        path.strip_prefix(root)
                            .unwrap()
                            .to_string_lossy()
                            .into_owned(),
                        format!(
                            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
                            crate::durable::hash(&bytes),
                            m.dev(),
                            m.ino(),
                            m.uid(),
                            m.gid(),
                            m.mode(),
                            m.nlink(),
                            m.len(),
                            m.atime(),
                            m.atime_nsec(),
                            m.mtime(),
                            m.mtime_nsec(),
                            m.ctime(),
                            m.ctime_nsec()
                        ),
                    );
                }
            }
        }
        let mut rows = BTreeMap::new();
        visit(path, path, &mut rows);
        rows
    };
    let before = hashes(input);
    let write = |path: &Path, bytes: &[u8], mode: u32| {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    };
    fs::create_dir(state).unwrap();
    cleanup.0.push(state.into());
    fs::set_permissions(state, fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::chown(state, Some(995), Some(993)).unwrap();
    fs::create_dir(identity.parent().unwrap()).unwrap();
    cleanup.0.push(identity.parent().unwrap().into());
    fs::create_dir_all(unit.parent().unwrap()).unwrap();
    write(
        unit,
        include_bytes!("../../../packaging/kura-management-agent-v2.service"),
        0o644,
    );
    cleanup.0.push(unit.into());
    fs::copy(std::env::current_exe().unwrap(), program).unwrap();
    fs::set_permissions(program, fs::Permissions::from_mode(0o755)).unwrap();
    cleanup.0.push(program.into());
    fs::create_dir(manifest.parent().unwrap()).unwrap();
    cleanup.0.push(manifest.parent().unwrap().into());
    // Deliberately a filesystem provenance fixture; no real package/source
    // acceptance is inferred from this test manifest.
    write(
        manifest,
        b"{\"schemaVersion\":2,\"fixtureOnly\":true}",
        0o644,
    );
    let digest = |path: &Path| {
        use sha2::{Digest, Sha256};
        let mut file = File::open(path).unwrap();
        let mut digest = Sha256::new();
        let mut bytes = [0u8; 65536];
        loop {
            let n = file.read(&mut bytes).unwrap();
            if n == 0 {
                break;
            }
            digest.update(&bytes[..n]);
        }
        format!("{:x}", digest.finalize())
    };
    write(identity, &serde_json::to_vec(&json!({"schemaVersion":1,"profile":"native-nonroot-v1", "user":"kura-management-agent",
        "uid":995,"gid":993,"readerGid":994,"stateDirectory":state,"socket":crate::runtime_identity::SOCKET,
        "unitSha256":digest(unit),"binarySha256":digest(program),"sourceManifestSha256":digest(manifest)})).unwrap(), 0o644);
    write(
        grant_file,
        &serde_json::to_vec(
            &json!({"schemaVersion":1,"requestId":uuid::Uuid::new_v4().to_string(),
        "agentUid":995,"agentGid":993,"readerGid":994,"sourceUid":997,"sourceRoot":SOURCE,
        "upstreamSocket":SOCKET,"socket":public,"publisherPairSha256":"a".repeat(64),
        "relayPairSha256":"b".repeat(64),"operator":"isolated-test"}),
        )
        .unwrap(),
        0o600,
    );
    cleanup.0.push(grant_file.into());
    fn listen(path: &Path, gid: u32, mode: u32) -> UnixListener {
        let listener = UnixListener::bind(path).unwrap();
        std::os::unix::fs::chown(path, Some(0), Some(gid)).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        listener.set_nonblocking(true).unwrap();
        listener
    }
    fn worker(listener: UnixListener, publisher: bool) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("isolated native accept: {e}"),
                }
            };
            let mut command = Command::new("setpriv");
            if publisher {
                command.args(["--reuid=997", "--regid=997", "--clear-groups"]);
            }
            command.args([
                "--bounding-set=-all",
                "--no-new-privs",
                "/usr/bin/python3",
                "-I",
            ]);
            command.arg(if publisher {
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/packaging/enrollment_reader.py"
                )
            } else {
                concat!(env!("CARGO_MANIFEST_DIR"), "/packaging/enrollment_relay.py")
            });
            let result = command
                .stdin(Stdio::from(OwnedFd::from(socket)))
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "isolated FD worker failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        })
    }
    let publisher = worker(listen(Path::new(SOCKET), 0, 0o600), true);
    cleanup.0.push(SOCKET.into());
    let relay = worker(listen(public, 994, 0o660), false);
    cleanup.0.push(public.into());
    let output = Command::new("setpriv")
        .args([
            "--reuid=995",
            "--regid=993",
            "--groups=994",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
        ])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", CHILD, "--ignored", "--nocapture"])
        .env("KURA_NATIVE_PROFILE_DISPOSABLE", "1")
        .env("KURA_READER_TEST_ID", &request.request_id)
        .env("KURA_READER_TEST_DIGEST", &request.expected_stage_sha256)
        .output()
        .unwrap();
    publisher.join().unwrap();
    relay.join().unwrap();
    assert!(
        output.status.success(),
        "native consumer failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        hashes(input),
        before,
        "both relays and the consumer preserve the source"
    );
}

#[tokio::test]
#[ignore = "child of the disposable native relay fixture only"]
async fn dedicated_native_consumer() {
    assert_eq!(
        std::env::var("KURA_NATIVE_PROFILE_DISPOSABLE").as_deref(),
        Ok("1")
    );
    assert_eq!(unsafe { libc::geteuid() }, 995);
    let state = Path::new(crate::runtime_identity::STATE);
    let status = fs::read_to_string("/proc/self/status").unwrap();
    for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        assert!(
            status
                .lines()
                .any(|line| line == format!("{key}:\t0000000000000000"))
        );
    }
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
    let id = std::env::var("KURA_READER_TEST_ID").unwrap();
    let digest = std::env::var("KURA_READER_TEST_DIGEST").unwrap();
    assert_eq!(
        fs::read(
            Path::new("/run/kura-enrollment-stage-input")
                .join(&id)
                .join("private.pk8")
        )
        .unwrap_err()
        .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    crate::secure::prepare_state(&state.join("results.sqlite")).unwrap();
    let db = crate::transport::database(state.join("results.sqlite").to_str().unwrap())
        .await
        .unwrap();
    let enrollment = crate::enrollment::Enrollment::open_with_reader(
        state.into(),
        None,
        Some(SOURCE.into()),
        Some(crate::runtime_identity::READER_SOCKET.into()),
        997,
        db,
        "isolated-boot".into(),
    )
    .unwrap();
    let candidate = enrollment
        .store
        .prepare(
            &crate::enrollment::BindInput {
                expected_revision: "unused".into(),
                request_id: id,
                expected_stage_sha256: digest,
                operator: "isolated-test".into(),
            },
            "isolated-local-actor".into(),
        )
        .unwrap();
    assert_eq!(candidate.receipt.source_uid, 997);
    let key = candidate
        .path
        .join("private.pk8")
        .symlink_metadata()
        .unwrap();
    assert_eq!(key.uid(), 995);
    assert_eq!(key.mode() & 0o7777, 0o600);
    assert!(!enrollment.store.pointer().exists() && !enrollment.store.pending().exists());
}
