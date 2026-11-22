use super::*;
use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    thread,
};

#[test]
fn binding_is_canonical_and_rejects_unknown_protocols_and_digests() {
    let mut binding = Binding {
        schema: 1,
        purpose: PURPOSE.into(),
        active_key_sha256: "1".repeat(64),
        ring_sha256: None,
        cohort_sha256: "2".repeat(64),
    };
    let raw = format!(
        "{{\"activeKeySha256\":\"{}\",\"cohortSha256\":\"{}\",\"purpose\":\"{}\",\"ringSha256\":null,\"schema\":1}}",
        "1".repeat(64),
        "2".repeat(64),
        PURPOSE
    );
    assert_eq!(durable::hash(raw.as_bytes()), binding.hash().unwrap());
    binding.ring_sha256 = Some("bad".into());
    assert!(binding.hash().is_err());
    binding.ring_sha256 = None;
    binding.schema = 2;
    assert!(binding.hash().is_err());
}

#[test]
fn socket_transfers_one_readonly_snapshot_fd_with_no_path_or_key() {
    let root = Path::new("/tmp").join(format!("ycv-fd-{}", uuid::Uuid::new_v4()));
    durable::directory(&root).unwrap();
    let path = root.join("snapshot");
    fs::write(&path, b"only a disposable snapshot").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .unwrap();
    let socket = root.join("control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut bytes = [0u8; 4096];
        let mut vector = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let mut control = [0usize; 16];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control) as _;
        let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, 0) };
        assert!(received >= 4);
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        assert!(!header.is_null());
        let descriptor = unsafe {
            assert_eq!((*header).cmsg_level, libc::SOL_SOCKET);
            assert_eq!((*header).cmsg_type, libc::SCM_RIGHTS);
            assert_eq!((*header).cmsg_len as usize, libc::CMSG_LEN(4) as usize);
            assert!(libc::CMSG_NXTHDR(&message, header).is_null());
            std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>())
        };
        use std::os::fd::FromRawFd;
        let mut received_file = unsafe { File::from_raw_fd(descriptor) };
        assert_eq!(
            unsafe { libc::fcntl(descriptor, libc::F_GETFL) } & libc::O_ACCMODE,
            libc::O_RDONLY
        );
        let mut snapshot = String::new();
        received_file.read_to_string(&mut snapshot).unwrap();
        assert_eq!(snapshot, "only a disposable snapshot");
        let size = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        let mut payload = bytes[4..received as usize].to_vec();
        if payload.len() < size {
            let old = payload.len();
            payload.resize(size, 0);
            stream.read_exact(&mut payload[old..]).unwrap();
        }
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&payload).unwrap(),
            serde_json::json!({"schema":1,"action":"core-snapshot-validate"})
        );
        assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
        stream.write_all(&[0, 0, 0, 2, b'{', b'}']).unwrap();
    });
    assert_eq!(
        request_at(
            &socket,
            unsafe { libc::geteuid() },
            &serde_json::json!({"schema":1,"action":"core-snapshot-validate"}),
            Some(&input)
        )
        .unwrap(),
        b"{}"
    );
    server.join().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn socket_refuses_untrusted_peer_and_trailing_or_oversized_responses() {
    for case in 0..3 {
        let root = Path::new("/tmp").join(format!("ycv-peer-{}", uuid::Uuid::new_v4()));
        durable::directory(&root).unwrap();
        let socket = root.join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            if case == 0 {
                return;
            }
            let mut input = Vec::new();
            stream.read_to_end(&mut input).unwrap();
            stream
                .write_all(if case == 1 {
                    &[0, 1, 0, 1]
                } else {
                    &[0, 0, 0, 2, b'{', b'}', b'x']
                })
                .unwrap();
        });
        let owner = unsafe { libc::geteuid() } + if case == 0 { 1 } else { 0 };
        assert!(request_at(&socket, owner, &serde_json::json!({"schema":1}), None).is_err());
        server.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "Only the guarded disposable systemd fixture may run this test"]
fn core_snapshot_fd_bridge_under_real_systemd() {
    use crate::snapshot_validation::Validator;
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        std::env::var("YOFC_DISPOSABLE_CORE_VALIDATION").as_deref(),
        Ok("1")
    );
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert!(fs::read("/etc/kura/credentials/kura_encryption_key").is_err());
    assert!(fs::read("/var/lib/kura-key-service/journal.key").is_err());
    let validator = Validator::new("/fixtures/core-validation/validator.json".into()).unwrap();
    // Loading the configuration itself did not contact Core or make agent startup depend on it.
    for name in ["plain.xml", "current.aes", "old.aes"] {
        let snapshot = Path::new("/fixtures/core-validation").join(name);
        assert_ne!(fs::metadata(&snapshot).unwrap().uid(), unsafe {
            libc::geteuid()
        });
        let config = Path::new("/fixtures/core-validation/validator.json");
        let policy = serde_json::json!({"schema":2,"mode":if name=="plain.xml" {"plain"} else {"aes-gcm"},
            "passwordPolicy":"authenticated","key":{"kind":"core"}});
        durable::json(config, &policy).unwrap();
        let sha = durable::hash(&fs::read(&snapshot).unwrap());
        let proof = validator.validate(&snapshot, &sha, None).unwrap();
        validator.validate(&snapshot, &sha, Some(&proof)).unwrap();
        let parameters = validator.startup_parameters(&proof).unwrap();
        assert!(
            parameters
                .iter()
                .any(|(k, v)| k == "crypto.systemd.credentials" && v == "true")
        );
        assert!(
            parameters
                .iter()
                .all(|(k, _)| k != "crypto.key.file" && k != "crypto.default")
        );
        assert!(
            validator
                .validate(&snapshot, &"0".repeat(64), Some(&proof))
                .is_err()
        );
    }
    let raw = request_at(
        Path::new(SOCKET),
        0,
        &serde_json::json!({"schema":1,"action":"backup-create"}),
        None,
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&raw).unwrap(),
        serde_json::json!({"schema":1,"error":"FORBIDDEN"})
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "Only the guarded disposable systemd fixture may run this test"]
fn core_validator_startup_without_root_service() {
    assert_eq!(
        std::env::var("YOFC_DISPOSABLE_CORE_VALIDATION").as_deref(),
        Ok("1")
    );
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert!(fs::read("/etc/kura/credentials/kura_encryption_key").is_err());
    assert!(fs::read("/var/lib/kura-key-service/journal.key").is_err());
    crate::snapshot_validation::Validator::new("/fixtures/core-validation/validator.json".into())
        .unwrap();
}
#[test]
fn snapshot_inventory_rejects_duplicate_paths_links_and_foreign_owners() {
    let directory =
        serde_json::json!({"device":"2097","inode":"11","mode":448,"uid":997,"gid":997});
    let record = serde_json::json!({"name":"snapshot_1.xml","size":7,"sha256":"f".repeat(64),
        "metadata":{"mode":384,"uid":997,"gid":997}});
    let raw = |files| {
        serde_json::json!({"schema":1,"directory":directory,
        "retainedDirectoryPresent":false,"files":files})
    };
    let single: Inventory = serde_json::from_value(raw(vec![record.clone()])).unwrap();
    assert!(single.verify().is_ok());
    let duplicate: Inventory =
        serde_json::from_value(raw(vec![record.clone(), record.clone()])).unwrap();
    assert!(duplicate.verify().is_err());
    for (key, value) in [
        ("name", serde_json::json!("../outside")),
        (
            "metadata",
            serde_json::json!({"mode":384,"uid":998,"gid":997}),
        ),
        ("sha256", serde_json::json!("not-a-digest")),
    ] {
        let mut changed = record.clone();
        changed[key] = value;
        let inventory: Inventory = serde_json::from_value(raw(vec![changed])).unwrap();
        assert!(inventory.verify().is_err());
    }
}

#[test]
fn delegated_stage_refuses_foreign_receipts_and_preserves_unknown() {
    let id = "rec-11111111-1111-4111-8111-111111111111";
    let mut value = serde_json::json!({"schema":1,"state":"RECOVERY_INPUT_ATTEMPTED","restoreId":id,
        "root":{"device":"2097","inode":"1"}});
    let raw = |value: &serde_json::Value| serde_json::to_vec(value).unwrap();
    assert!(restore_id(id));
    assert!(!restore_id("rec-11111111111141118111111111111111"));
    assert_eq!(delegated_result(id, &raw(&value)).unwrap(), value);
    assert_eq!(
        delegated_result("rec-22222222-2222-4222-8222-222222222222", &raw(&value)),
        Err("UNKNOWN")
    );
    value["path"] = serde_json::json!("/tmp/unused");
    assert_eq!(delegated_result(id, &raw(&value)), Err("UNKNOWN"));
    assert_eq!(
        delegated_result(id, br#"{"schema":1,"error":"UNKNOWN"}"#),
        Err("UNKNOWN")
    );
}

#[test]
fn main_command_receipt_pins_original_identity_and_systemd_job_scope() {
    let id = "rec-11111111-1111-4111-8111-111111111111";
    let mut original = serde_json::json!({"schema":1,"restoreId":id,"root":{"device":"33","inode":"1"},
        "state":"MAIN_START_UNKNOWN","planSha256":"a".repeat(64),"selectionSha256":"b".repeat(64),
        "bootId":"22222222-2222-4222-8222-222222222222"});
    let raw = |value: &serde_json::Value| serde_json::to_vec(value).unwrap();
    assert_eq!(main_result(id, &raw(&original)).unwrap(), original);
    original["state"] = serde_json::json!("MAIN_START_JOB_ACCEPTED");
    assert_eq!(main_result(id, &raw(&original)), Err("UNKNOWN"));
    original["jobPath"] = serde_json::json!("/org/freedesktop/systemd1/job/111");
    assert_eq!(main_result(id, &raw(&original)).unwrap(), original);
    original["jobPath"] = serde_json::json!("/usr/bin/systemctl");
    assert_eq!(main_result(id, &raw(&original)), Err("UNKNOWN"));
}
