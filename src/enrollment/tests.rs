use super::*;
use std::os::unix::fs::PermissionsExt;
fn root() -> PathBuf {
    let p = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("agent-enrollment-{}", uuid::Uuid::new_v4()));
    crate::durable::directory(&p).unwrap();
    p
}
fn write(path: &Path, bytes: &[u8]) {
    crate::durable::publish_new(path, bytes, crate::durable::FileMetadata::private()).unwrap();
}
pub(super) fn fixture() -> (Store, BindInput) {
    let base = root();
    let grant = base.join("kura");
    crate::durable::directory(&grant).unwrap();
    let request_id = uuid::Uuid::new_v4().to_string();
    let slot = grant.join(&request_id);
    crate::durable::directory(&slot).unwrap();
    let cmd = |args: &[&str]| crypto::command(args, None).unwrap();
    let key = cmd(&[
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
    ]);
    write(
        &slot.join("private.pk8"),
        &crypto::command(
            &["pkcs8", "-topk8", "-nocrypt", "-outform", "DER"],
            Some(&key),
        )
        .unwrap(),
    );
    let key_file = base.join("test-only.key");
    write(&key_file, &key);
    let k = key_file.to_str().unwrap();
    write(
        &slot.join("public.der"),
        &crypto::command(&["pkey", "-pubout", "-outform", "DER"], Some(&key)).unwrap(),
    );
    write(
        &slot.join("request.pem"),
        &cmd(&["req", "-new", "-key", k, "-subj", "/CN=enrollment-test"]),
    );
    write(&slot.join("gateway.id"), b"enrollment-test");
    write(&slot.join("complete"), b"kura.remote.identity.v1\n");
    let ca = base.join("ca.pem");
    write(
        &ca,
        &cmd(&[
            "req",
            "-new",
            "-x509",
            "-key",
            k,
            "-subj",
            "/CN=enrollment-ca",
            "-days",
            "2",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]),
    );
    let ext = base.join("ext");
    write(&ext,b"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n");
    let certs = slot.join("certificates");
    crate::durable::directory(&certs).unwrap();
    let leaf = cmd(&[
        "x509",
        "-req",
        "-in",
        slot.join("request.pem").to_str().unwrap(),
        "-CA",
        ca.to_str().unwrap(),
        "-CAkey",
        k,
        "-set_serial",
        "2",
        "-days",
        "1",
        "-extfile",
        ext.to_str().unwrap(),
    ]);
    write(&certs.join("client-chain.pem"), &leaf);
    let anchor = fs::read(ca).unwrap();
    write(&certs.join("issuer-ca.pem"), &anchor);
    write(&certs.join("console-ca.pem"), &anchor);
    let expiry = String::from_utf8(
        crypto::command(
            &["x509", "-noout", "-enddate", "-dateopt", "iso_8601"],
            Some(&leaf),
        )
        .unwrap(),
    )
    .unwrap();
    let not_after = expiry
        .trim()
        .strip_prefix("notAfter=")
        .unwrap()
        .replace(' ', "T");
    let m = Manifest {
        schema: "yofc.kura.remote.certificates.v1".into(),
        request_id: request_id.clone(),
        gateway_id: "enrollment-test".into(),
        endpoint: "https://example.invalid:8443".into(),
        public_key_sha256: crate::durable::hash(&fs::read(slot.join("public.der")).unwrap()),
        client_certificate_sha256: crate::durable::hash(
            &crypto::blocks(&leaf, "CERTIFICATE").unwrap()[0],
        ),
        issuer_ca_sha256: crate::durable::hash(&anchor),
        console_ca_sha256: crate::durable::hash(&anchor),
        not_after,
    };
    let bytes = serde_json::to_vec(&m).unwrap();
    let hash = crate::durable::hash(&bytes);
    write(&certs.join("manifest.json"), &bytes);
    write(&certs.join("complete"), format!("{hash}\n").as_bytes());
    let state = base.join("state");
    crate::durable::directory(&state).unwrap();
    (
        Store {
            root: state,
            grant: Some(grant),
            kura_uid: unsafe { libc::geteuid() },
        },
        BindInput {
            expected_revision: "unused".into(),
            request_id,
            expected_stage_sha256: hash,
            operator: "test-admin".into(),
        },
    )
}
#[test]
fn parses_only_fixed_safe_addresses_and_private_format() {
    for value in ["https://example.invalid:8443", "https://[::1]:443/"] {
        endpoint(value).unwrap();
    }
    for value in [
        "http://example.invalid",
        "https://a/path",
        "https://a@b",
        "https://a:0",
        "https://a:65536",
        "https://a/?x=1",
        "https://a/#x",
    ] {
        assert!(endpoint(value).is_err(), "{value}");
    }
    assert!(crypto::private_pkcs8(b"-----BEGIN PRIVATE KEY-----").is_err());
    assert!(crypto::blocks(b"junk", "CERTIFICATE").is_err());
}
#[test]
fn independently_validates_copies_commits_and_reloads_without_enabling() {
    let (store, mut input) = fixture();
    let remote = crate::remote::Remote::open(store.root.clone(), false, None).unwrap();
    input.expected_revision = remote.status()["revision"].as_str().unwrap().into();
    let candidate = store.prepare(&input, "kura-uid:test".into()).unwrap();
    remote
        .bind_target(
            &input.expected_revision,
            (
                "https://example.invalid:8443".into(),
                "enrollment-test".into(),
                1,
            ),
            "test".into(),
            |bytes| store.commit(&candidate, bytes),
        )
        .unwrap();
    assert_eq!(remote.status()["connectionState"], "DISABLED");
    assert!(remote.session().is_none());
    let cfg = store.load("test-boot").unwrap().unwrap();
    assert_eq!(cfg.gateway, "enrollment-test");
    assert_eq!(
        fs::read(candidate.path.join("receipt.json")).unwrap(),
        fs::read(store.pointer()).unwrap()
    );
    assert!(candidate.path.join("completed-intent.json").exists());
    assert!(!store.pending().exists());
    assert!(store.prepare(&input, "second".into()).is_err());
    fs::remove_file(candidate.path.join("agent-key.pem")).unwrap();
    assert!(store.load("test").is_err());
    assert!(!candidate.path.join("agent-key.pem").exists());
}
#[test]
fn changed_material_or_private_key_never_becomes_authoritative() {
    let (store, mut input) = fixture();
    let slot = store.grant.as_ref().unwrap().join(&input.request_id);
    input.expected_stage_sha256 = "a".repeat(64);
    assert!(store.prepare(&input, "test".into()).is_err());
    let m = fs::read(slot.join("certificates/manifest.json")).unwrap();
    input.expected_stage_sha256 = crate::durable::hash(&m);
    let private = slot.join("private.pk8");
    fs::write(&private, b"corrupt").unwrap();
    assert!(store.prepare(&input, "test".into()).is_err());
    assert!(!store.pointer().exists());
    assert_eq!(fs::read(&private).unwrap(), b"corrupt");
    assert_eq!(
        fs::read_dir(store.base().join("candidates"))
            .unwrap()
            .count(),
        1
    );
}
#[test]
fn permission_links_and_unknown_files_are_rejected_before_handoff() {
    let (store, input) = fixture();
    let slot = store.grant.as_ref().unwrap().join(&input.request_id);
    fs::set_permissions(slot.join("private.pk8"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.prepare(&input, "test".into()).is_err());
    fs::set_permissions(slot.join("private.pk8"), fs::Permissions::from_mode(0o600)).unwrap();
    write(&slot.join("extra"), b"preserve");
    assert!(store.prepare(&input, "test".into()).is_err());
    fs::remove_file(slot.join("extra")).unwrap();
    let private = slot.join("private.pk8");
    fs::rename(&private, slot.join("original")).unwrap();
    fs::hard_link(slot.join("original"), &private).unwrap();
    assert!(store.prepare(&input, "test".into()).is_err());
    assert!(!store.pointer().exists());
}
#[tokio::test]
async fn pending_or_corrupt_identity_keeps_local_process_but_inhibits_binding() {
    let p = root();
    write(&p.join("identity-enrollment-pending.json"), b"retained");
    let db = crate::transport::database(p.join("agent.db").to_str().unwrap())
        .await
        .unwrap();
    let enrollment = Enrollment::open(p.clone(), None, None, u32::MAX, db, "boot".into()).unwrap();
    assert!(enrollment.fault());
    assert!(enrollment.current().is_none());
    assert_eq!(enrollment.status(true).unwrap()["canEnroll"], false);
    assert_eq!(
        fs::read(p.join("identity-enrollment-pending.json")).unwrap(),
        b"retained"
    );
}
#[test]
fn failed_identity_commit_cannot_be_cleared_by_remote_switch_recovery() {
    let p = root();
    let remote = crate::remote::Remote::open(p, false, None).unwrap();
    let revision = remote.status()["revision"].as_str().unwrap().to_owned();
    assert!(
        remote
            .bind_target(
                &revision,
                ("https://a".into(), "gw".into(), 1),
                "test".into(),
                |_| anyhow::bail!("uncertain")
            )
            .is_err()
    );
    assert_eq!(remote.status()["connectionState"], "RECOVERY_REQUIRED");
    assert!(remote.set_enabled(&revision, false, "test".into()).is_err());
    assert_eq!(remote.recovery_status().unwrap()["canResolve"], false);
}

#[tokio::test]
async fn lost_pointer_with_retained_receipt_never_becomes_fresh_unbound_install() {
    let (store, input) = fixture();
    let candidate = store.prepare(&input, "test".into()).unwrap();
    let bytes = serde_json::to_vec(&candidate.receipt).unwrap();
    write(&candidate.path.join("receipt.json"), &bytes);
    let db = crate::transport::database(store.root.join("db").to_str().unwrap())
        .await
        .unwrap();
    let enrollment = Enrollment::open(
        store.root.clone(),
        None,
        store.grant.clone(),
        store.kura_uid,
        db,
        "boot".into(),
    )
    .unwrap();
    assert!(enrollment.fault());
    assert_eq!(enrollment.status(true).unwrap()["canEnroll"], false);
    assert_eq!(
        fs::read(candidate.path.join("receipt.json")).unwrap(),
        bytes
    );
}

fn replace_leaf(store: &Store, input: &mut BindInput, mode: &str) {
    let slot = store.grant.as_ref().unwrap().join(&input.request_id);
    let base = store.root.parent().unwrap();
    let certs = slot.join("certificates");
    let mut m: Manifest =
        serde_json::from_slice(&fs::read(certs.join("manifest.json")).unwrap()).unwrap();
    let ext = base.join("alternate-ext");
    let extensions = match mode {
        "purpose" => {
            "basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n"
        }
        "critical" => {
            "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\n1.2.3.4=critical,DER:05:00\n"
        }
        "ca" => {
            "basicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign,digitalSignature\nextendedKeyUsage=clientAuth\n"
        }
        "usage" => {
            "basicConstraints=critical,CA:FALSE\nkeyUsage=keyAgreement\nextendedKeyUsage=clientAuth\n"
        }
        _ => {
            "basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n"
        }
    };
    write(&ext, extensions.as_bytes());
    let original = slot.join("request.pem");
    let mut request = original.clone();
    if mode == "subject" {
        request = base.join("wrong-subject.csr");
        write(
            &request,
            &crypto::command(
                &[
                    "req",
                    "-new",
                    "-key",
                    base.join("test-only.key").to_str().unwrap(),
                    "-subj",
                    "/CN=Enrollment-test",
                ],
                None,
            )
            .unwrap(),
        );
    }
    if mode == "key" {
        let key = crypto::command(
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
            ],
            None,
        )
        .unwrap();
        let file = base.join("wrong-key.pem");
        write(&file, &key);
        request = base.join("wrong-key.csr");
        write(
            &request,
            &crypto::command(
                &[
                    "req",
                    "-new",
                    "-key",
                    file.to_str().unwrap(),
                    "-subj",
                    "/CN=enrollment-test",
                ],
                None,
            )
            .unwrap(),
        );
    }
    let leaf = if mode == "expired" {
        let config = base.join("expiry-ca.conf");
        write(&base.join("index"), b"");
        write(&base.join("serial"), b"04\n");
        write(&config,format!("[ca]\ndefault_ca=test\n[test]\ndatabase={0}/index\nserial={0}/serial\nprivate_key={0}/test-only.key\ncertificate={0}/ca.pem\nnew_certs_dir={0}\ndefault_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n",base.display()).as_bytes());
        crypto::command(
            &[
                "ca",
                "-batch",
                "-notext",
                "-config",
                config.to_str().unwrap(),
                "-in",
                request.to_str().unwrap(),
                "-startdate",
                "20000101000000Z",
                "-enddate",
                "20000102000000Z",
                "-extfile",
                ext.to_str().unwrap(),
            ],
            None,
        )
        .unwrap()
    } else {
        crypto::command(
            &[
                "x509",
                "-req",
                "-in",
                request.to_str().unwrap(),
                "-CA",
                base.join("ca.pem").to_str().unwrap(),
                "-CAkey",
                base.join("test-only.key").to_str().unwrap(),
                "-set_serial",
                "3",
                "-days",
                if mode == "expired" { "-1" } else { "1" },
                "-extfile",
                ext.to_str().unwrap(),
            ],
            None,
        )
        .unwrap()
    };
    fs::write(certs.join("client-chain.pem"), &leaf).unwrap();
    m.client_certificate_sha256 =
        crate::durable::hash(&crypto::blocks(&leaf, "CERTIFICATE").unwrap()[0]);
    let expiry = String::from_utf8(
        crypto::command(
            &["x509", "-noout", "-enddate", "-dateopt", "iso_8601"],
            Some(&leaf),
        )
        .unwrap(),
    )
    .unwrap();
    m.not_after = expiry
        .trim()
        .strip_prefix("notAfter=")
        .unwrap()
        .replace(' ', "T");
    let bytes = serde_json::to_vec(&m).unwrap();
    input.expected_stage_sha256 = crate::durable::hash(&bytes);
    fs::write(certs.join("manifest.json"), &bytes).unwrap();
    fs::write(
        certs.join("complete"),
        format!("{}\n", input.expected_stage_sha256),
    )
    .unwrap();
}
#[test]
fn independent_certificate_policy_rejects_signed_but_inapplicable_material() {
    for mode in [
        "purpose", "critical", "ca", "usage", "subject", "key", "expired",
    ] {
        let (store, mut input) = fixture();
        replace_leaf(&store, &mut input, mode);
        assert!(
            store.prepare(&input, "test".into()).is_err(),
            "accepted {mode}"
        );
        assert!(!store.pointer().exists(), "{mode}");
    }
}

#[tokio::test]
async fn interrupted_identity_commit_never_replays_and_restarts_blocked_or_durably_off() {
    for boundary in [
        "receipt",
        "receipt-complete",
        "pending",
        "pointer",
        "decision",
        "renamed",
        "durable",
    ] {
        let (store, mut input) = fixture();
        let remote = crate::remote::Remote::open(store.root.clone(), false, None).unwrap();
        input.expected_revision = remote.status()["revision"].as_str().unwrap().into();
        let candidate = store.prepare(&input, "test".into()).unwrap();
        let target = (
            "https://example.invalid:8443".into(),
            "enrollment-test".into(),
            1,
        );
        let result = remote.bind_target(&input.expected_revision, target, "test".into(), |bytes| {
            store.commit_with_hook(&candidate, bytes, |step| {
                if step == boundary {
                    anyhow::bail!("injected publication uncertainty");
                }
                Ok(())
            })
        });
        assert!(result.is_err());
        assert_eq!(remote.status()["recoveryRequired"], true);
        assert!(remote.session().is_none());
        assert_eq!(remote.recovery_status().unwrap()["canResolve"], false);
        let before = fs::read(candidate.path.join("receipt.json")).unwrap();
        let db = crate::transport::database(store.root.join("db").to_str().unwrap())
            .await
            .unwrap();
        let enrollment = Enrollment::open(
            store.root.clone(),
            None,
            store.grant.clone(),
            store.kura_uid,
            db,
            "boot".into(),
        )
        .unwrap();
        let cfg = enrollment.current();
        let reopened = crate::remote::Remote::open(
            store.root.clone(),
            false,
            cfg.as_ref()
                .map(|c| (c.endpoint.clone(), c.gateway.clone(), c.binding_generation)),
        )
        .unwrap();
        if enrollment.fault() {
            reopened.inhibit_binding();
            assert_eq!(reopened.status()["recoveryRequired"], true, "{boundary}");
            assert!(cfg.is_none());
        } else {
            assert!(matches!(boundary, "renamed" | "durable"));
            assert_eq!(reopened.status()["connectionState"], "DISABLED");
            assert!(cfg.is_some());
        }
        assert!(!reopened.status()["enabled"].as_bool().unwrap());
        assert!(reopened.session().is_none());
        assert_eq!(
            fs::read(candidate.path.join("receipt.json")).unwrap(),
            before
        );
    }
}

#[tokio::test]
async fn unbound_enrollment_cannot_bypass_unknown_execution_or_network_recovery() {
    let (store, mut input) = fixture();
    let db = crate::transport::database(store.root.join("db").to_str().unwrap())
        .await
        .unwrap();
    let enrollment = Enrollment::open(
        store.root.clone(),
        None,
        store.grant.clone(),
        store.kura_uid,
        db.clone(),
        "boot".into(),
    )
    .unwrap();
    let remote = crate::remote::Remote::open(store.root.clone(), false, None).unwrap();
    input.expected_revision = remote.status()["revision"].as_str().unwrap().into();
    sqlx::query("INSERT INTO executions(command_id,operation,idempotency_key,request_hash,plan,state,created_at,updated_at,expires_at) VALUES('retained-unknown',12,'key','hash',X'00','UNKNOWN',0,0,0)").execute(&db).await.unwrap();
    assert!(
        enrollment
            .bind(input, remote.clone(), "test".into())
            .await
            .is_err()
    );
    assert!(!store.base().exists());
    assert_eq!(remote.status()["connectionState"], "UNBOUND");
    // Alter only this fresh test's execution state to verify the independent journal gate.
    sqlx::query("UPDATE executions SET state='SUCCEEDED' WHERE command_id='retained-unknown'")
        .execute(&db)
        .await
        .unwrap();
    crate::durable::directory(&store.root.join("network")).unwrap();
    write(
        &store.root.join("network/transaction.json"),
        br#"{"state":"RECOVERY_REQUIRED"}"#,
    );
    let input = BindInput {
        expected_revision: remote.status()["revision"].as_str().unwrap().into(),
        request_id: uuid::Uuid::new_v4().to_string(),
        expected_stage_sha256: "a".repeat(64),
        operator: "test".into(),
    };
    assert!(enrollment.bind(input, remote, "test".into()).await.is_err());
    assert!(!store.base().exists());
    assert_eq!(
        fs::read(store.root.join("network/transaction.json")).unwrap(),
        br#"{"state":"RECOVERY_REQUIRED"}"#
    );
}

#[test]
fn explicit_issuer_cannot_be_supplemented_by_ambient_openssl_ca_directory() {
    let (store, input) = fixture();
    let (other, _) = fixture();
    let base = store.root.parent().unwrap();
    let slot = store.grant.as_ref().unwrap().join(&input.request_id);
    let certs = slot.join("certificates");
    let trusted = base.join("ambient-ca-directory");
    fs::create_dir(&trusted).unwrap();
    fs::copy(certs.join("issuer-ca.pem"), trusted.join("issuer.pem")).unwrap();
    crypto::command(&["rehash", trusted.to_str().unwrap()], None).unwrap();
    let unrelated = base.join("unrelated-explicit-ca.pem");
    write(
        &unrelated,
        &crypto::command(
            &[
                "req",
                "-new",
                "-x509",
                "-key",
                other
                    .root
                    .parent()
                    .unwrap()
                    .join("test-only.key")
                    .to_str()
                    .unwrap(),
                "-sha256",
                "-days",
                "2",
                "-subj",
                "/CN=unrelated-explicit-ca",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign",
            ],
            None,
        )
        .unwrap(),
    );
    let ambient = format!("SSL_CERT_DIR={}", trusted.display());
    let leaf = certs.join("client-chain.pem");
    let verify = |issuer: &Path| {
        let raw = [
            "verify",
            "-partial_chain",
            "-auth_level",
            "2",
            "-purpose",
            "sslclient",
            "-CAfile",
            issuer.to_str().unwrap(),
            leaf.to_str().unwrap(),
        ];
        let mut args = vec![ambient.as_str(), crypto::openssl().to_str().unwrap()];
        args.extend(crypto::arguments(&raw));
        crate::process::run(
            Path::new("/usr/bin/env"),
            &args,
            None,
            std::time::Duration::from_secs(5),
        )
        .unwrap()
        .status
        .success()
    };
    assert!(
        verify(&certs.join("issuer-ca.pem")),
        "Explicit issuer must remain usable"
    );
    assert!(
        !verify(&unrelated),
        "Ambient default CA directory must not repair a mismatching explicit issuer"
    );
    // The parent's environment and machine-wide trust store are never modified.
}

#[test]
fn java_sunec_minimal_pkcs8_is_adapted_for_actual_tls_without_replacing_key_material() {
    // Exact Java SunEC P256 PKCS8 layout: private scalar, no redundant public point.
    // Fixed test-only scalar, never a gateway identity or persisted product key.
    let mut der = vec![
        0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25,
        0x02, 0x01, 0x01, 0x04, 0x20,
    ];
    der.extend_from_slice(&[1u8; 32]);
    let original = crypto::pem("PRIVATE KEY", &der);
    crypto::private_pkcs8(&der).unwrap();
    let base = root();
    let key = base.join("java-key.pem");
    write(&key, &original);
    let certificate = crypto::command(
        &[
            "req",
            "-new",
            "-x509",
            "-key",
            key.to_str().unwrap(),
            "-subj",
            "/CN=localhost",
            "-days",
            "1",
        ],
        None,
    )
    .unwrap();
    let endpoint = || tonic::transport::Endpoint::from_static("https://localhost:1");
    let tls = |identity| {
        tonic::transport::ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(&certificate))
            .identity(identity)
    };
    assert!(
        endpoint()
            .tls_config(tls(tonic::transport::Identity::from_pem(
                &certificate,
                &original
            )))
            .is_err(),
        "regression must exercise ring's rejected SunEC encoding"
    );
    let identity = super::tls_identity(certificate.clone(), original.clone()).unwrap();
    assert!(
        endpoint().tls_config(tls(identity)).is_ok(),
        "actual TLS builder must accept same key after in-memory adaptation"
    );
    assert_eq!(std::fs::read(key).unwrap(), original);
    let adapted = crypto::tls_private_key(&original).unwrap();
    assert_eq!(
        crypto::command(&["pkey", "-pubout", "-outform", "DER"], Some(&original)).unwrap(),
        crypto::command(&["pkey", "-pubout", "-outform", "DER"], Some(&adapted)).unwrap()
    );
    assert_eq!(crypto::tls_private_key(&adapted).unwrap(), adapted);
    let invalid = super::tls_identity(
        certificate.clone(),
        b"-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n".to_vec(),
    )
    .unwrap();
    assert!(endpoint().tls_config(tls(invalid)).is_err());
}
