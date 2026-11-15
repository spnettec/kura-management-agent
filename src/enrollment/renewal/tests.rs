use super::*;

fn first() -> (Store, crate::remote::Remote, PathBuf, Vec<u8>) {
    let (store, mut input) = crate::enrollment::tests::fixture();
    let remote = crate::remote::Remote::open(store.root.clone(), false, None).unwrap();
    input.expected_revision = remote.status()["revision"].as_str().unwrap().into();
    let candidate = store.prepare(&input, "kura-uid:test".into()).unwrap();
    remote
        .bind_target(
            &input.expected_revision,
            (
                candidate.receipt.material.endpoint.clone(),
                candidate.receipt.material.gateway_id.clone(),
                1,
            ),
            "test-operator".into(),
            |bytes| store.commit(&candidate, bytes),
        )
        .unwrap();
    let bytes = fs::read(candidate.path.join("receipt.json")).unwrap();
    (store, remote, candidate.path, bytes)
}

fn proposal(store: &Store, remote: &crate::remote::Remote) -> RenewInput {
    let (source, input) = crate::enrollment::tests::fixture();
    let slot = source.grant.as_ref().unwrap().join(&input.request_id);
    let m: Manifest =
        serde_json::from_slice(&fs::read(slot.join("certificates/manifest.json")).unwrap())
            .unwrap();
    fs::rename(slot, store.grant.as_ref().unwrap().join(&input.request_id)).unwrap();
    let old = store.record().unwrap().unwrap();
    RenewInput {
        operation_id: uuid::Uuid::new_v4().to_string(),
        expected_revision: remote.status()["revision"].as_str().unwrap().into(),
        previous_receipt_sha256: crate::durable::hash(&fs::read(store.pointer()).unwrap()),
        request_id: input.request_id,
        expected_stage_sha256: input.expected_stage_sha256,
        center_operation_id: uuid::Uuid::new_v4().to_string(),
        center_previous_certificate_sha256: old.material.client_certificate_sha256,
        center_certificate_sha256: m.client_certificate_sha256,
        center_previous_binding_generation: old.binding_generation,
        center_binding_generation: old.binding_generation + 1,
        operator: "local-test-admin".into(),
    }
}

fn apply(
    store: &Store,
    remote: &crate::remote::Remote,
    input: &RenewInput,
    checkpoint: impl FnMut(&str) -> Result<()>,
) -> Result<bool> {
    let old = store.record()?.unwrap();
    let target = (
        old.material.endpoint,
        old.material.gateway_id,
        old.binding_generation,
    );
    remote.renew_target(
        &input.expected_revision,
        &target,
        "kura-uid:test".into(),
        |decision| store.renew_with_hook(input, "kura-uid:test".into(), decision, checkpoint),
    )
}

async fn reopen(store: &Store) -> Enrollment {
    let db = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    Enrollment::open(
        store.root.clone(),
        None,
        store.grant.clone(),
        store.kura_uid,
        db,
        "fresh-test-boot".into(),
    )
    .unwrap()
}

#[tokio::test]
async fn two_renewals_preserve_old_original_proof_and_restart_disabled() {
    let (store, remote, first_path, first_receipt) = first();
    let old_key = fs::read(first_path.join("private.pk8")).unwrap();
    let second = proposal(&store, &remote);
    assert!(apply(&store, &remote, &second, |_| Ok(())).unwrap());
    let second_result = store.read_renewal(&second.operation_id).unwrap();
    assert_eq!(second_result["state"], "APPLIED");
    assert_eq!(second_result["bindingGeneration"], 2);
    assert_eq!(remote.status()["connectionState"], "DISABLED");
    assert!(remote.session().is_none());
    assert_eq!(store.load("second").unwrap().unwrap().binding_generation, 2);
    let third = proposal(&store, &remote);
    assert!(apply(&store, &remote, &third, |_| Ok(())).unwrap());
    assert_eq!(
        store.read_renewal(&third.operation_id).unwrap()["bindingGeneration"],
        3
    );
    assert_eq!(
        store.read_renewal(&second.operation_id).unwrap(),
        second_result
    );
    assert_eq!(
        fs::read(first_path.join("receipt.json")).unwrap(),
        first_receipt
    );
    assert_eq!(fs::read(first_path.join("private.pk8")).unwrap(), old_key);
    let reopened = reopen(&store).await;
    assert!(!reopened.fault());
    let cfg = reopened.current().unwrap();
    assert_eq!(cfg.binding_generation, 3);
    let remote2 = crate::remote::Remote::open(
        store.root.clone(),
        true,
        Some((cfg.endpoint, cfg.gateway, cfg.binding_generation)),
    )
    .unwrap();
    assert_eq!(remote2.status()["enabled"], false);
    let revision = remote2.status()["revision"].as_str().unwrap().to_owned();
    remote2
        .set_enabled(&revision, true, "test-local-admin".into())
        .unwrap();
    assert_eq!(
        store.read_renewal(&second.operation_id).unwrap(),
        second_result
    );
    assert!(remote2.admit(&second.expected_revision).is_err());
    assert!(
        !serde_json::to_string(&second_result)
            .unwrap()
            .contains("PRIVATE KEY")
    );
    println!(
        "RENEWAL_TWO_GENERATIONS root={} second={} third={} originalProofUnchanged=true",
        store.root.display(),
        second.operation_id,
        third.operation_id
    );
}

#[tokio::test]
async fn missing_original_result_is_unknown_even_when_current_credential_matches() {
    let (store, remote, _, _) = first();
    let input = proposal(&store, &remote);
    assert!(apply(&store, &remote, &input, |_| Ok(())).unwrap());
    let candidate = store.record().unwrap().unwrap();
    assert_eq!(
        candidate.material.client_certificate_sha256,
        input.center_certificate_sha256
    );
    fs::remove_file(
        store
            .renewal_operations()
            .join(&input.operation_id)
            .join("result.json"),
    )
    .unwrap();
    assert_eq!(
        store.read_renewal(&input.operation_id).unwrap()["state"],
        "UNKNOWN"
    );
    assert!(store.renewal_blocked().unwrap());
    assert!(store.load("missing-receipt").is_err());
    let reopened = reopen(&store).await;
    assert!(reopened.fault());
    assert!(reopened.current().is_none());
    let next = proposal(&store, &remote);
    assert!(apply(&store, &remote, &next, |_| Ok(())).is_err());
    assert!(!store.renewal_operations().join(&next.operation_id).exists());
    assert!(
        !store
            .renewal_operations()
            .join(&input.operation_id)
            .join("result.json")
            .exists()
    );
}

#[tokio::test]
async fn mismatched_public_center_confirmation_is_durably_rejected_without_changing_identity() {
    for mode in 0..4 {
        let (store, remote, _, before) = first();
        let decision = fs::read(store.root.join("remote-management.json")).unwrap();
        let state = remote.status();
        let mut input = proposal(&store, &remote);
        match mode {
            0 => input.center_previous_certificate_sha256 = "a".repeat(64),
            1 => input.center_certificate_sha256 = "b".repeat(64),
            2 => input.center_previous_binding_generation = 3,
            _ => input.center_binding_generation = 3,
        }
        assert!(!apply(&store, &remote, &input, |_| Ok(())).unwrap());
        let result = store.read_renewal(&input.operation_id).unwrap();
        assert_eq!(result["state"], "REJECTED");
        assert_eq!(result["rejectionCode"], "CONFLICT");
        assert_eq!(remote.status(), state);
        assert_eq!(fs::read(store.pointer()).unwrap(), before);
        assert_eq!(
            fs::read(store.root.join("remote-management.json")).unwrap(),
            decision
        );
        assert!(!store.renewal_pending().exists());
        assert!(!store.renewal_blocked().unwrap());
        assert!(!reopen(&store).await.fault());
    }
}

#[tokio::test]
async fn every_interruption_retains_original_intent_and_never_replays_or_reenables() {
    for boundary in [
        "operation-created",
        "request",
        "request-complete",
        "reserved",
        "candidate",
        "pointer",
        "decision",
        "completed-intent",
        "pending-removed",
        "result",
    ] {
        let (store, remote, first_path, before) = first();
        let old_key = fs::read(first_path.join("private.pk8")).unwrap();
        let input = proposal(&store, &remote);
        assert!(
            apply(&store, &remote, &input, |at| {
                ensure!(at != boundary, "injected durable-boundary failure");
                Ok(())
            })
            .is_err(),
            "{boundary}"
        );
        assert_eq!(remote.status()["connectionState"], "RECOVERY_REQUIRED");
        assert!(remote.session().is_none());
        let result = store.read_renewal(&input.operation_id).unwrap();
        let reopened = reopen(&store).await;
        if boundary == "result" {
            assert_eq!(result["state"], "APPLIED");
            assert!(!reopened.fault());
            assert_eq!(reopened.current().unwrap().binding_generation, 2);
        } else {
            assert_eq!(result["state"], "UNKNOWN", "{boundary}");
            assert!(reopened.fault(), "{boundary}");
            assert!(reopened.current().is_none());
            assert!(store.renewal_blocked().unwrap());
        }
        assert_eq!(fs::read(first_path.join("receipt.json")).unwrap(), before);
        assert_eq!(fs::read(first_path.join("private.pk8")).unwrap(), old_key);
        let changed = store.renewal_operations().join(&input.operation_id);
        assert!(changed.exists());
        println!(
            "RENEWAL_BOUNDARY root={} operation={} boundary={} state={}",
            store.root.display(),
            input.operation_id,
            boundary,
            result["state"]
        );
    }
}

#[tokio::test]
async fn changed_parent_receipt_does_not_become_a_new_enrollment_or_repaired_history() {
    let (store, remote, first_path, _) = first();
    let input = proposal(&store, &remote);
    assert!(apply(&store, &remote, &input, |_| Ok(())).unwrap());
    fs::write(first_path.join("receipt.json"), b"retained-corrupt-parent").unwrap();
    assert_eq!(
        store.read_renewal(&input.operation_id).unwrap()["state"],
        "UNKNOWN"
    );
    assert!(reopen(&store).await.fault());
    assert!(store.load("corrupt-parent").is_err());
    assert_eq!(
        fs::read(first_path.join("receipt.json")).unwrap(),
        b"retained-corrupt-parent"
    );
}

#[tokio::test]
async fn known_admission_refusals_survive_later_renewal_without_changing_switch_or_canceling_work()
{
    let (store, remote, _, _) = first();
    let enrollment = live_enrollment(&store).await;
    let input = proposal(&store, &remote);
    let enabled = remote
        .set_enabled(&input.expected_revision, true, "other-local-admin".into())
        .unwrap();
    let revision = enabled["revision"].as_str().unwrap();
    let permit = remote.admit(revision).unwrap();
    let before = fs::read(store.pointer()).unwrap();
    let refusal = enrollment
        .renew(input.clone(), remote.clone(), "kura-uid:test".into())
        .await
        .unwrap();
    assert_eq!(refusal["state"], "REJECTED");
    assert_eq!(refusal["rejectionSource"], "ADMISSION");
    assert_eq!(remote.status()["enabled"], true);
    assert_eq!(remote.status()["activeRequests"], 1);
    assert_eq!(fs::read(store.pointer()).unwrap(), before);
    assert_eq!(
        fs::read_dir(store.base().join("candidates"))
            .unwrap()
            .count(),
        1
    );
    drop(permit);
    remote
        .set_enabled(revision, false, "other-local-admin".into())
        .unwrap();
    let next = proposal(&store, &remote);
    assert_eq!(
        enrollment
            .renew(next, remote.clone(), "kura-uid:test".into())
            .await
            .unwrap()["state"],
        "APPLIED"
    );
    assert_eq!(
        enrollment
            .renewal_status(Some(&input.operation_id), &remote)
            .unwrap(),
        refusal
    );
    let mut stale = input.clone();
    stale.operation_id = uuid::Uuid::new_v4().to_string();
    stale.expected_revision = remote.status()["revision"].as_str().unwrap().into();
    let current = fs::read(store.pointer()).unwrap();
    assert_eq!(
        enrollment
            .renew(stale.clone(), remote.clone(), "kura-uid:test".into())
            .await
            .unwrap()["state"],
        "REJECTED"
    );
    assert_eq!(fs::read(store.pointer()).unwrap(), current);
    assert_eq!(
        enrollment.renewal_status(None, &remote).unwrap()["canRenew"],
        true
    );
}

#[tokio::test]
async fn missing_definite_refusal_proof_is_unknown_and_cannot_be_rebuilt_after_restart() {
    let (store, remote, _, _) = first();
    let enrollment = live_enrollment(&store).await;
    let input = proposal(&store, &remote);
    remote
        .set_enabled(&input.expected_revision, true, "other-local-admin".into())
        .unwrap();
    assert_eq!(
        enrollment
            .renew(input.clone(), remote.clone(), "kura-uid:test".into())
            .await
            .unwrap()["state"],
        "REJECTED"
    );
    let path = store
        .renewal_operations()
        .join(&input.operation_id)
        .join("result.json");
    fs::remove_file(&path).unwrap();
    assert_eq!(
        enrollment
            .renewal_status(Some(&input.operation_id), &remote)
            .unwrap()["state"],
        "UNKNOWN"
    );
    let reopened = reopen(&store).await;
    assert!(reopened.fault());
    assert!(reopened.current().is_none());
    let restarted = crate::remote::Remote::open(store.root.clone(), false, None).unwrap();
    if reopened.fault() {
        restarted.inhibit_binding();
    }
    assert_eq!(restarted.status()["connectionState"], "RECOVERY_REQUIRED");
    assert_eq!(restarted.recovery_status().unwrap()["canResolve"], false);
    assert!(!path.exists());
}

fn utc_time(seconds: u64) -> String {
    let value = seconds.to_string();
    let mut command = std::process::Command::new("date");
    command.arg("-u");
    if cfg!(target_os = "macos") {
        command.args(["-r", &value]);
    } else {
        command.args(["-d", &format!("@{value}")]);
    }
    let result = command.arg("+%Y%m%d%H%M%SZ").output().unwrap();
    assert!(result.status.success());
    String::from_utf8(result.stdout).unwrap().trim().into()
}

async fn live_enrollment(store: &Store) -> Enrollment {
    let db = crate::transport::database(store.root.join("runtime.sqlite").to_str().unwrap())
        .await
        .unwrap();
    Enrollment::open(
        store.root.clone(),
        None,
        store.grant.clone(),
        store.kura_uid,
        db,
        "live-test-boot".into(),
    )
    .unwrap()
}

#[tokio::test]
async fn runtime_publishes_new_config_without_enabling_and_duplicate_uuid_cannot_commit_again() {
    let (store, remote, _, _) = first();
    let enrollment = live_enrollment(&store).await;
    let mut configs = enrollment.subscribe();
    assert_eq!(configs.borrow().as_ref().unwrap().binding_generation, 1);
    assert_eq!(
        enrollment.renewal_status(None, &remote).unwrap()["canRenew"],
        true
    );
    let input = proposal(&store, &remote);
    let receipt = enrollment
        .renew(input.clone(), remote.clone(), "kura-uid:test".into())
        .await
        .unwrap();
    assert_eq!(receipt["state"], "APPLIED");
    assert!(configs.has_changed().unwrap());
    assert_eq!(
        configs
            .borrow_and_update()
            .as_ref()
            .unwrap()
            .binding_generation,
        2
    );
    assert_eq!(remote.status()["bindingGeneration"], "2");
    assert_eq!(remote.status()["enabled"], false);
    let before = fs::read(store.pointer()).unwrap();
    assert!(
        enrollment
            .renew(input.clone(), remote.clone(), "kura-uid:test".into())
            .await
            .is_err()
    );
    assert_eq!(fs::read(store.pointer()).unwrap(), before);
    assert_eq!(remote.status()["recoveryRequired"], false);
    assert_eq!(
        enrollment
            .renewal_status(Some(&input.operation_id), &remote)
            .unwrap(),
        receipt
    );
    assert!(!configs.has_changed().unwrap());
}

#[tokio::test]
async fn unresolved_write_states_block_runtime_renewal_without_altering_rows_or_intents() {
    for state in ["QUEUED", "RUNNING", "UNKNOWN"] {
        let (store, remote, _, _) = first();
        let enrollment = live_enrollment(&store).await;
        let command = uuid::Uuid::new_v4().to_string();
        // Synthetic journal blockers only; no executor or remote command runs.
        sqlx::query("INSERT INTO executions(command_id,operation,idempotency_key,request_hash,plan,state,created_at,updated_at,expires_at) VALUES(?,12,?,?,X'00',?,1,1,9223372036854775807)")
            .bind(&command).bind(&command).bind("a".repeat(64)).bind(state).execute(&enrollment.db).await.unwrap();
        let input = proposal(&store, &remote);
        let before = fs::read(store.pointer()).unwrap();
        let refusal = enrollment
            .renew(input.clone(), remote.clone(), "kura-uid:test".into())
            .await
            .unwrap();
        assert_eq!(refusal["state"], "REJECTED");
        assert_eq!(refusal["rejectionSource"], "ADMISSION");
        assert_eq!(
            enrollment
                .renewal_status(Some(&input.operation_id), &remote)
                .unwrap(),
            refusal
        );
        assert_eq!(fs::read(store.pointer()).unwrap(), before);
        assert!(
            store
                .renewal_operations()
                .join(&input.operation_id)
                .join("result.json")
                .exists()
        );
        let retained: String =
            sqlx::query_scalar("SELECT state FROM executions WHERE command_id=?")
                .bind(&command)
                .fetch_one(&enrollment.db)
                .await
                .unwrap();
        assert_eq!(retained, state);
        assert_eq!(remote.status()["bindingGeneration"], "1");
    }
    let (store, remote, _, _) = first();
    let enrollment = live_enrollment(&store).await;
    sqlx::query("INSERT INTO executions(command_id,operation,idempotency_key,request_hash,plan,state,created_at,updated_at,expires_at) VALUES('read-only',48,'read-only','read-only',X'00','UNKNOWN',1,1,9223372036854775807)")
        .execute(&enrollment.db).await.unwrap();
    let input = proposal(&store, &remote);
    assert_eq!(
        enrollment
            .renew(input, remote.clone(), "kura-uid:test".into())
            .await
            .unwrap()["state"],
        "APPLIED"
    );
    let retained: String =
        sqlx::query_scalar("SELECT state FROM executions WHERE command_id='read-only'")
            .fetch_one(&enrollment.db)
            .await
            .unwrap();
    assert_eq!(retained, "UNKNOWN");
}

#[tokio::test]
async fn expired_historical_identity_can_renew_but_expired_new_material_cannot_enroll() {
    let (store, mut input) = crate::enrollment::tests::fixture();
    let base = store.root.parent().unwrap();
    let slot = store.grant.as_ref().unwrap().join(&input.request_id);
    let certs = slot.join("certificates");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let accepted = now - 129600;
    let config = base.join("backdated-ca.cnf");
    let index = base.join("backdated-index");
    let serial = base.join("backdated-serial");
    let issued = base.join("backdated-issued");
    crate::durable::directory(&issued).unwrap();
    crate::durable::publish_new(&index, b"", crate::durable::FileMetadata::private()).unwrap();
    crate::durable::publish_new(&serial, b"10\n", crate::durable::FileMetadata::private()).unwrap();
    let key = base.join("test-only.key");
    let ca = base.join("ca.pem");
    let text = format!(
        "[ca]\ndefault_ca=local\n[local]\ndatabase={}\nnew_certs_dir={}\ncertificate={}\nprivate_key={}\nserial={}\ndefault_md=sha256\ndefault_days=1\npolicy=policy\nunique_subject=no\n[policy]\ncommonName=supplied\n[root]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n",
        index.display(),
        issued.display(),
        ca.display(),
        key.display(),
        serial.display()
    );
    crate::durable::publish_new(
        &config,
        text.as_bytes(),
        crate::durable::FileMetadata::private(),
    )
    .unwrap();
    let ca_request = base.join("backdated-ca.csr");
    let csr = crypto::command(
        &[
            "req",
            "-new",
            "-key",
            key.to_str().unwrap(),
            "-subj",
            "/CN=enrollment-ca",
        ],
        None,
    )
    .unwrap();
    crate::durable::publish_new(&ca_request, &csr, crate::durable::FileMetadata::private())
        .unwrap();
    let root = crypto::command(
        &[
            "ca",
            "-selfsign",
            "-keyfile",
            key.to_str().unwrap(),
            "-config",
            config.to_str().unwrap(),
            "-in",
            ca_request.to_str().unwrap(),
            "-startdate",
            &utc_time(now - 30 * 86400),
            "-enddate",
            &utc_time(now + 30 * 86400),
            "-extensions",
            "root",
            "-batch",
            "-notext",
        ],
        None,
    )
    .unwrap();
    fs::write(&ca, &root).unwrap();
    let expired = crypto::command(
        &[
            "ca",
            "-config",
            config.to_str().unwrap(),
            "-in",
            slot.join("request.pem").to_str().unwrap(),
            "-startdate",
            &utc_time(now - 2 * 86400),
            "-enddate",
            &utc_time(now - 86400),
            "-extensions",
            "leaf",
            "-batch",
            "-notext",
        ],
        None,
    )
    .unwrap();
    fs::write(certs.join("client-chain.pem"), &expired).unwrap();
    fs::write(certs.join("issuer-ca.pem"), &root).unwrap();
    fs::write(certs.join("console-ca.pem"), &root).unwrap();
    let mut material: Manifest =
        serde_json::from_slice(&fs::read(certs.join("manifest.json")).unwrap()).unwrap();
    material.client_certificate_sha256 =
        crate::durable::hash(&crypto::blocks(&expired, "CERTIFICATE").unwrap()[0]);
    material.issuer_ca_sha256 = crate::durable::hash(&root);
    material.console_ca_sha256 = crate::durable::hash(&root);
    material.not_after = String::from_utf8(
        crypto::command(
            &["x509", "-noout", "-enddate", "-dateopt", "iso_8601"],
            Some(&expired),
        )
        .unwrap(),
    )
    .unwrap()
    .trim()
    .strip_prefix("notAfter=")
    .unwrap()
    .replace(' ', "T");
    let bytes = serde_json::to_vec(&material).unwrap();
    input.expected_stage_sha256 = crate::durable::hash(&bytes);
    fs::write(certs.join("manifest.json"), &bytes).unwrap();
    fs::write(
        certs.join("complete"),
        format!("{}\n", input.expected_stage_sha256),
    )
    .unwrap();
    // Actual certificates are expired now. Public initial enrollment must refuse them.
    assert!(
        store
            .prepare(&input, "test-current-enrollment".into())
            .is_err()
    );
    assert!(!store.pointer().exists());
    let candidates: Vec<_> = fs::read_dir(store.base().join("candidates"))
        .unwrap()
        .map(|x| x.unwrap().path())
        .collect();
    assert_eq!(candidates.len(), 1);
    let path = candidates[0].clone();
    crypto::validate_at(&path, &material, true, Some(accepted)).unwrap();
    assert!(crypto::validate(&path, &material, false).is_err());
    // Construct a test-only historical installation after proving validity at its
    // original acceptance time; no current enrollment API accepts expired material.
    let candidate = Candidate {
        receipt: Receipt {
            schema: "yofc.agent.enrollment.v1".into(),
            candidate_id: path.file_name().unwrap().to_str().unwrap().into(),
            request_id: input.request_id.clone(),
            stage_sha256: input.expected_stage_sha256.clone(),
            material,
            binding_generation: 1,
            source_uid: store.kura_uid,
            actor: "historical-fixture".into(),
            operator: "historical-local-admin".into(),
            accepted_at_unix_ms: accepted * 1000,
            renewal: None,
        },
        path,
    };
    let remote = crate::remote::Remote::open(store.root.clone(), false, None).unwrap();
    let revision = remote.status()["revision"].as_str().unwrap().to_owned();
    remote
        .bind_target(
            &revision,
            (
                candidate.receipt.material.endpoint.clone(),
                candidate.receipt.material.gateway_id.clone(),
                1,
            ),
            "historical-fixture".into(),
            |decision| store.commit(&candidate, decision),
        )
        .unwrap();
    assert!(!reopen(&store).await.fault());
    assert!(remote.session().is_none());
    let renewal = proposal(&store, &remote);
    assert!(apply(&store, &remote, &renewal, |_| Ok(())).unwrap());
    assert_eq!(
        store.read_renewal(&renewal.operation_id).unwrap()["state"],
        "APPLIED"
    );
    assert_eq!(
        store
            .load("renewed-after-expiry")
            .unwrap()
            .unwrap()
            .binding_generation,
        2
    );
    assert_eq!(remote.status()["enabled"], false);
    let fresh_pointer = fs::read(store.pointer()).unwrap();
    let expired_replacement = RenewInput {
        operation_id: uuid::Uuid::new_v4().to_string(),
        expected_revision: remote.status()["revision"].as_str().unwrap().into(),
        previous_receipt_sha256: crate::durable::hash(&fresh_pointer),
        request_id: input.request_id.clone(),
        expected_stage_sha256: input.expected_stage_sha256.clone(),
        center_operation_id: uuid::Uuid::new_v4().to_string(),
        center_previous_certificate_sha256: renewal.center_certificate_sha256.clone(),
        center_certificate_sha256: candidate.receipt.material.client_certificate_sha256.clone(),
        center_previous_binding_generation: 2,
        center_binding_generation: 3,
        operator: "local-test-admin".into(),
    };
    assert!(!apply(&store, &remote, &expired_replacement, |_| Ok(())).unwrap());
    assert_eq!(
        store
            .read_renewal(&expired_replacement.operation_id)
            .unwrap()["state"],
        "REJECTED"
    );
    assert_eq!(fs::read(store.pointer()).unwrap(), fresh_pointer);
    assert_eq!(remote.status()["bindingGeneration"], "2");
    println!(
        "RENEWAL_EXPIRED_FIXTURE root={} actualOldCertificateExpired=true originalAcceptanceProved=true freshReplacementAccepted=true expiredReplacementRejected=true",
        store.root.display()
    );
}
