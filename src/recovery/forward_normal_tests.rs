//! Contract fixtures use recording fake units/receipts; native verification is separate.
use super::tests::{TempDir, calls};
use super::*;

async fn applied_fixture() -> (Recovery, TempDir, Value) {
    let (mut recovery, dir) = tests::inverse_fixture();
    durable::directory(&dir.0.join("normal")).unwrap();
    let hook = dir.0.join("normal-receipt.py");
    fs::write(&hook,format!(r#"import pathlib,hashlib,os
root=pathlib.Path({root});p=root/'normal/request.properties'
d=dict(line.split('=',1) for line in p.read_text().splitlines());r=pathlib.Path(d['receipt.path'])
observed=b'exact forward CM observation';pathlib.Path(str(r)+'.cm-observed.aes').write_bytes(observed)
pathlib.Path(str(r)+'.bundle-levels').write_text('schema=1\n22=5\n')
r.write_text('schema=1\nstatus=NORMAL_BOOT_ADMITTED\nrestore.id='+d['restore.id']+'\nsnapshot.sha256='+d['snapshot.sha256']+'\nsource.receipt.sha256='+d['verification.source.receipt.sha256']+'\nsource.applied.sha256='+d['verification.source.applied.sha256']+'\nobserved.sha256='+hashlib.sha256(observed).hexdigest()+'\nfullRecoveryVerified=false\nnormalBootVerified=false\nbusinessHealth=UNVERIFIED\n')
for suffix in ['', '.cm-observed.aes','.bundle-levels']:os.chmod(pathlib.Path(str(r)+suffix),0o600)
"#,root=serde_json::to_string(&dir.0).unwrap())).unwrap();
    let script = dir.0.join("fake-systemctl");
    let body = fs::read_to_string(&script).unwrap();
    fs::write(&script,body.replace("args=['/usr/bin/python3',str(root/'emit-receipt.py')]","args=['/usr/bin/python3',str(root/('normal-receipt.py' if unit=='kura-normal.service' else 'emit-receipt.py'))]")).unwrap();
    durable::json(&dir.0.join("normal.json"),&json!({"schema":1,"unit":"kura-normal.service",
        "requestPath":dir.0.join("normal/request.properties"),"receiptDirectory":dir.0.join("application"),"timeoutSeconds":1,
        "profileFiles":[{"path":dir.0.join("profile"),"sha256":durable::hash(b"fixed startup profile")}]})).unwrap();
    Arc::get_mut(&mut recovery.0)
        .unwrap()
        .units
        .push("kura-normal.service".into());
    recovery = recovery
        .with_normal_startup(
            crate::controlled_startup::Startup::new(dir.0.join("normal.json")).unwrap(),
        )
        .unwrap();
    let prepared = tests::prepared_java(&recovery).await;
    recovery
        .execute(
            prepared["transactionId"].as_str().unwrap(),
            prepared["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        recovery.journal().unwrap().unwrap().state,
        State::AwaitingCompletion
    );
    assert!(recovery.journal().unwrap().unwrap().inverse.is_none());
    (recovery, dir, prepared)
}
fn grant(recovery: Recovery, dir: &TempDir) -> Recovery {
    let authority = recovery
        .0
        .normal_startup
        .as_ref()
        .unwrap()
        .authority_sha256()
        .unwrap();
    durable::json(&dir.0.join("forward-normal.json"),&json!({"schema":1,"source":"applied-forward","acceptAppliedForwardSource":true,"normalStartupAuthoritySha256":authority})).unwrap();
    recovery
        .with_forward_normal_profile(dir.0.join("forward-normal.json"))
        .unwrap()
}
#[tokio::test]
async fn applied_forward_normal_is_default_off_and_legacy_inverse_entry_does_not_switch_sources() {
    let (recovery, dir, source) = applied_fixture().await;
    let before = calls(&dir);
    assert!(
        recovery
            .prepare_applied_normal_boot(
                source["transactionId"].as_str().unwrap(),
                source["confirmToken"].as_str().unwrap()
            )
            .await
            .is_err()
    );
    assert!(
        recovery
            .prepare_normal_boot(
                source["transactionId"].as_str().unwrap(),
                source["confirmToken"].as_str().unwrap()
            )
            .await
            .is_err()
    );
    assert_eq!(calls(&dir), before);
    assert!(recovery.journal().unwrap().unwrap().normal_boot.is_none());
}
#[tokio::test]
async fn applied_forward_normal_binds_source_receipt_and_preserves_candidate_without_inverse_replay()
 {
    let (recovery, dir, source) = applied_fixture().await;
    let recovery = grant(recovery, &dir);
    let baseline = recovery.inventory().unwrap();
    let prepared = recovery
        .prepare_applied_normal_boot(
            source["transactionId"].as_str().unwrap(),
            source["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(prepared["normalSource"], "applied-forward");
    let j = recovery.journal().unwrap().unwrap();
    let plan = j.normal_boot.as_ref().unwrap();
    assert_eq!(plan.target, recovery.0.root.join(&j.target));
    assert_eq!(plan.sha256, j.sha256);
    assert!(j.inverse.is_none());
    assert!(
        plan.parameters
            .iter()
            .any(|(k, v)| k == "verification.source.receipt.sha256"
                && v == &j.cm_application.as_ref().unwrap().receipt_sha256)
    );
    let done = recovery
        .execute_normal_boot(
            prepared["transactionId"].as_str().unwrap(),
            prepared["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(done["state"], "AWAITING_NORMAL_BOOT_COMPLETION");
    assert_eq!(recovery.inventory().unwrap(), baseline);
    recovery.recover().await.unwrap();
    let log = calls(&dir);
    assert_eq!(
        log.iter()
            .filter(|x| x.starts_with("start kura-normal.service"))
            .count(),
        1
    );
    assert_eq!(
        log.iter()
            .filter(|x| x.starts_with("start kura-inverse.service"))
            .count(),
        0
    );
    assert!(recovery.upload("still-blocked", "eA==").await.is_err());
    assert!(
        recovery
            .execute_normal_boot(
                prepared["transactionId"].as_str().unwrap(),
                prepared["confirmToken"].as_str().unwrap()
            )
            .await
            .is_err()
    );
    assert_eq!(
        calls(&dir)
            .iter()
            .filter(|x| x.starts_with("start kura-normal.service"))
            .count(),
        1
    );
}
#[tokio::test]
async fn applied_forward_normal_wrong_token_and_changed_approval_dispatch_no_stop_or_start() {
    let (recovery, dir, source) = applied_fixture().await;
    let recovery = grant(recovery, &dir);
    let before = calls(&dir);
    assert!(
        recovery
            .prepare_applied_normal_boot(source["transactionId"].as_str().unwrap(), "wrong")
            .await
            .is_err()
    );
    assert_eq!(calls(&dir), before);
    let prepared = recovery
        .prepare_applied_normal_boot(
            source["transactionId"].as_str().unwrap(),
            source["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    let before = calls(&dir);
    fs::write(dir.0.join("forward-normal.json"), "{}").unwrap();
    assert!(
        recovery
            .execute_normal_boot(
                prepared["transactionId"].as_str().unwrap(),
                prepared["confirmToken"].as_str().unwrap()
            )
            .await
            .is_err()
    );
    assert_eq!(
        calls(&dir)
            .iter()
            .filter(|x| x.starts_with("start ") || x.starts_with("stop "))
            .collect::<Vec<_>>(),
        before
            .iter()
            .filter(|x| x.starts_with("start ") || x.starts_with("stop "))
            .collect::<Vec<_>>()
    );
}
#[tokio::test]
async fn applied_forward_normal_rejects_snapshot_drift_before_dispatch() {
    let (recovery, dir, source) = applied_fixture().await;
    let recovery = grant(recovery, &dir);
    let before = calls(&dir);
    durable::write(
        &recovery
            .snapshots()
            .unwrap()
            .join("snapshot_9999999999999999.xml"),
        b"unexpected",
        FileMetadata::private(),
    )
    .unwrap();
    assert!(
        recovery
            .prepare_applied_normal_boot(
                source["transactionId"].as_str().unwrap(),
                source["confirmToken"].as_str().unwrap()
            )
            .await
            .is_err()
    );
    let after = calls(&dir);
    assert_eq!(
        after
            .iter()
            .filter(|x| x.starts_with("start ") || x.starts_with("stop "))
            .count(),
        before
            .iter()
            .filter(|x| x.starts_with("start ") || x.starts_with("stop "))
            .count()
    );
}

#[test]
fn applied_forward_profile_rejects_implicit_widened_public_or_unbound_authority() {
    let root = std::env::temp_dir().join(format!("forward-authority-{}", uuid::Uuid::new_v4()));
    durable::directory(&root).unwrap();
    let path = root.join("grant.json");
    let valid = json!({"schema":1,"source":"applied-forward","acceptAppliedForwardSource":true,"normalStartupAuthoritySha256":"a".repeat(64)});
    for patch in [
        json!({"acceptAppliedForwardSource":false}),
        json!({"source":"inverse"}),
        json!({"unexpected":true}),
    ] {
        let mut config = valid.clone();
        for (k, v) in patch.as_object().unwrap() {
            config[k] = v.clone();
        }
        durable::json(&path, &config).unwrap();
        assert!(forward_normal::Profile::new(path.clone()).is_err());
    }
    durable::json(&path, &valid).unwrap();
    let profile = forward_normal::Profile::new(path.clone()).unwrap();
    assert!(profile.inputs(&"b".repeat(64)).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(forward_normal::Profile::new(path.clone()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = root.join("link.json");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(forward_normal::Profile::new(link).is_err());
    fs::remove_dir_all(root).unwrap();
}
#[tokio::test]
async fn applied_forward_source_composes_with_health_completion_and_ordinary_handoff_contracts() {
    let (recovery, dir, source) = applied_fixture().await;
    let recovery = grant(recovery, &dir);
    let normal = recovery
        .prepare_applied_normal_boot(
            source["transactionId"].as_str().unwrap(),
            source["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    recovery
        .execute_normal_boot(
            normal["transactionId"].as_str().unwrap(),
            normal["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    durable::json(&dir.0.join("health.json"),&json!({"schema":1,"componentPids":["pid"],"checkIds":["business.check"],"validForSeconds":300})).unwrap();
    let recovery = tests::grant_health(recovery, &dir);
    let health_sha = durable::hash(&fs::read(dir.0.join("health.json")).unwrap());
    durable::json(&dir.0.join("completion.json"),&json!({"schema":1,"scope":"administrator-selected-checks","releaseOrdinaryWrites":true,"healthGrantSha256":health_sha,"maximumObservationAgeSeconds":300,"validForSeconds":300})).unwrap();
    let recovery = recovery
        .with_completion_profile(dir.0.join("completion.json"))
        .unwrap();
    let health = recovery
        .prepare_health(
            normal["transactionId"].as_str().unwrap(),
            normal["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    let (local, task) = tests::health_bridge(&recovery, "").await;
    recovery
        .execute_health(
            health["transactionId"].as_str().unwrap(),
            health["confirmToken"].as_str().unwrap(),
            local,
        )
        .await
        .unwrap();
    task.abort();
    let completion = recovery
        .prepare_completion(
            health["transactionId"].as_str().unwrap(),
            health["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    let (local, task, count) = completion_tests::bridge(&recovery, "").await;
    recovery
        .execute_completion(
            completion["transactionId"].as_str().unwrap(),
            completion["confirmToken"].as_str().unwrap(),
            local,
        )
        .await
        .unwrap();
    task.abort();
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(recovery.journal().unwrap().unwrap().inverse.is_none());
    recovery.recover().await.unwrap();
    let config = ordinary_tests::profile(&dir);
    let recovery = ordinary_tests::grant(recovery, &dir, &config);
    let ordinary = recovery
        .prepare_ordinary(
            completion["transactionId"].as_str().unwrap(),
            completion["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    let (local, task, count) = ordinary_tests::bridge("").await;
    let result = recovery
        .execute_ordinary(
            ordinary["transactionId"].as_str().unwrap(),
            ordinary["confirmToken"].as_str().unwrap(),
            local,
        )
        .await
        .unwrap();
    task.abort();
    assert_eq!(result["ordinaryUnitHandedOff"], true);
    assert_eq!(
        recovery.journal().unwrap().unwrap().state,
        State::OrdinaryActiveApprovedChecks
    );
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    recovery.recover().await.unwrap();
    assert!(recovery.journal().unwrap().unwrap().inverse.is_none());
    assert_eq!(
        calls(&dir)
            .iter()
            .filter(|x| x.starts_with("start kura-inverse.service"))
            .count(),
        0
    );
}

#[tokio::test]
async fn applied_forward_normal_dispatch_failure_is_retained_and_cannot_branch_to_inverse() {
    let (recovery, dir, source) = applied_fixture().await;
    let recovery = grant(recovery, &dir);
    let normal = recovery
        .prepare_applied_normal_boot(
            source["transactionId"].as_str().unwrap(),
            source["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    fs::write(dir.0.join("normal-receipt.py"), "raise SystemExit(1)\n").unwrap();
    assert!(
        recovery
            .execute_normal_boot(
                normal["transactionId"].as_str().unwrap(),
                normal["confirmToken"].as_str().unwrap()
            )
            .await
            .is_err()
    );
    let journal = recovery.journal().unwrap().unwrap();
    assert_eq!(journal.state, State::RecoveryRequired);
    assert!(journal.normal_boot.as_ref().unwrap().issued);
    let before = calls(&dir);
    assert!(
        recovery
            .execute_normal_boot(
                normal["transactionId"].as_str().unwrap(),
                normal["confirmToken"].as_str().unwrap()
            )
            .await
            .is_err()
    );
    assert!(
        recovery
            .prepare_compensation(
                source["transactionId"].as_str().unwrap(),
                source["confirmToken"].as_str().unwrap()
            )
            .await
            .is_err()
    );
    assert_eq!(calls(&dir), before);
    assert!(recovery.journal().unwrap().unwrap().inverse.is_none());
}
