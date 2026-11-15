use super::tests::{TempDir, calls, grant_health, health_bridge, health_ready_fixture};
use super::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) async fn ready() -> (Recovery, TempDir, Value) {
    let (recovery, dir, normal) = health_ready_fixture().await;
    let recovery = grant_health(recovery, &dir);
    let health_sha = durable::hash(&fs::read(dir.0.join("health.json")).unwrap());
    durable::json(
        &dir.0.join("completion.json"),
        &json!({"schema":1,"scope":"administrator-selected-checks","releaseOrdinaryWrites":true,
        "healthGrantSha256":health_sha,"maximumObservationAgeSeconds":300,"validForSeconds":300}),
    )
    .unwrap();
    let recovery = recovery
        .with_completion_profile(dir.0.join("completion.json"))
        .unwrap();
    let prepared = recovery
        .prepare_health(
            normal["transactionId"].as_str().unwrap(),
            normal["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    let (local, task) = health_bridge(&recovery, "").await;
    recovery
        .execute_health(
            prepared["transactionId"].as_str().unwrap(),
            prepared["confirmToken"].as_str().unwrap(),
            local,
        )
        .await
        .unwrap();
    task.abort();
    (recovery, dir, prepared)
}
pub(super) async fn bridge(
    recovery: &Recovery,
    mode: &str,
) -> (
    crate::local::Local,
    tokio::task::JoinHandle<()>,
    Arc<AtomicUsize>,
) {
    let local = crate::local::Local::new(unsafe { libc::geteuid() }, unsafe { libc::geteuid() });
    let mut rx = local.install_test_bridge(&["kura.recovery.complete"]).await;
    let j = recovery.journal().unwrap().unwrap();
    let normal = j.normal_boot.unwrap();
    let receipt = PathBuf::from(format!(
        "{}.write-release.properties",
        normal.startup.receipt_path.display()
    ));
    let health = serde_json::to_value(j.health.unwrap().evidence.unwrap().report).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let peer = local.clone();
    let mode = mode.to_owned();
    let task = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            seen.fetch_add(1, Ordering::SeqCst);
            let p = frame.params.unwrap();
            if mode == "no-receipt" {
                peer.complete_pending(&frame.request_id, None, Some("OUTCOME_UNKNOWN"));
                continue;
            }
            let c = &p["challenge"];
            let b = &p["bounds"];
            let hash_names = |a: &Value| {
                durable::hash(
                    a.as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap())
                        .collect::<Vec<_>>()
                        .join("\0")
                        .as_bytes(),
                )
            };
            let text = |v: &Value| v.as_str().unwrap().to_owned();
            let mut fields = BTreeMap::from([
                ("schema", "yofc.kura.write-release.v1".to_owned()),
                ("status", "ORDINARY_WRITES_RELEASE_COMMITTED".to_owned()),
                ("scope", "administrator-selected-checks".to_owned()),
                ("completion.id", text(&p["completionId"])),
                ("recovery.id", text(&c["recoveryId"])),
                ("snapshot.sha256", text(&c["snapshotSha256"])),
                ("decision.sha256", text(&p["decisionSha256"])),
                ("health.receipt.sha256", text(&p["healthReceiptSha256"])),
                ("policy.sha256", text(&p["policySha256"])),
                ("nonce", text(&c["nonce"])),
                ("process.id", "123".into()),
                ("source.count", b["sourceCount"].to_string()),
                ("managed.count", b["managedCount"].to_string()),
                ("property.count", b["propertyCount"].to_string()),
                ("components.sha256", hash_names(&c["componentPids"])),
                ("checks.sha256", hash_names(&c["checkIds"])),
                (
                    "additional.grant.sha256",
                    hash_names(&c["additionalSelfPids"]),
                ),
                (
                    "additional.observed.sha256",
                    hash_names(&b["materializedSelfPids"]),
                ),
                ("kuraRecoveryVerified", "false".into()),
            ]);
            if mode == "wrong-receipt" {
                fields.insert("nonce", "0".repeat(64));
            }
            let body = fields
                .iter()
                .map(|(k, v)| format!("{k}={v}\n"))
                .collect::<String>();
            durable::publish_new(&receipt, body.as_bytes(), FileMetadata::private()).unwrap();
            if mode == "lost-response" {
                peer.complete_pending(&frame.request_id, None, Some("OUTCOME_UNKNOWN"));
                continue;
            }
            let mut fresh = health.clone();
            fresh["nonce"] = c["nonce"].clone();
            let report = json!({"schema":1,"completionId":p["completionId"],"recoveryId":c["recoveryId"],"snapshotSha256":c["snapshotSha256"],
                "decisionSha256":p["decisionSha256"],"receiptSha256":durable::hash(body.as_bytes()),"processId":123,
                "writeReleaseCommitted":true,"kuraRecoveryVerified":false,"preReleaseHealth":fresh});
            peer.complete_pending(&frame.request_id, Some(report), None);
        }
    });
    (local, task, count)
}
async fn prepare(recovery: &Recovery, health: &Value) -> Value {
    recovery
        .prepare_completion(
            health["transactionId"].as_str().unwrap(),
            health["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap()
}
async fn execute(recovery: &Recovery, p: &Value, local: crate::local::Local) -> Result<Value> {
    recovery
        .execute_completion(
            p["transactionId"].as_str().unwrap(),
            p["confirmToken"].as_str().unwrap(),
            local,
        )
        .await
}
#[tokio::test]
async fn completion_commits_selected_scope_releases_agent_guard_and_preserves_legitimate_later_changes()
 {
    let (recovery, dir, health) = ready().await;
    let before = calls(&dir);
    let p = prepare(&recovery, &health).await;
    assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_err());
    let (local, task, count) = bridge(&recovery, "").await;
    let result = execute(&recovery, &p, local.clone()).await.unwrap();
    assert_eq!(result["scope"], "administrator-selected-checks");
    assert_eq!(result["writeReleaseCommitted"], true);
    assert_eq!(result["kuraReleaseReplyVerified"], true);
    assert_eq!(result["kuraRecoveryVerified"], false);
    assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_ok());
    assert!(execute(&recovery, &p, local).await.is_err());
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let post_completion_calls = calls(&dir);
    // Ordinary snapshots and unit availability are mutable after the durable release decision.
    fs::write(
        recovery
            .0
            .root
            .join(&recovery.0.snapshots)
            .join("snapshot_999.xml"),
        b"legitimate later snapshot",
    )
    .unwrap();
    recovery.recover().await.unwrap();
    assert_eq!(
        recovery.journal().unwrap().unwrap().state,
        State::CompletedApprovedChecks
    );
    assert_eq!(calls(&dir), post_completion_calls);
    let mutations = |rows: Vec<String>| {
        rows.into_iter()
            .filter(|s| s.starts_with("start ") || s.starts_with("stop "))
            .collect::<Vec<_>>()
    };
    assert_eq!(mutations(calls(&dir)), mutations(before));
    assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_ok());
    task.abort();
}
#[tokio::test]
async fn completion_lost_reply_uses_durable_receipt_without_resend_and_recovers_final_journal_crash_window()
 {
    let (recovery, dir, health) = ready().await;
    let p = prepare(&recovery, &health).await;
    let (local, task, count) = bridge(&recovery, "lost-response").await;
    execute(&recovery, &p, local).await.unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let before = calls(&dir);
    let path = recovery.0.state.join("transaction.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["state"] = json!("COMMITTING_COMPLETION");
    value["completion"]["completed"] = json!(false);
    value["completion"]["java_receipt_sha256"] = Value::Null;
    durable::json(&path, &value).unwrap();
    fs::remove_file(recovery.0.state.join("receipts").join(format!(
        "{}.completed.json",
        p["transactionId"].as_str().unwrap()
    )))
    .unwrap();
    recovery.recover().await.unwrap();
    assert_eq!(
        recovery.journal().unwrap().unwrap().state,
        State::CompletedApprovedChecks
    );
    assert_eq!(calls(&dir), before);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    task.abort();
}
#[tokio::test]
async fn completion_unknown_or_wrong_receipt_stops_units_retains_decision_and_never_repeats_write()
{
    for mode in ["no-receipt", "wrong-receipt"] {
        let (recovery, dir, health) = ready().await;
        let p = prepare(&recovery, &health).await;
        let (local, task, count) = bridge(&recovery, mode).await;
        assert!(execute(&recovery, &p, local.clone()).await.is_err());
        assert_eq!(
            recovery.journal().unwrap().unwrap().state,
            State::RecoveryRequired
        );
        assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_err());
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let decision = recovery.0.state.join("receipts").join(format!(
            "{}.decision.json",
            p["transactionId"].as_str().unwrap()
        ));
        let bytes = fs::read(&decision).unwrap();
        let before = calls(&dir);
        assert!(execute(&recovery, &p, local).await.is_err());
        assert!(recovery.recover().await.is_err());
        assert_eq!(fs::read(decision).unwrap(), bytes);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(
            calls(&dir)
                .iter()
                .filter(|s| s.starts_with("start "))
                .count(),
            before.iter().filter(|s| s.starts_with("start ")).count()
        );
        task.abort();
    }
}
#[tokio::test]
async fn completion_rejects_stale_health_changed_approval_and_wrong_token_before_attempt() {
    for mode in ["approval", "stale"] {
        let (recovery, dir, health) = ready().await;
        let p = prepare(&recovery, &health).await;
        let (local, task, count) = bridge(&recovery, "").await;
        assert!(
            recovery
                .execute_completion(
                    p["transactionId"].as_str().unwrap(),
                    health["confirmToken"].as_str().unwrap(),
                    local.clone()
                )
                .await
                .is_err()
        );
        if mode == "approval" {
            let path = dir.0.join("completion.json");
            let mut c: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            c["releaseOrdinaryWrites"] = json!(false);
            durable::json(&path, &c).unwrap();
        } else {
            let path = recovery.0.state.join("transaction.json");
            let mut c: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            c["completion"]["not_after"] = json!(1);
            durable::json(&path, &c).unwrap();
        }
        assert!(execute(&recovery, &p, local).await.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_err());
        task.abort();
    }
}
