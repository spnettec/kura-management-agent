use super::tests::{TempDir, calls};
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

async fn completed() -> (Recovery, TempDir, Value) {
    let (r, d, h) = super::completion_tests::ready().await;
    let p = r
        .prepare_completion(
            h["transactionId"].as_str().unwrap(),
            h["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    let (local, task, _) = super::completion_tests::bridge(&r, "").await;
    r.execute_completion(
        p["transactionId"].as_str().unwrap(),
        p["confirmToken"].as_str().unwrap(),
        local,
    )
    .await
    .unwrap();
    task.abort();
    (r, d, p)
}
fn declaration(c: &ordinary_profile::Config) -> String {
    format!(
        "FragmentPath={}\nDropInPaths=\nExecStart={{ path=/jdk/bin/java ; argv[]=/jdk/bin/java @{} -jar /launcher.jar ; ignore_errors=no ; pid=0 }}\nEnvironment=\nUnsetEnvironment=JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS _JAVA_OPTIONS\nNeedDaemonReload=no\n",
        c.unit_file.display(),
        c.jvm_args_path.display()
    )
}
fn declaration_hash(text: &str) -> String {
    let mut fields = text
        .lines()
        .map(|l| l.split_once('=').unwrap())
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect::<std::collections::BTreeMap<_, _>>();
    fields.insert("EnvironmentFiles".into(), String::new());
    let value = fields["ExecStart"]
        .split_once(" ; ignore_errors=")
        .unwrap()
        .0
        .to_owned();
    fields.insert("ExecStart".into(), value);
    durable::hash(
        fields
            .iter()
            .map(|(k, v)| format!("{k}={v}\n"))
            .collect::<String>()
            .as_bytes(),
    )
}
pub(super) fn profile(dir: &TempDir) -> ordinary_profile::Config {
    let unit_file = dir.0.join("ordinary.service");
    fs::write(&unit_file, b"reviewed unit").unwrap();
    let args = dir.0.join("ordinary.args");
    fs::write(&args,b"-Xmx256m\n-Dkura.management.ordinary.profile.id=profile-11111111-1111-1111-1111-111111111111\n-Dkura.management.ordinary.verification.enabled=true\n").unwrap();
    let mut c = ordinary_profile::Config {
        schema: 1,
        launcher_kind: ordinary_profile::Launcher::DirectJava,
        launcher_script_path: None,
        profile_id: "profile-11111111-1111-1111-1111-111111111111".into(),
        unit: "kura-ordinary.service".into(),
        unit_file: unit_file.clone(),
        jvm_args_path: args.clone(),
        unit_definition_sha256: "0".repeat(64),
        timeout_seconds: 2,
        valid_for_seconds: 300,
        component_pids: vec!["pid".into()],
        check_ids: vec!["business.check".into()],
        profile_files: vec![unit_file, args]
            .into_iter()
            .map(|p| ordinary_profile::File {
                sha256: durable::hash(&fs::read(&p).unwrap()),
                path: p,
            })
            .collect(),
    };
    c.unit_definition_sha256 = declaration_hash(&declaration(&c));
    c
}
pub(super) fn grant(mut r: Recovery, d: &TempDir, c: &ordinary_profile::Config) -> Recovery {
    let normal = r.journal().unwrap().unwrap().normal_boot.unwrap().unit;
    let script = format!(
        r#"#!/bin/sh
echo "$@" >> '{root}/systemctl.log'
if [ "$1" = show ] && [ "$3" = --all ]; then cat '{root}/unit-definition'; exit 0; fi
case "$1" in
stop) printf inactive > '{root}/state-'"$2";;
start) printf active > '{root}/state-'"$2";;
show)
 s=$(cat '{root}/state-'"$2" 2>/dev/null || echo inactive)
 echo LoadState=loaded; echo ActiveState=$s
 if [ "$s" = active ]; then
  if [ "$2" = kura-ordinary.service ]; then echo MainPID=234; else echo MainPID=123; fi
 else echo MainPID=0; fi;;
esac
"#,
        root = d.0.display()
    );
    fs::write(&r.0.systemctl, script).unwrap();
    fs::write(d.0.join(format!("state-{normal}")), "active").unwrap();
    fs::write(d.0.join("unit-definition"), declaration(c)).unwrap();
    durable::json(&d.0.join("ordinary.json"), c).unwrap();
    Arc::get_mut(&mut r.0).unwrap().units.push(c.unit.clone());
    r.with_ordinary_profile(d.0.join("ordinary.json")).unwrap()
}
async fn prepare(r: &Recovery, p: &Value) -> Value {
    r.prepare_ordinary(
        p["transactionId"].as_str().unwrap(),
        p["confirmToken"].as_str().unwrap(),
    )
    .await
    .unwrap()
}
async fn execute(r: &Recovery, p: &Value, l: crate::local::Local) -> Result<Value> {
    r.execute_ordinary(
        p["transactionId"].as_str().unwrap(),
        p["confirmToken"].as_str().unwrap(),
        l,
    )
    .await
}
pub(super) async fn bridge(
    mode: &str,
) -> (
    crate::local::Local,
    tokio::task::JoinHandle<()>,
    Arc<AtomicUsize>,
) {
    let l = crate::local::Local::new(unsafe { libc::geteuid() }, unsafe { libc::geteuid() });
    let mut rx = l.install_test_bridge(&["kura.ordinary.verify"]).await;
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let peer = l.clone();
    let mode = mode.to_owned();
    let task = tokio::spawn(async move {
        while let Some(f) = rx.recv().await {
            let n = seen.fetch_add(1, Ordering::SeqCst);
            let p = f.params.unwrap();
            let mut v = json!({"schema":2,"handoffId":p["handoffId"],"profileId":p["profileId"],"nonce":p["nonce"],"approvedSnapshotSha256":p["snapshotSha256"],"observerInstanceId":"22222222-2222-2222-2222-222222222222","processId":234,"frameworkStartLevel":5,"ordinaryLoad":true,"ready":true,"components":[{"pid":"pid","registered":true}],"providers":[{"id":"business.check","available":true,"unique":true}],"checks":[{"id":"business.check","passed":true}]});
            match mode.as_str() {
                "business" => v["checks"][0]["passed"] = json!(false),
                "pid" => v["processId"] = json!(123),
                "profile" => v["profileId"] = json!("profile-wrong"),
                "nonce" => v["nonce"] = json!("0".repeat(64)),
                "recovery" => v["ordinaryLoad"] = json!(false),
                "extra" => v["unapproved"] = json!(true),
                "provider-waiting" if n == 0 => {
                    v["providers"][0]["available"] = json!(false);
                    v["providers"][0]["unique"] = json!(false);
                    v["ready"] = json!(false);
                    v["checks"][0]["passed"] = json!(false);
                }
                "legacy-live" => {
                    v["schema"] = json!(1);
                    v.as_object_mut().unwrap().remove("providers");
                }
                "provider-id" => v["providers"][0]["id"] = json!("unapproved"),
                "duplicate" => {
                    v["providers"][0]["unique"] = json!(false);
                    v["checks"][0]["passed"] = json!(false);
                }
                "duplicate-passed" => v["providers"][0]["unique"] = json!(false),
                "duplicate-waiting" => {
                    v["providers"][0]["unique"] = json!(false);
                    v["frameworkStartLevel"] = json!(4);
                    v["ready"] = json!(false);
                    v["checks"][0]["passed"] = json!(false);
                }
                "waiting" if n == 0 => {
                    v["frameworkStartLevel"] = json!(4);
                    v["ready"] = json!(false);
                    v["checks"][0]["passed"] = json!(false);
                }
                _ => {}
            }
            peer.complete_pending(&f.request_id, Some(v), None);
        }
    });
    (l, task, count)
}
fn starts(d: &TempDir) -> usize {
    calls(d).iter().filter(|s| s.starts_with("start ")).count()
}
#[tokio::test]
async fn selected_profile_runtime_reopens_recovery_and_keeps_original_status_when_the_ordinary_source_is_temporarily_absent() {
    let (r,d,completion)=completed().await;let c=profile(&d);let r=grant(r,&d,&c);
    let origin=d.0.join("ordinary.json");let retained=d.0.join("ordinary.args.retained");fs::rename(&c.jvm_args_path,&retained).unwrap();
    assert!(ordinary_profile::Profile::new(origin.clone()).is_err(),"the old eager constructor cannot initialize this interrupted material");
    let mut reopened=Recovery::open(r.0.root.clone(),r.0.state_root.clone(),r.0.units.clone(),r.0.snapshots.clone(),Some(r.0.systemctl.clone())).unwrap();
    let engine=Arc::get_mut(&mut reopened.0).unwrap();
    engine.startup=r.0.startup.clone();engine.inverse_startup=r.0.inverse_startup.clone();engine.normal_startup=r.0.normal_startup.clone();
    engine.health=r.0.health.clone();engine.completion=r.0.completion.clone();
    let reopened=reopened.with_ordinary_profile(origin).unwrap();assert!(reopened.0.ordinary.as_ref().unwrap().inputs().is_err());
    let before=r.status().await.unwrap();let operations=calls(&d);let bytes=fs::read(r.0.state.join("transaction.json")).unwrap();
    assert_eq!(reopened.status().await.unwrap()["transaction"],before["transaction"]);
    assert!(reopened.prepare_ordinary(completion["transactionId"].as_str().unwrap(),completion["confirmToken"].as_str().unwrap()).await.is_err());
    assert_eq!(calls(&d),operations);assert_eq!(fs::read(reopened.0.state.join("transaction.json")).unwrap(),bytes);assert!(retained.exists());assert!(!c.jvm_args_path.exists());
}

fn remote_command(operation: i32) -> yofc_management_protocol::v1::ReadCommand {
    yofc_management_protocol::v1::ReadCommand {
        command_id: uuid::Uuid::new_v4().to_string(),
        operation,
        expires_at_unix_ms: i64::MAX,
        idempotency_key: uuid::Uuid::new_v4().to_string(),
        ..Default::default()
    }
}

#[tokio::test]
async fn lost_handoff_receipts_resolve_only_from_bound_committed_evidence_without_live_operations()
{
    use yofc_management_protocol::v1::*;
    let (r, d, _) = completed().await;
    let c = profile(&d);
    let r = grant(r, &d, &c);
    let path = d.0.join("lost-receipt.sqlite");
    let db = crate::transport::database(path.to_str().unwrap())
        .await
        .unwrap();
    let r = r.with_execution_database(path);
    let (mut l, task, seen) = bridge("").await;
    l.recovery = Some(r.clone());
    l.ordinary_handoff_remote = true;
    let prepare = remote_command(21);
    let original = crate::transport::execute(&db, &l, prepare.clone())
        .await
        .unwrap();
    assert_eq!(original.state, TaskState::Succeeded as i32);
    let p: Value = serde_json::from_slice(&original.result_json).unwrap();
    sqlx::query("UPDATE executions SET state='RUNNING',result=NULL WHERE command_id=?")
        .bind(&prepare.command_id)
        .execute(&db)
        .await
        .unwrap();
    crate::journal::initialize(&db).await.unwrap();
    let before = calls(&d);
    let journal = fs::read(r.0.state.join("transaction.json")).unwrap();
    let proof = crate::transport::query_receipt(&db, &l, &prepare.command_id)
        .await
        .unwrap();
    assert_eq!(proof.state, TaskState::Succeeded as i32);
    let mut value: Value = serde_json::from_slice(&proof.result_json).unwrap();
    assert_eq!(
        value["reconciliation"]["source"],
        "ordinary.handoff.journal.v1"
    );
    value.as_object_mut().unwrap().remove("reconciliation");
    assert_eq!(value, p);
    assert_eq!(calls(&d), before);
    assert_eq!(
        fs::read(r.0.state.join("transaction.json")).unwrap(),
        journal
    );
    let mut execute = remote_command(22);
    execute.ordinary_handoff_action = Some(OrdinaryHandoffAction {
        transaction_id: p["transactionId"].as_str().unwrap().into(),
        confirmation_token: p["confirmToken"].as_str().unwrap().into(),
    });
    let original = crate::transport::execute(&db, &l, execute.clone())
        .await
        .unwrap();
    assert_eq!(original.state, TaskState::Succeeded as i32);
    sqlx::query("UPDATE executions SET state='RUNNING',result=NULL WHERE command_id=?")
        .bind(&execute.command_id)
        .execute(&db)
        .await
        .unwrap();
    crate::journal::initialize(&db).await.unwrap();
    let before = calls(&d);
    let observed = seen.load(Ordering::SeqCst);
    task.abort();
    let journal_path = r.0.state.join("transaction.json");
    let journal = fs::read(&journal_path).unwrap();
    let native: Value = serde_json::from_slice(&journal).unwrap();
    let command_path =
        r.0.state
            .join("commands")
            .join(format!("{}.json", execute.command_id));
    let decision = fs::read(&command_path).unwrap();
    // All wire fields, including the original token and expiry, participate.
    for n in 0..5 {
        let mut changed = execute.clone();
        match n {
            0 => changed.expires_at_unix_ms -= 1,
            1 => changed.idempotency_key.push('x'),
            2 => changed.command_id = uuid::Uuid::new_v4().to_string(),
            3 => {
                changed
                    .ordinary_handoff_action
                    .as_mut()
                    .unwrap()
                    .confirmation_token = uuid::Uuid::new_v4().to_string()
            }
            _ => changed.operation = 21,
        }
        assert!(r.prove_ordinary_command(&changed).await.unwrap().is_none());
    }
    for state in ["VERIFYING_ORDINARY", "RECOVERY_REQUIRED"] {
        let mut bad = native.clone();
        bad["state"] = json!(state);
        durable::json(&journal_path, &bad).unwrap();
        let bytes = fs::read(&journal_path).unwrap();
        assert!(r.prove_ordinary_command(&execute).await.unwrap().is_none());
        assert_eq!(fs::read(&journal_path).unwrap(), bytes);
        assert!(
            crate::system_change::Guard::acquire(
                &r.0.state_root,
                crate::system_change::Subsystem::Configuration
            )
            .is_err()
        );
        // The earlier prepare decision remains true without clearing this gate.
        assert!(r.prove_ordinary_command(&prepare).await.unwrap().is_some());
        assert_eq!(fs::read(&journal_path).unwrap(), bytes);
    }
    durable::write(&journal_path, &journal, FileMetadata::private()).unwrap();
    fs::write(&command_path, [decision.as_slice(), b" "].concat()).unwrap();
    assert!(r.prove_ordinary_command(&execute).await.unwrap().is_none());
    durable::write(&command_path, &decision, FileMetadata::private()).unwrap();
    fs::set_permissions(&command_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(r.prove_ordinary_command(&execute).await.unwrap().is_none());
    fs::set_permissions(&command_path, fs::Permissions::from_mode(0o600)).unwrap();
    let native_receipt = r.0.state.join("receipts").join(format!(
        "{}.ordinary.json",
        p["transactionId"].as_str().unwrap()
    ));
    let receipt = fs::read(&native_receipt).unwrap();
    fs::write(&native_receipt, b"{}").unwrap();
    assert!(r.prove_ordinary_command(&execute).await.unwrap().is_none());
    durable::write(&native_receipt, &receipt, FileMetadata::private()).unwrap();
    let (a, b) = tokio::join!(
        crate::transport::query_receipt(&db, &l, &execute.command_id),
        crate::transport::query_receipt(&db, &l, &execute.command_id)
    );
    let a = a.unwrap();
    assert_eq!(a, b.unwrap());
    assert_eq!(a.state, TaskState::Succeeded as i32);
    let mut result: Value = serde_json::from_slice(&a.result_json).unwrap();
    result.as_object_mut().unwrap().remove("reconciliation");
    assert_eq!(
        result,
        serde_json::from_slice::<Value>(&original.result_json).unwrap()
    );
    assert_eq!(calls(&d), before);
    assert_eq!(seen.load(Ordering::SeqCst), observed);
    assert_eq!(fs::read(&journal_path).unwrap(), journal);
    assert_eq!(fs::read(&native_receipt).unwrap(), receipt);
    let resolutions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM execution_resolutions WHERE command_id=?")
            .bind(&execute.command_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(resolutions, 1);
    // A later legitimate recovery keeps the original command proof independent
    // of current units, current grants and the new mutable journal.
    let j = r.journal().unwrap().unwrap();
    drop(l);
    let mut next: Value =
        serde_json::from_slice(&fs::read(d.0.join("startup.json")).unwrap()).unwrap();
    durable::directory(&d.0.join("next-startup")).unwrap();
    next["requestPath"] = json!(d.0.join("next-startup/request.properties"));
    let config = d.0.join("next-startup.json");
    durable::json(&config, &next).unwrap();
    let r = r
        .with_controlled_startup(crate::controlled_startup::Startup::new(config).unwrap())
        .unwrap();
    r.prepare(&j.upload_id, &j.sha256, &j.unit).await.unwrap();
    let after = calls(&d);
    assert!(r.prove_ordinary_command(&execute).await.unwrap().is_some());
    assert!(r.prove_ordinary_command(&prepare).await.unwrap().is_some());
    assert_eq!(calls(&d), after);
    db.close().await;
}

#[tokio::test]
async fn missing_handoff_journal_never_adopts_retained_command_evidence() {
    let (r, d, _) = completed().await;
    let c = profile(&d);
    let r = grant(r, &d, &c);
    let commands = r.0.state.join("commands");
    durable::directory(&commands).unwrap();
    durable::json(&commands.join("retained.json"), &json!({"unlinked":true})).unwrap();
    fs::rename(
        r.0.state.join("transaction.json"),
        r.0.state.join("transaction.retained.json"),
    )
    .unwrap();
    let before = calls(&d);
    assert!(r.journal().is_err());
    for caller in [
        crate::system_change::Subsystem::Network,
        crate::system_change::Subsystem::Firewall,
        crate::system_change::Subsystem::Configuration,
        crate::system_change::Subsystem::Identity,
        crate::system_change::Subsystem::OrdinaryBoot,
    ] {
        assert!(crate::system_change::Guard::acquire(&r.0.state_root, caller).is_err());
    }
    assert_eq!(calls(&d), before);
    assert!(commands.join("retained.json").exists());
}
#[tokio::test]
async fn remote_ordinary_uses_current_completion_and_exact_admission_then_replays_only_the_receipt()
{
    use yofc_management_protocol::v1::*;
    let (r, d, _) = completed().await;
    let c = profile(&d);
    let r = grant(r, &d, &c);
    let path = d.0.join("remote.sqlite");
    let db = crate::transport::database(path.to_str().unwrap())
        .await
        .unwrap();
    let r = r.with_execution_database(path);
    let (mut l, bridge, _) = bridge("waiting").await;
    l.recovery = Some(r.clone());
    let off = crate::transport::execute(&db, &l, remote_command(20))
        .await
        .unwrap();
    assert_eq!(off.error, ErrorCode::Unsupported as i32);
    l.ordinary_handoff_remote = true;
    let status = crate::transport::execute(&db, &l, remote_command(20))
        .await
        .unwrap();
    let status: Value = serde_json::from_slice(&status.result_json).unwrap();
    assert_eq!(status["canPrepare"], true);
    assert!(!status.to_string().contains("confirmToken"));
    let prepare = remote_command(21);
    // A copied UUID without its exact, still-running durable admission grants nothing.
    assert!(
        r.remote_ordinary(&prepare, l.clone())
            .await
            .unwrap_err()
            .to_string()
            .starts_with("CONFLICT")
    );
    let before = starts(&d);
    let result = crate::transport::execute(&db, &l, prepare.clone())
        .await
        .unwrap();
    assert_eq!(result.state, TaskState::Succeeded as i32);
    let p: Value = serde_json::from_slice(&result.result_json).unwrap();
    assert_eq!(p["state"], "ORDINARY_PREPARED");
    assert_eq!(p["unit"], "kura-ordinary.service");
    assert_eq!(p["checkIds"], json!(["business.check"]));
    assert_eq!(starts(&d), before);
    assert_eq!(
        crate::transport::execute(&db, &l, prepare).await.unwrap(),
        result
    );
    let mut execute = remote_command(22);
    execute.ordinary_handoff_action = Some(OrdinaryHandoffAction {
        transaction_id: p["transactionId"].as_str().unwrap().into(),
        confirmation_token: p["confirmToken"].as_str().unwrap().into(),
    });
    let result = crate::transport::execute(&db, &l, execute.clone())
        .await
        .unwrap();
    assert_eq!(result.state, TaskState::Succeeded as i32);
    let v: Value = serde_json::from_slice(&result.result_json).unwrap();
    assert_eq!(v["state"], "ORDINARY_ACTIVE_APPROVED_CHECKS");
    assert_eq!(v["ordinaryUnitHandedOff"], true);
    assert_eq!(v["normalBootVerified"], false);
    assert_eq!(v["kuraRecoveryVerified"], false);
    assert_eq!(starts(&d), before + 1);
    r.recover().await.unwrap();
    assert_eq!(
        crate::transport::execute(&db, &l, execute).await.unwrap(),
        result
    );
    assert_eq!(starts(&d), before + 1);
    let secrets: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT result FROM executions WHERE operation=21")
            .fetch_all(&db)
            .await
            .unwrap();
    let token = p["confirmToken"].as_str().unwrap().as_bytes();
    assert!(
        secrets
            .iter()
            .all(|s| !s.windows(token.len()).any(|w| w == token))
    );
    bridge.abort();
    db.close().await;
}
#[tokio::test]
async fn remote_ordinary_cannot_exclude_another_admission_or_a_different_wire_command() {
    use prost::Message;
    use sha2::{Digest, Sha256};
    let (r, d, _) = completed().await;
    let c = profile(&d);
    let r = grant(r, &d, &c);
    let path = d.0.join("remote.sqlite");
    let db = crate::transport::database(path.to_str().unwrap())
        .await
        .unwrap();
    let r = r.with_execution_database(path);
    let l = crate::local::Local::new(0, 0);
    let command = remote_command(21);
    let hash = format!("{:x}", Sha256::digest(command.encode_to_vec()));
    crate::journal::claim(&db, &command, &hash).await.unwrap();
    let mut forged = command.clone();
    forged.idempotency_key.push('x');
    assert!(
        r.remote_ordinary(&forged, l.clone())
            .await
            .unwrap_err()
            .to_string()
            .starts_with("CONFLICT")
    );
    let other = remote_command(99);
    crate::journal::claim(
        &db,
        &other,
        &format!("{:x}", Sha256::digest(other.encode_to_vec())),
    )
    .await
    .unwrap();
    let before = calls(&d);
    assert!(
        r.remote_ordinary(&command, l)
            .await
            .unwrap_err()
            .to_string()
            .starts_with("CONFLICT")
    );
    assert_eq!(before, calls(&d));
    assert_eq!(
        r.remote_ordinary(&remote_command(20), crate::local::Local::new(0, 0))
            .await
            .unwrap()["canPrepare"],
        true
    );
    db.close().await;
}
#[tokio::test]
async fn ordinary_handoff_starts_fixed_unit_once_and_recovers_receipt_without_restarting_or_rechecking_mutable_state()
 {
    let (r, d, old) = completed().await;
    let c = profile(&d);
    let r = grant(r, &d, &c);
    let before = starts(&d);
    let p = prepare(&r, &old).await;
    assert!(Guard::acquire(&r.0.state_root, Subsystem::Configuration).is_err());
    // Reopening a prepared, unissued transaction is read-only.
    let mutations = calls(&d)
        .iter()
        .filter(|s| s.starts_with("start ") || s.starts_with("stop "))
        .count();
    r.recover().await.unwrap();
    assert_eq!(
        mutations,
        calls(&d)
            .iter()
            .filter(|s| s.starts_with("start ") || s.starts_with("stop "))
            .count()
    );
    let (l, t, count) = bridge("waiting").await;
    let result = execute(&r, &p, l.clone()).await.unwrap();
    assert_eq!(result["ordinaryUnitHandedOff"], true);
    assert_eq!(result["kuraRecoveryVerified"], false);
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert_eq!(starts(&d), before + 1);
    assert!(execute(&r, &p, l).await.is_err());
    assert!(Guard::acquire(&r.0.state_root, Subsystem::Configuration).is_ok());
    let path = r.0.state.join("transaction.json");
    let mut v: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    v["state"] = json!("VERIFYING_ORDINARY");
    v["ordinary"]["verified"] = json!(false);
    v["ordinary"]["receipt_sha256"] = Value::Null;
    durable::json(&path, &v).unwrap();
    fs::write(
        r.snapshots().unwrap().join("snapshot_999.xml"),
        b"legitimate later configuration",
    )
    .unwrap();
    fs::write(&c.jvm_args_path, b"legitimate later profile upgrade").unwrap();
    let calls_before = calls(&d);
    r.recover().await.unwrap();
    assert_eq!(
        r.journal().unwrap().unwrap().state,
        State::OrdinaryActiveApprovedChecks
    );
    assert_eq!(calls(&d), calls_before);
    t.abort();
}
#[tokio::test]
async fn ordinary_failed_business_or_identity_stops_all_four_units_and_never_retries() {
    for mode in [
        "business",
        "pid",
        "profile",
        "nonce",
        "recovery",
        "extra",
        "legacy-live",
        "provider-id",
        "duplicate",
        "duplicate-passed",
        "duplicate-waiting",
    ] {
        let (r, d, old) = completed().await;
        let c = profile(&d);
        let r = grant(r, &d, &c);
        let p = prepare(&r, &old).await;
        let (l, t, count) = bridge(mode).await;
        assert!(execute(&r, &p, l.clone()).await.is_err(), "{mode}");
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "a definitive failure must not be polled into success"
        );
        let j = r.journal().unwrap().unwrap();
        assert_eq!(j.state, State::RecoveryRequired);
        assert!(Guard::acquire(&r.0.state_root, Subsystem::Configuration).is_err());
        for unit in [
            &j.unit,
            &j.inverse.unwrap().unit,
            &j.normal_boot.unwrap().unit,
            &c.unit,
        ] {
            r.stopped(unit).unwrap();
        }
        let n = starts(&d);
        assert!(execute(&r, &p, l).await.is_err());
        assert!(r.recover().await.is_err());
        assert_eq!(starts(&d), n);
        t.abort();
    }
}
#[tokio::test]
async fn ordinary_interrupted_intent_never_starts_and_changed_approval_fails_before_unit_mutation()
{
    for mode in ["issued", "args", "snapshot", "definition"] {
        let (r, d, old) = completed().await;
        let c = profile(&d);
        let r = grant(r, &d, &c);
        let p = prepare(&r, &old).await;
        let before = starts(&d);
        let (l, t, _) = bridge("").await;
        match mode {
            "issued" => {
                let mut j = r.journal().unwrap().unwrap();
                let mut value = serde_json::to_value(&j).unwrap();
                value["ordinary"]["issued"] = json!(true);
                j = serde_json::from_value(value).unwrap();
                j.state = State::StartingOrdinary;
                r.persist(&j).unwrap();
                assert!(r.recover().await.is_err());
            }
            "args" => {
                fs::write(&c.jvm_args_path, b"changed").unwrap();
                assert!(execute(&r, &p, l).await.is_err());
            }
            "snapshot" => {
                fs::write(
                    r.snapshots().unwrap().join("snapshot_999.xml"),
                    b"unapproved newer snapshot",
                )
                .unwrap();
                assert!(execute(&r, &p, l).await.is_err());
            }
            _ => {
                fs::write(
                    d.0.join("unit-definition"),
                    declaration(&c).replace("Environment=", "Environment=CHANGED=1"),
                )
                .unwrap();
                assert!(execute(&r, &p, l).await.is_err());
            }
        }
        assert_eq!(starts(&d), before);
        assert!(Guard::acquire(&r.0.state_root, Subsystem::Configuration).is_err());
        t.abort();
    }
}
#[tokio::test]
async fn ordinary_requires_independent_default_off_grant_and_completion_authority() {
    let (r, d, p) = completed().await;
    let before = calls(&d);
    assert!(
        r.prepare_ordinary(
            p["transactionId"].as_str().unwrap(),
            p["confirmToken"].as_str().unwrap()
        )
        .await
        .is_err()
    );
    assert_eq!(calls(&d), before);
    let c = profile(&d);
    let r = grant(r, &d, &c);
    assert!(
        r.prepare_ordinary(p["transactionId"].as_str().unwrap(), "wrong-token")
            .await
            .is_err()
    );
    assert_eq!(
        starts(&d),
        before.iter().filter(|s| s.starts_with("start ")).count()
    );
}
#[test]
fn ordinary_profile_rejects_argument_indirection_overrides_environment_injection_and_effective_unit_drift()
 {
    let root = std::env::temp_dir().join(format!("ordinary-profile-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let d = TempDir(root);
    let c = profile(&d);
    let initial = fs::read(&c.jvm_args_path).unwrap();
    for bad in [
        "@/unapproved.args",
        "-Dkura.recovery.request=/old",
        "-Dkura.management.ordinary.profile.id=other",
        "-Dkura.management.ordinary.verification.enabled=false",
        "\"unterminated",
    ] {
        let mut c = c.clone();
        let mut args = initial.clone();
        args.extend_from_slice(format!("{bad}\n").as_bytes());
        fs::write(&c.jvm_args_path, &args).unwrap();
        c.profile_files
            .iter_mut()
            .find(|f| f.path == c.jvm_args_path)
            .unwrap()
            .sha256 = durable::hash(&args);
        durable::json(&d.0.join("grant.json"), &c).unwrap();
        assert!(
            ordinary_profile::Profile::new(d.0.join("grant.json")).is_err(),
            "{bad}"
        );
    }
    for bad in [
        declaration(&c).replace("NeedDaemonReload=no", "NeedDaemonReload=yes"),
        declaration(&c).replace("DropInPaths=", "DropInPaths=/unknown.conf"),
        declaration(&c).replace(
            "UnsetEnvironment=JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS _JAVA_OPTIONS",
            "UnsetEnvironment=",
        ),
        declaration(&c).replace("Environment=", "Environment=CHANGED=1"),
        declaration(&c).replace(
            " ; ignore_errors=",
            " -Dkura.recovery.request=/old ; ignore_errors=",
        ),
    ] {
        assert!(ordinary_profile::Profile::declaration(&c, &bad).is_err());
    }
}

fn packaged(d: &TempDir) -> ordinary_profile::Config {
    let mut c = profile(d);
    let bin = d.0.join("bin");
    fs::create_dir(&bin).unwrap();
    let script = bin.join("start_kura_background.sh");
    fs::write(&script, b"#!/bin/sh\n# YOFC-KURA-ORDINARY-JVM-ARGS-V1\nset -- \"@$KURA_JVM_ARGS_FILE\"\nnohup java \"$@\"\n").unwrap();
    let generator = bin.join("gen_config_ini.sh");
    fs::write(&generator, b"reviewed generator").unwrap();
    c.launcher_kind = ordinary_profile::Launcher::PackagedBackground;
    c.launcher_script_path = Some(script.clone());
    for p in [script, generator] {
        c.profile_files.push(ordinary_profile::File {
            sha256: durable::hash(&fs::read(&p).unwrap()),
            path: p,
        });
    }
    c.unit_definition_sha256 = declaration_hash(&packaged_declaration(&c));
    c
}
fn packaged_declaration(c: &ordinary_profile::Config) -> String {
    let script = c.launcher_script_path.as_ref().unwrap();
    let direct = declaration(c);
    let prefix = direct
        .lines()
        .find(|l| l.starts_with("ExecStart="))
        .unwrap();
    direct
        .replace(
            prefix,
            &format!(
                "ExecStart={{ path=/bin/sh ; argv[]=/bin/sh {} ; ignore_errors=no ; pid=0 }}",
                script.display()
            ),
        )
        .replace(
            "Environment=\n",
            &format!(
                "Environment=KURA_JVM_ARGS_FILE={}\n",
                c.jvm_args_path.display()
            ),
        )
}
#[test]
fn packaged_profile_requires_pinned_supported_launcher_generator_and_exact_environment_binding() {
    let root = std::env::temp_dir().join(format!("ordinary-packaged-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let d = TempDir(root);
    let c = packaged(&d);
    let grant = d.0.join("grant.json");
    durable::json(&grant, &c).unwrap();
    ordinary_profile::Profile::new(grant.clone()).unwrap();
    ordinary_profile::Profile::declaration(&c, &packaged_declaration(&c)).unwrap();
    for bad in [
        packaged_declaration(&c).replace("KURA_JVM_ARGS_FILE=", "OTHER_FILE="),
        packaged_declaration(&c).replace(
            "Environment=KURA",
            "Environment=KURA_JVM_ARGS_FILE=/other KURA",
        ),
        packaged_declaration(&c).replace("argv[]=/bin/sh ", "argv[]=/bin/bash "),
        packaged_declaration(&c).replace(" ; ignore_errors=", " --extra ; ignore_errors="),
    ] {
        assert!(ordinary_profile::Profile::declaration(&c, &bad).is_err());
    }
    for mode in ["unpinned", "old-script", "kind"] {
        let mut changed = c.clone();
        match mode {
            "unpinned" => changed
                .profile_files
                .retain(|f| f.path.file_name().unwrap() != "gen_config_ini.sh"),
            "old-script" => {
                let path = changed.launcher_script_path.as_ref().unwrap();
                fs::write(path, b"#!/bin/sh\nnohup java -version\n").unwrap();
                changed
                    .profile_files
                    .iter_mut()
                    .find(|f| &f.path == path)
                    .unwrap()
                    .sha256 = durable::hash(&fs::read(path).unwrap());
            }
            _ => changed.launcher_kind = ordinary_profile::Launcher::DirectJava,
        }
        durable::json(&grant, &changed).unwrap();
        assert!(
            ordinary_profile::Profile::new(grant.clone()).is_err(),
            "{mode}"
        );
    }
}
#[test]
fn packaged_key_launcher_requires_pinned_credential_inputs_and_only_jvm_options() {
    let root = std::env::temp_dir().join(format!("ordinary-managed-launcher-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let d = TempDir(root);
    let mut c = packaged(&d);
    let script = c.launcher_script_path.clone().unwrap();
    let body = r#"#!/bin/sh
# YOFC-KURA-ORDINARY-JVM-ARGS-V1
set -- "@$KURA_JVM_ARGS_FILE"
nohup python3 -I "${DIR}/bin/kura_key_store.py" exec-java "$@" \
 -jar "${DIR}/main.jar"
"#;
    fs::write(&script, body).unwrap();
    c.profile_files.iter_mut().find(|row| row.path == script).unwrap().sha256 = durable::hash(body.as_bytes());
    let grant = d.0.join("managed-launcher.json");
    durable::json(&grant, &c).unwrap();
    assert!(ordinary_profile::Profile::new(grant.clone()).is_err());
    for helper in ["kura_key_store.py", "kura_credential_env.sh"] {
        let path = script.with_file_name(helper);
        let code = b"# fixture placeholder\n";
        fs::write(&path, code).unwrap();
        c.profile_files.push(ordinary_profile::File { path, sha256: durable::hash(code) });
    }
    let base = format!("-Dkura.management.ordinary.profile.id={}\n-Dkura.management.ordinary.verification.enabled=true\n", c.profile_id);
    for (extra, accepted) in [("", true), ("-jar\nother.jar\n", false),
        ("-Dorg.eclipse.kura.core.crypto.secretKey=other\n", false)] {
        let args = format!("{base}{extra}");
        fs::write(&c.jvm_args_path, &args).unwrap();
        c.profile_files.iter_mut().find(|row| row.path == c.jvm_args_path).unwrap().sha256 = durable::hash(args.as_bytes());
        durable::json(&grant, &c).unwrap();
        assert_eq!(ordinary_profile::Profile::new(grant.clone()).is_ok(), accepted);
    }
}

#[test]
fn installation_seal_derives_effective_definition_is_create_only_and_never_mutates_units_or_state()
{
    for legacy in [false, true] {
        let root = std::env::temp_dir().join(format!("ordinary-seal-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let d = TempDir(root);
        let c = if legacy { packaged(&d) } else { profile(&d) };
        let request = d.0.join("request.json");
        let mut value = serde_json::to_value(&c).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("unitDefinitionSha256");
        durable::json(&request, &value).unwrap();
        let definition = if legacy {
            packaged_declaration(&c)
        } else {
            declaration(&c)
        };
        fs::write(d.0.join("unit-definition"), &definition).unwrap();
        let controller = d.0.join("systemctl");
        let log = d.0.join("actions");
        fs::write(&controller,format!("#!/bin/sh\necho \"$@\" >> '{log}'\ncase \"$4\" in\n *LoadState*) printf 'LoadState=loaded\\nActiveState=inactive\\nMainPID=0\\n';;\n *) cat '{root}/unit-definition';;\nesac\n",log=log.display(),root=d.0.display())).unwrap();
        fs::set_permissions(&controller, fs::Permissions::from_mode(0o700)).unwrap();
        let output = d.0.join("ordinary.json");
        let result = ordinary_profile::seal(request.clone(), output.clone(), &controller).unwrap();
        assert_eq!(result["unitStarted"], false);
        assert_eq!(result["unitEnabled"], false);
        assert_eq!(result["unitDefinitionSha256"], c.unit_definition_sha256);
        ordinary_profile::Profile::new(output.clone()).unwrap();
        let bytes = fs::read(&output).unwrap();
        assert!(ordinary_profile::seal(request.clone(), output.clone(), &controller).is_err());
        assert_eq!(fs::read(&output).unwrap(), bytes);
        assert!(
            fs::read_to_string(log)
                .unwrap()
                .lines()
                .all(|l| l.starts_with("show "))
        );
        assert!(!d.0.join("state").exists());
        value["unitDefinitionSha256"] = json!(c.unit_definition_sha256);
        durable::json(&request, &value).unwrap();
        assert!(
            ordinary_profile::seal(request.clone(), d.0.join("second.json"), &controller).is_err()
        );
        assert!(!d.0.join("second.json").exists());
        let object = value.as_object_mut().unwrap();
        object.remove("unitDefinitionSha256");
        let raw = serde_json::to_string(&value).unwrap();
        fs::write(
            &request,
            raw.replacen('{', "{\"unit\":\"other.service\",", 1),
        )
        .unwrap();
        assert!(
            ordinary_profile::seal(request.clone(), d.0.join("duplicate.json"), &controller)
                .is_err()
        );
        assert!(!d.0.join("duplicate.json").exists());
        durable::json(&request, &value).unwrap();
        let body = fs::read_to_string(&controller)
            .unwrap()
            .replace("ActiveState=inactive", "ActiveState=active");
        fs::write(&controller, body).unwrap();
        assert!(
            ordinary_profile::seal(request.clone(), d.0.join("active.json"), &controller).is_err()
        );
        assert!(!d.0.join("active.json").exists());
    }
}

#[tokio::test]
async fn ordinary_waits_for_declared_provider_availability_without_polling_a_failed_business_check()
{
    let (r, d, old) = completed().await;
    let c = profile(&d);
    let r = grant(r, &d, &c);
    let p = prepare(&r, &old).await;
    let (l, t, count) = bridge("provider-waiting").await;
    let result = execute(&r, &p, l).await.unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert_eq!(result["report"]["schema"], 2);
    assert_eq!(result["report"]["providers"][0]["available"], true);
    t.abort();
}
#[tokio::test]
async fn ordinary_schema1_historical_receipt_remains_terminal_without_new_start_or_observation() {
    let (r, d, old) = completed().await;
    let c = profile(&d);
    let r = grant(r, &d, &c);
    let p = prepare(&r, &old).await;
    let (l, t, _) = bridge("").await;
    execute(&r, &p, l).await.unwrap();
    t.abort();
    let path = r.0.state.join("receipts").join(format!(
        "{}.ordinary.json",
        p["transactionId"].as_str().unwrap()
    ));
    let mut receipt: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    receipt["observation"]["report"]["schema"] = json!(1);
    receipt["observation"]["report"]
        .as_object_mut()
        .unwrap()
        .remove("providers");
    let body = serde_json::to_vec(&receipt).unwrap();
    fs::write(&path, &body).unwrap();
    let journal = r.0.state.join("transaction.json");
    let mut j: Value = serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
    j["ordinary"]["observation"]["report"]["schema"] = json!(1);
    j["ordinary"]["observation"]["report"]
        .as_object_mut()
        .unwrap()
        .remove("providers");
    j["ordinary"]["receipt_sha256"] = json!(durable::hash(&body));
    durable::json(&journal, &j).unwrap();
    let before = calls(&d);
    r.recover().await.unwrap();
    assert_eq!(calls(&d), before);
    assert_eq!(
        r.journal().unwrap().unwrap().state,
        State::OrdinaryActiveApprovedChecks
    );
    assert_eq!(fs::read(path).unwrap(), body);
}

#[tokio::test]
async fn ordinary_cancel_expired_unissued_retains_parent_and_allows_new_review_without_unit_actions()
 {
    let (r, d, parent) = completed().await;
    let c = profile(&d);
    let r = grant(r, &d, &c);
    let p = prepare(&r, &parent).await;
    let mut j = r.journal().unwrap().unwrap();
    let mut v = serde_json::to_value(&j).unwrap();
    v["ordinary"]["expires_at"] = json!(now() - 1);
    j = serde_json::from_value(v).unwrap();
    r.persist(&j).unwrap();
    // Expiry alone cannot turn an unissued plan into a unit stop/compensation.
    let before = calls(&d);
    r.recover().await.unwrap();
    assert!(
        calls(&d)[before.len()..]
            .iter()
            .all(|s| s.starts_with("show "))
    );
    assert_eq!(r.journal().unwrap().unwrap().state, State::OrdinaryPrepared);
    let before = calls(&d);
    let bytes = fs::read(r.0.state.join("transaction.json")).unwrap();
    assert!(
        r.cancel_ordinary(p["transactionId"].as_str().unwrap(), "wrong")
            .await
            .is_err()
    );
    assert_eq!(bytes, fs::read(r.0.state.join("transaction.json")).unwrap());
    assert_eq!(calls(&d), before);
    let v = r
        .cancel_ordinary(
            p["transactionId"].as_str().unwrap(),
            p["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(v["state"], "ORDINARY_CANCELLED");
    assert_eq!(v["ordinaryUnitHandedOff"], false);
    assert_eq!(calls(&d), before);
    let j = r.journal().unwrap().unwrap();
    assert!(j.completion.unwrap().completed);
    let bytes = fs::read(r.0.state.join("transaction.json")).unwrap();
    r.recover().await.unwrap();
    assert_eq!(calls(&d), before);
    assert_eq!(bytes, fs::read(r.0.state.join("transaction.json")).unwrap());
    crate::recovery::validate_cancelled_handoff(&r.0.state).unwrap();
    drop(Guard::acquire(&r.0.state_root, Subsystem::Configuration).unwrap());
    let archive = r.0.state.join("receipts").join(format!(
        "{}.ordinary-journal.json",
        p["transactionId"].as_str().unwrap()
    ));
    assert!(!archive.exists());
    assert!(
        r.prepare_ordinary(
            parent["transactionId"].as_str().unwrap(),
            "wrong-parent-token"
        )
        .await
        .is_err()
    );
    assert!(!archive.exists());
    assert_eq!(bytes, fs::read(r.0.state.join("transaction.json")).unwrap());
    let next = prepare(&r, &parent).await;
    assert_ne!(next["transactionId"], p["transactionId"]);
    assert!(
        r.0.state
            .join("receipts")
            .join(format!(
                "{}.ordinary-journal.json",
                p["transactionId"].as_str().unwrap()
            ))
            .exists()
    );
}

#[tokio::test]
async fn ordinary_cancel_never_clears_issued_or_unrelated_recovery_required() {
    for kind in ["issued", "recovery", "other"] {
        let (r, d, parent) = completed().await;
        let c = profile(&d);
        let r = grant(r, &d, &c);
        let p = prepare(&r, &parent).await;
        let mut j = r.journal().unwrap().unwrap();
        match kind {
            "issued" => {
                let mut v = serde_json::to_value(&j).unwrap();
                v["ordinary"]["issued"] = json!(true);
                j = serde_json::from_value(v).unwrap();
                j.state = State::StartingOrdinary;
                r.persist(&j).unwrap();
            }
            "recovery" => {
                j.state = State::RecoveryRequired;
                r.persist(&j).unwrap();
            }
            _ => {
                durable::directory(&r.0.state_root.join("network")).unwrap();
                durable::json(
                    &r.0.state_root.join("network/transaction.json"),
                    &json!({"state":"RECOVERY_REQUIRED"}),
                )
                .unwrap();
            }
        }
        let bytes = fs::read(r.0.state.join("transaction.json")).unwrap();
        let before = calls(&d);
        assert!(
            r.cancel_ordinary(
                p["transactionId"].as_str().unwrap(),
                p["confirmToken"].as_str().unwrap()
            )
            .await
            .is_err()
        );
        assert_eq!(bytes, fs::read(r.0.state.join("transaction.json")).unwrap());
        assert_eq!(before, calls(&d));
    }
}

#[tokio::test]
async fn ordinary_cancel_crash_requires_original_receipt_and_never_mutates_units() {
    for tamper in [false, true] {
        let (r, d, parent) = completed().await;
        let c = profile(&d);
        let r = grant(r, &d, &c);
        let p = prepare(&r, &parent).await;
        r.cancel_ordinary(
            p["transactionId"].as_str().unwrap(),
            p["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
        let mut j = r.journal().unwrap().unwrap();
        j.state = State::CancellingOrdinary;
        let mut v = serde_json::to_value(&j).unwrap();
        v["ordinary"]["receipt_sha256"] = Value::Null;
        j = serde_json::from_value(v).unwrap();
        r.persist(&j).unwrap();
        if tamper {
            let f = r.0.state.join("receipts").join(format!(
                "{}.ordinary-cancel.json",
                p["transactionId"].as_str().unwrap()
            ));
            fs::write(f, b"changed").unwrap();
        }
        let before = calls(&d);
        let result = r.recover().await;
        assert_eq!(calls(&d), before);
        assert_eq!(result.is_err(), tamper);
        assert_eq!(
            r.journal().unwrap().unwrap().state,
            if tamper {
                State::RecoveryRequired
            } else {
                State::OrdinaryCancelled
            }
        );
        if tamper {
            assert!(Guard::acquire(&r.0.state_root, Subsystem::Configuration).is_err());
            let native = fs::read(r.0.state.join("transaction.json")).unwrap();
            assert!(r.recover().await.is_err());
            assert_eq!(before, calls(&d));
            assert_eq!(
                native,
                fs::read(r.0.state.join("transaction.json")).unwrap()
            );
        }
    }
}

#[tokio::test]
async fn ordinary_cancel_original_command_resolves_once_and_survives_later_prepare_history() {
    use prost::Message;
    let (r, d, _) = completed().await;
    let c = profile(&d);
    let r = grant(r, &d, &c);
    let path = d.0.join("cancel.sqlite");
    let db = crate::transport::database(path.to_str().unwrap())
        .await
        .unwrap();
    let r = r.with_execution_database(path);
    let mut local = crate::local::Local::new(0, 0);
    local.recovery = Some(r.clone());
    local.ordinary_handoff_remote = true;
    let prepared = crate::transport::execute(&db, &local, remote_command(21))
        .await
        .unwrap();
    let p: Value = serde_json::from_slice(&prepared.result_json).unwrap();
    let mut cmd = remote_command(29);
    cmd.ordinary_handoff_action = Some(yofc_management_protocol::v1::OrdinaryHandoffAction {
        transaction_id: p["transactionId"].as_str().unwrap().into(),
        confirmation_token: p["confirmToken"].as_str().unwrap().into(),
    });
    let hash = durable::hash(&cmd.encode_to_vec());
    crate::journal::claim(&db, &cmd, &hash).await.unwrap();
    let before = calls(&d);
    let result = r.remote_ordinary(&cmd, local.clone()).await.unwrap();
    assert_eq!(result["state"], "ORDINARY_CANCELLED");
    assert_eq!(calls(&d), before);
    crate::journal::initialize(&db).await.unwrap();
    let native = fs::read(r.0.state.join("transaction.json")).unwrap();
    for _ in 0..2 {
        let proved = crate::transport::query_receipt(&db, &local, &cmd.command_id)
            .await
            .unwrap();
        assert_eq!(
            proved.state,
            yofc_management_protocol::v1::TaskState::Succeeded as i32
        );
    }
    assert_eq!(
        native,
        fs::read(r.0.state.join("transaction.json")).unwrap()
    );
    assert_eq!(before, calls(&d));
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM execution_resolutions WHERE command_id=?")
            .bind(&cmd.command_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(count, 1);
    let next = crate::transport::execute(&db, &local, remote_command(21))
        .await
        .unwrap();
    assert_eq!(
        next.state,
        yofc_management_protocol::v1::TaskState::Succeeded as i32
    );
    assert!(r.prove_ordinary_command(&cmd).await.unwrap().is_some());
    let mut forged = cmd.clone();
    forged.idempotency_key.push('x');
    assert!(r.prove_ordinary_command(&forged).await.unwrap().is_none());
    if let Ok(path) = std::env::var("YOFC_ORDINARY_CANCEL_GUARD_FIXTURE") {
        let out = std::path::PathBuf::from(path);
        assert!(out.is_absolute() && !out.exists());
        fn copy(src: &std::path::Path, dst: &std::path::Path) {
            fs::create_dir(dst).unwrap();
            fs::set_permissions(dst, fs::Permissions::from_mode(0o700)).unwrap();
            for entry in fs::read_dir(src).unwrap() {
                let p = entry.unwrap().path();
                let to = dst.join(p.file_name().unwrap());
                let m = fs::symlink_metadata(&p).unwrap();
                assert!(!m.file_type().is_symlink());
                if m.is_dir() {
                    copy(&p, &to);
                } else {
                    fs::copy(&p, &to).unwrap();
                }
            }
        }
        // The later prepare archived the cancellation. Export this test's exact
        // native cancellation journal as current for cross-language guard tests.
        copy(&d.0, &out);
        let state = out.join(r.0.state.strip_prefix(&d.0).unwrap());
        let archived = state.join("receipts").join(format!(
            "{}.ordinary-journal.json",
            p["transactionId"].as_str().unwrap()
        ));
        fs::copy(archived, state.join("transaction.json")).unwrap();
        fs::write(out.join("fixture.json"),serde_json::to_vec(&json!({"state":state,"scope":"native mocked unit contract; not real Kura business"})).unwrap()).unwrap();
    }
    db.close().await;
}
