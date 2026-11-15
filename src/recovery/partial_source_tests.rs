async fn partial_source_fixture(opt_in: bool) -> (Recovery, TempDir, Value, PathBuf) {
    let (recovery, dir) = inverse_fixture();
    let prepared = forward_for_inverse(&recovery).await;
    let mut journal = recovery.journal().unwrap().unwrap();
    let receipt = journal.controlled_startup.as_ref().unwrap().receipt_path.clone();
    // Protocol fixture only: simulate the failure receipt after a durable CM checkpoint.
    fs::write(&receipt, format!("schema=1\nstatus=RECOVERY_REQUIRED\nrestore.id={}\nfullRecoveryVerified=false\nbusinessHealth=BLOCKED\n", journal.id)).unwrap();
    fs::write(dir.0.join("kura-probe.service.state"), "inactive").unwrap();
    journal.cm_application = None;
    journal.state = State::RecoveryRequired;
    recovery.persist(&journal).unwrap();
    if opt_in {
        let path = dir.0.join("inverse.json");
        let mut grant: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        grant["allowPartialSource"] = json!(true);
        durable::json(&path, &grant).unwrap();
    }
    (recovery, dir, prepared, receipt)
}

#[tokio::test]
async fn partial_source_is_default_off_and_does_not_infer_an_application() {
    let (recovery, dir, source, _) = partial_source_fixture(false).await;
    let before = calls(&dir);
    assert!(recovery.prepare_compensation(source["transactionId"].as_str().unwrap(), source["confirmToken"].as_str().unwrap()).await.is_err());
    assert_eq!(calls(&dir), before);
    let journal = recovery.journal().unwrap().unwrap();
    assert_eq!(journal.state, State::RecoveryRequired);
    assert!(journal.cm_application.is_none() && journal.inverse.is_none());
    assert!(!dir.0.join("inverse/request.properties").exists());
}

#[tokio::test]
async fn partial_source_inverse_is_distinct_durable_nonterminal_and_never_replays() {
    let (recovery, dir, source, receipt) = partial_source_fixture(true).await;
    let retained = fs::read(&receipt).unwrap();
    let inverse = recovery.prepare_compensation(source["transactionId"].as_str().unwrap(), source["confirmToken"].as_str().unwrap()).await.unwrap();
    assert_eq!(inverse["sourceStatus"], "RECOVERY_REQUIRED");
    assert_ne!(inverse["transactionId"], source["transactionId"]);
    let journal = recovery.journal().unwrap().unwrap();
    assert!(journal.cm_application.is_none());
    assert!(journal.inverse.as_ref().unwrap().source_application.is_none());
    assert!(journal.inverse.as_ref().unwrap().source_partial.is_some());
    assert!(!dir.0.join("inverse/request.properties").exists());
    let result = recovery.execute_compensation(inverse["transactionId"].as_str().unwrap(), inverse["confirmToken"].as_str().unwrap()).await.unwrap();
    assert_eq!(result["state"], "AWAITING_COMPENSATION_COMPLETION");
    assert_eq!(result["kuraRecoveryVerified"], false);
    let before = calls(&dir).iter().filter(|line| line.starts_with("start ")).count();
    recovery.recover().await.unwrap();
    assert_eq!(calls(&dir).iter().filter(|line| line.starts_with("start ")).count(), before);
    assert_eq!(fs::read(&receipt).unwrap(), retained);
    assert!(recovery.journal().unwrap().unwrap().cm_application.is_none());
    assert!(recovery.upload("still-blocked", "eA==").await.is_err());
    assert!(recovery.execute_compensation(inverse["transactionId"].as_str().unwrap(), inverse["confirmToken"].as_str().unwrap()).await.is_err());
}

#[tokio::test]
async fn partial_source_requires_a_stopped_source_and_exact_complete_checkpoint() {
    for drift in ["active", "receipt", "duplicate", "plan", "backup", "intent", "request", "ledger", "permissions", "symlink"] {
        let (recovery, dir, source, receipt) = partial_source_fixture(true).await;
        match drift {
            "active" => fs::write(dir.0.join("kura-probe.service.state"), "active").unwrap(),
            "receipt" => fs::write(&receipt, "schema=1\nstatus=CM_APPLIED\n").unwrap(),
            "duplicate" => { use std::io::Write; std::fs::OpenOptions::new().append(true).open(&receipt).unwrap().write_all(b"schema=1\n").unwrap(); },
            "plan" => fs::write(PathBuf::from(format!("{}.cm-plan.properties", receipt.display())), "schema=1\n").unwrap(),
            "backup" => fs::write(PathBuf::from(format!("{}.cm-backup.aes", receipt.display())), "drift").unwrap(),
            "intent" => fs::write(PathBuf::from(format!("{}.cm-intended.aes", receipt.display())), "drift").unwrap(),
            "request" => fs::write(recovery.journal().unwrap().unwrap().controlled_startup.unwrap().request_path, "changed").unwrap(),
            "ledger" => fs::write(PathBuf::from(format!("{}.bundle-levels", receipt.display())), "invalid").unwrap(),
            "permissions" => { use std::os::unix::fs::PermissionsExt; fs::set_permissions(&receipt, fs::Permissions::from_mode(0o644)).unwrap(); },
            "symlink" => { let retained = dir.0.join("retained-failed-receipt"); fs::rename(&receipt, &retained).unwrap(); std::os::unix::fs::symlink(retained, &receipt).unwrap(); },
            _ => unreachable!(),
        }
        let before = calls(&dir).iter().filter(|line| line.starts_with("start ") || line.starts_with("stop ")).count();
        assert!(recovery.prepare_compensation(source["transactionId"].as_str().unwrap(), source["confirmToken"].as_str().unwrap()).await.is_err(), "{drift}");
        assert_eq!(calls(&dir).iter().filter(|line| line.starts_with("start ") || line.starts_with("stop ")).count(), before);
        assert!(recovery.journal().unwrap().unwrap().inverse.is_none());
        assert!(!dir.0.join("inverse/request.properties").exists());
    }
}

#[tokio::test]
async fn partial_source_opt_in_revocation_preserves_prepared_state_without_publication() {
    let (recovery, dir, source, _) = partial_source_fixture(true).await;
    let inverse = recovery.prepare_compensation(source["transactionId"].as_str().unwrap(), source["confirmToken"].as_str().unwrap()).await.unwrap();
    let path = dir.0.join("inverse.json");
    let mut grant: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    grant["allowPartialSource"] = json!(false);
    durable::json(&path, &grant).unwrap();
    let before = calls(&dir).iter().filter(|line| line.starts_with("start ")).count();
    assert!(recovery.execute_compensation(inverse["transactionId"].as_str().unwrap(), inverse["confirmToken"].as_str().unwrap()).await.is_err());
    assert!(!dir.0.join("inverse/request.properties").exists());
    assert_eq!(calls(&dir).iter().filter(|line| line.starts_with("start ")).count(), before);
    assert_eq!(recovery.journal().unwrap().unwrap().state, State::CompensationPrepared);
    assert!(recovery.upload("still-blocked-revoked", "eA==").await.is_err());
}

#[tokio::test]
async fn partial_source_drift_after_prepare_cannot_publish_an_inverse_or_start_a_unit() {
    for suffix in ["", ".cm-plan.properties", ".cm-backup.aes", ".cm-intended.aes", ".bundle-levels"] {
        let (recovery, dir, source, receipt) = partial_source_fixture(true).await;
        let inverse = recovery.prepare_compensation(source["transactionId"].as_str().unwrap(), source["confirmToken"].as_str().unwrap()).await.unwrap();
        fs::write(PathBuf::from(format!("{}{suffix}", receipt.display())), "drift").unwrap();
        let before = calls(&dir).iter().filter(|line| line.starts_with("start ")).count();
        assert!(recovery.execute_compensation(inverse["transactionId"].as_str().unwrap(), inverse["confirmToken"].as_str().unwrap()).await.is_err());
        assert_eq!(calls(&dir).iter().filter(|line| line.starts_with("start ")).count(), before);
        assert!(!dir.0.join("inverse/request.properties").exists());
        assert_eq!(recovery.journal().unwrap().unwrap().state, State::CompensationPrepared);
        assert!(recovery.upload("still-blocked-after-drift", "eA==").await.is_err());
    }
}

#[tokio::test]
async fn complete_source_keeps_the_historical_serialized_shape() {
    let (recovery, _dir) = inverse_fixture();
    let source = forward_for_inverse(&recovery).await;
    let inverse = recovery.prepare_compensation(source["transactionId"].as_str().unwrap(), source["confirmToken"].as_str().unwrap()).await.unwrap();
    assert_eq!(inverse["sourceStatus"], "CM_APPLIED");
    let journal = recovery.journal().unwrap().unwrap();
    let value = serde_json::to_value(&journal).unwrap();
    assert!(value["inverse"]["source_application"].is_object());
    assert!(value["inverse"].get("source_partial").is_none());
    assert!(serde_json::from_value::<Journal>(value).unwrap().inverse.unwrap().source_application.is_some());
}

async fn retained_partial_source() -> (Recovery, TempDir, Value, PathBuf) {
    let (recovery, dir, source, receipt) = partial_source_fixture(true).await;
    let inverse = recovery.prepare_compensation(source["transactionId"].as_str().unwrap(), source["confirmToken"].as_str().unwrap()).await.unwrap();
    recovery.execute_compensation(inverse["transactionId"].as_str().unwrap(), inverse["confirmToken"].as_str().unwrap()).await.unwrap();
    let set = recovery.prepare_snapshot_set(inverse["transactionId"].as_str().unwrap(), inverse["confirmToken"].as_str().unwrap()).await.unwrap();
    recovery.execute_snapshot_set(set["transactionId"].as_str().unwrap(), set["confirmToken"].as_str().unwrap()).await.unwrap();
    (recovery, dir, set, receipt)
}

#[tokio::test]
async fn partial_source_retention_preserves_failure_grade_and_cannot_implicitly_start_normal_or_release() {
    let (recovery, dir, set, receipt) = retained_partial_source().await;
    let before = calls(&dir);
    let original = fs::read(&receipt).unwrap();
    recovery.recover().await.unwrap();
    assert_eq!(calls(&dir).iter().filter(|x|x.starts_with("start ")).count(), before.iter().filter(|x|x.starts_with("start ")).count());
    let journal = recovery.journal().unwrap().unwrap();
    assert_eq!(journal.state, State::AwaitingSnapshotCompletion);
    assert_eq!(recovery.inventory().unwrap(), journal.base);
    assert!(journal.cm_application.is_none());
    let inverse = journal.inverse.unwrap();
    assert!(inverse.source_application.is_none() && inverse.source_partial.is_some());
    assert_eq!(fs::read(&receipt).unwrap(), original);
    assert!(recovery.prepare_normal_boot(set["transactionId"].as_str().unwrap(),set["confirmToken"].as_str().unwrap()).await.is_err());
    assert!(recovery.upload("partial-retained-blocked", "eA==").await.is_err());
    assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_err());
    assert_eq!(calls(&dir).iter().filter(|x|x.starts_with("start ")).count(), before.iter().filter(|x|x.starts_with("start ")).count());
}

#[tokio::test]
async fn partial_source_retained_checkpoint_drift_keeps_archive_and_blocks_without_forward_replay() {
    let (recovery, dir, _set, receipt) = retained_partial_source().await;
    let journal = recovery.journal().unwrap().unwrap();
    let set = journal.inverse.as_ref().unwrap().snapshot_set.as_ref().unwrap();
    let archive = recovery.snapshot_archive(set).unwrap();
    let before_files = fs::read_dir(&archive).unwrap().map(|x|{let p=x.unwrap().path();(p.clone(),fs::read(p).unwrap())}).collect::<Vec<_>>();
    fs::write(&receipt, "schema=1\nstatus=CM_APPLIED\n").unwrap();
    let before = calls(&dir);
    assert!(recovery.recover().await.is_err());
    assert_eq!(recovery.journal().unwrap().unwrap().state, State::RecoveryRequired);
    for (path,bytes) in before_files { assert_eq!(fs::read(path).unwrap(),bytes); }
    assert_eq!(calls(&dir).iter().filter(|x|x.starts_with("start ")).count(), before.iter().filter(|x|x.starts_with("start ")).count());
    assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_err());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a new explicitly pinned IDEA fixture; never replay a retained request"]
async fn actual_partial_cm_source_kura_startup_with_explicit_fixture() {
    let path = std::env::var("AGENT_ACTUAL_PARTIAL_CM_FIXTURE").expect("explicit new fixture required");
    let fixture: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let field = |name: &str| fixture[name].as_str().unwrap().to_owned();
    let file = |name: &str| PathBuf::from(field(name));
    let write = |name: &str, value: &Value| durable::publish_new(&file(name), &serde_json::to_vec(value).unwrap(), FileMetadata::private()).unwrap();
    let wait = |name: &str| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
        while !file(name).is_file() {
            assert!(std::time::Instant::now() < deadline, "IDEA coordination deadline; inspect original process, never replay");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    };
    let mut units = vec![field("unit"), field("inverseUnit")];
    if fixture.get("normalUnit").is_some() { units.push(field("normalUnit")); }
    let recovery = Recovery::open(PathBuf::from("/"), file("state"), units, file("snapshots"), Some(file("systemctl"))).unwrap()
        .with_snapshot_validator(crate::snapshot_validation::Validator::new(file("validatorConfig")).unwrap())
        .with_controlled_startup(crate::controlled_startup::Startup::new(file("startupConfig")).unwrap()).unwrap()
        .with_inverse_startup(crate::controlled_startup::Startup::new(file("inverseStartupConfig")).unwrap()).unwrap();
    let recovery = if fixture.get("normalStartupConfig").is_some() {
        recovery.with_normal_startup(crate::controlled_startup::Startup::new(file("normalStartupConfig")).unwrap()).unwrap()
            .with_normal_snapshot_validator(crate::snapshot_validation::Validator::new(file("normalValidatorConfig")).unwrap()).unwrap()
            .with_health_profile(file("healthConfig")).unwrap()
            .with_completion_profile(file("completionConfig")).unwrap()
    } else { recovery };
    let mut local = crate::local::Local::new(unsafe { libc::geteuid() }, unsafe { libc::geteuid() });
    local.recovery = Some(recovery.clone());
    let server = if fixture.get("socket").is_some() {
        let listener = local.listen(&file("socket")).await.unwrap();
        Some(tokio::spawn(local.clone().serve(listener)))
    } else { None };
    use base64::Engine;
    let payload = fs::read(file("payload")).unwrap();
    let upload = recovery.upload("partial-source", &base64::engine::general_purpose::STANDARD.encode(&payload)).await.unwrap();
    let prepared = recovery.prepare("partial-source", upload["sha256"].as_str().unwrap(), &field("unit")).await.unwrap();
    write("preparedRecord", &prepared);write("beforeApply", &json!({"ready":true}));wait("continueApply");
    assert!(recovery.execute(prepared["transactionId"].as_str().unwrap(),prepared["confirmToken"].as_str().unwrap()).await.is_err());
    let journal = recovery.journal().unwrap().unwrap();
    assert_eq!(journal.state, State::RecoveryRequired);assert!(journal.cm_application.is_none());
    recovery.stopped(&field("unit")).unwrap();
    assert!(file("actualPartialWrite").is_file() && file("injectedFailure").is_file());
    assert!(!file("unexpectedBusinessEvents").exists());
    let receipt = &journal.controlled_startup.as_ref().unwrap().receipt_path;
    let backup = PathBuf::from(format!("{}.cm-backup.aes",receipt.display()));
    durable::publish_new(&file("sourceCheck"),format!("backup={}\nsha256={}\n",backup.display(),durable::hash(&fs::read(&backup).unwrap())).as_bytes(),FileMetadata::private()).unwrap();
    write("sourceFailed", &recovery.status().await.unwrap());
    let before = serde_json::to_vec(&recovery.journal().unwrap().unwrap()).unwrap();
    assert!(recovery.recover().await.is_err());
    let after = serde_json::to_vec(&recovery.journal().unwrap().unwrap()).unwrap();assert_eq!(before,after);
    assert!(recovery.upload("blocked", "eA==").await.is_err());
    wait("continueInverse");
    let inverse = recovery.prepare_compensation(prepared["transactionId"].as_str().unwrap(),prepared["confirmToken"].as_str().unwrap()).await.unwrap();
    assert_eq!(inverse["sourceStatus"],"RECOVERY_REQUIRED");write("inversePreparedRecord", &inverse);
    let result = recovery.execute_compensation(inverse["transactionId"].as_str().unwrap(),inverse["confirmToken"].as_str().unwrap()).await.unwrap();
    assert_eq!(result["state"],"AWAITING_COMPENSATION_COMPLETION");write("inverseResultRecord", &result);
    let before = serde_json::to_vec(&recovery.journal().unwrap().unwrap()).unwrap();
    recovery.recover().await.unwrap();assert_eq!(before,serde_json::to_vec(&recovery.journal().unwrap().unwrap()).unwrap());
    assert!(recovery.journal().unwrap().unwrap().cm_application.is_none());
    write("inverseStatus", &recovery.status().await.unwrap());
    if fixture.get("normalStartupConfig").is_some() {
        write("beforeSnapshotSet", &json!({"inverseProven":true}));wait("continueSnapshotSet");
        let set = recovery.prepare_snapshot_set(inverse["transactionId"].as_str().unwrap(),inverse["confirmToken"].as_str().unwrap()).await.unwrap();
        write("snapshotSetPreparedRecord", &set);
        let result = recovery.execute_snapshot_set(set["transactionId"].as_str().unwrap(),set["confirmToken"].as_str().unwrap()).await.unwrap();
        assert_eq!(result["state"], "AWAITING_SNAPSHOT_COMPLETION");recovery.recover().await.unwrap();
        assert!(Guard::acquire(&recovery.0.state_root,Subsystem::Configuration).is_err());
        assert!(recovery.journal().unwrap().unwrap().cm_application.is_none());write("snapshotSetResultRecord", &result);
        let normal = recovery.prepare_normal_boot(set["transactionId"].as_str().unwrap(),set["confirmToken"].as_str().unwrap()).await.unwrap();
        write("normalPreparedRecord", &normal);
        let result = recovery.execute_normal_boot(normal["transactionId"].as_str().unwrap(),normal["confirmToken"].as_str().unwrap()).await.unwrap();
        assert_eq!(result["state"], "AWAITING_NORMAL_BOOT_COMPLETION");recovery.recover().await.unwrap();
        assert!(Guard::acquire(&recovery.0.state_root,Subsystem::Configuration).is_err());write("normalResultRecord", &result);
        let deadline = std::time::Instant::now()+Duration::from_secs(90);
        while local.call("kura.configuration.list").await.is_err() {
            assert!(std::time::Instant::now()<deadline,"actual Java UDS readiness");tokio::time::sleep(Duration::from_millis(100)).await;
        }
        write("beforeHealth", &json!({"normalAndActualBridgeProven":true}));wait("continueHealth");
        let health = recovery.prepare_health(normal["transactionId"].as_str().unwrap(),normal["confirmToken"].as_str().unwrap()).await.unwrap();
        write("healthPreparedRecord", &health);
        let result = recovery.execute_health(health["transactionId"].as_str().unwrap(),health["confirmToken"].as_str().unwrap(),local.clone()).await.unwrap();
        assert_eq!(result["state"], "AWAITING_HEALTH_COMPLETION");recovery.recover().await.unwrap();
        assert!(Guard::acquire(&recovery.0.state_root,Subsystem::Configuration).is_err());write("healthResultRecord", &result);
        write("beforeCompletion", &json!({"selectedHealthProven":true}));wait("continueCompletion");
        let approved = recovery.prepare_completion(health["transactionId"].as_str().unwrap(),health["confirmToken"].as_str().unwrap()).await.unwrap();
        write("completionPreparedRecord", &approved);
        let result = recovery.execute_completion(approved["transactionId"].as_str().unwrap(),approved["confirmToken"].as_str().unwrap(),local.clone()).await.unwrap();
        assert_eq!(result["writeReleaseCommitted"],true);assert_eq!(result["kuraReleaseReplyVerified"],true);assert_eq!(result["kuraRecoveryVerified"],false);
        recovery.recover().await.unwrap();assert!(Guard::acquire(&recovery.0.state_root,Subsystem::Configuration).is_ok());
        assert!(recovery.journal().unwrap().unwrap().cm_application.is_none());write("completionResultRecord", &result);
        write("beforeCompletionBrowser", &json!({"durableSelectedScopeRelease":true}));wait("finishCompletionBrowser");
        recovery.recover().await.unwrap();let journal = recovery.journal().unwrap().unwrap();assert_eq!(journal.state,State::CompletedApprovedChecks);
        assert!(journal.cm_application.is_none() && journal.inverse.as_ref().unwrap().source_application.is_none() && journal.inverse.as_ref().unwrap().source_partial.is_some());
        assert!(Guard::acquire(&recovery.0.state_root,Subsystem::Configuration).is_ok());write("postCompletionRecord", &recovery.status().await.unwrap());
    } else { wait("finish"); }
    if let Some(server) = server { server.abort(); }
}
