//! Explicit fresh native fixture only. This does not invoke historical acceptance entries.
use super::*;

#[tokio::test]
#[ignore = "requires explicit cloned original factory UNKNOWN, new grants and three independent IDEA launchers"]
async fn actual_nonidempotent_original_receipt_forward_handoff_with_explicit_fixture() {
    let spec: Value = serde_json::from_slice(
        &fs::read(std::env::var("YOFC_TEST_NONIDEMPOTENT_RECEIPT_HANDOFF").expect("fresh fixture"))
            .unwrap(),
    )
    .unwrap();
    let path = |key: &str| PathBuf::from(spec[key].as_str().expect("fixture path"));
    let unknown: Value = serde_json::from_slice(&fs::read(path("unknownProof")).unwrap()).unwrap();
    assert_eq!(unknown["originalId"], spec["originalOperationId"]);
    assert_eq!(unknown["originalIntentStillUncompleted"], true);
    assert_eq!(unknown["noInverseOrReplay"], true);
    async fn gate(records: &std::path::Path, stage: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(900);
        while !records.join(format!("dispatch-{stage}.ready")).exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "owned IDEA preselection gate expired"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    assert!(!path("state").join("recovery/transaction.json").exists());
    let recovery = Recovery::open(
        "/".into(),
        path("state"),
        ["unit", "inverseUnit", "normalUnit", "ordinaryUnit"]
            .iter()
            .map(|k| spec[k].as_str().unwrap().to_owned())
            .collect(),
        path("snapshots"),
        Some(path("systemctl")),
    )
    .unwrap()
    .with_snapshot_validator(
        crate::snapshot_validation::Validator::new(path("validatorConfig")).unwrap(),
    )
    .with_controlled_startup(
        crate::controlled_startup::Startup::new(path("startupConfig")).unwrap(),
    )
    .unwrap()
    .with_inverse_startup(
        crate::controlled_startup::Startup::new(path("inverseStartupConfig")).unwrap(),
    )
    .unwrap()
    .with_normal_startup(
        crate::controlled_startup::Startup::new(path("normalStartupConfig")).unwrap(),
    )
    .unwrap()
    .with_forward_normal_profile(path("forwardConfig"))
    .unwrap()
    .with_normal_snapshot_validator(
        crate::snapshot_validation::Validator::new(path("validatorConfig")).unwrap(),
    )
    .unwrap()
    .with_health_profile(path("healthConfig"))
    .unwrap()
    .with_completion_profile(path("completionConfig"))
    .unwrap()
    .with_ordinary_profile(path("ordinaryStartupConfig"))
    .unwrap()
    .with_ordinary_snapshot_validator(
        crate::snapshot_validation::Validator::new(path("validatorConfig")).unwrap(),
    )
    .unwrap();
    let mut local =
        crate::local::Local::new(unsafe { libc::geteuid() }, unsafe { libc::geteuid() });
    local.recovery = Some(recovery.clone());
    let listener = local.listen(&path("socket")).await.unwrap();
    let server = tokio::spawn(local.clone().serve(listener));
    let record = |name: &str, value: &Value| {
        durable::publish_new(
            &path("records").join(name),
            &serde_json::to_vec_pretty(value).unwrap(),
            FileMetadata::private(),
        )
        .unwrap();
    };
    let data = fs::read(path("payload")).unwrap();
    use base64::Engine;
    recovery
        .upload(
            "nonidempotent-current-cm-input",
            &base64::engine::general_purpose::STANDARD.encode(&data),
        )
        .await
        .unwrap();
    let p = recovery
        .prepare(
            "nonidempotent-current-cm-input",
            &durable::hash(&data),
            spec["unit"].as_str().unwrap(),
        )
        .await
        .unwrap();
    record("apply-prepared.json", &p);
    gate(&path("records"), "apply").await;
    let result = recovery
        .execute(
            p["transactionId"].as_str().unwrap(),
            p["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(result["state"], "AWAITING_COMPLETION");
    record("apply-result.json", &result);
    let p = recovery
        .prepare_applied_normal_boot(
            p["transactionId"].as_str().unwrap(),
            p["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    record("normal-prepared.json", &p);
    gate(&path("records"), "normal").await;
    let result = recovery
        .execute_normal_boot(
            p["transactionId"].as_str().unwrap(),
            p["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(result["state"], "AWAITING_NORMAL_BOOT_COMPLETION");
    record("normal-result.json", &result);
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    while local.call("kura.configuration.list").await.is_err() {
        assert!(
            std::time::Instant::now() < deadline,
            "native bridge readiness"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    gate(&path("records"), "normal-reviewed").await;
    let p = recovery
        .prepare_health(
            p["transactionId"].as_str().unwrap(),
            p["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    record("health-prepared.json", &p);
    let result = recovery
        .execute_health(
            p["transactionId"].as_str().unwrap(),
            p["confirmToken"].as_str().unwrap(),
            local.clone(),
        )
        .await
        .unwrap();
    assert_eq!(result["state"], "AWAITING_HEALTH_COMPLETION");
    record("health-result.json", &result);
    let p = recovery
        .prepare_completion(
            p["transactionId"].as_str().unwrap(),
            p["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    record("completion-prepared.json", &p);
    let result = recovery
        .execute_completion(
            p["transactionId"].as_str().unwrap(),
            p["confirmToken"].as_str().unwrap(),
            local.clone(),
        )
        .await
        .unwrap();
    assert_eq!(result["writeReleaseCommitted"], true);
    record("completion-result.json", &result);
    recovery.recover().await.unwrap();
    let p = recovery
        .prepare_ordinary(
            p["transactionId"].as_str().unwrap(),
            p["confirmToken"].as_str().unwrap(),
        )
        .await
        .unwrap();
    record("ordinary-prepared.json", &p);
    gate(&path("records"), "ordinary").await;
    let result = recovery
        .execute_ordinary(
            p["transactionId"].as_str().unwrap(),
            p["confirmToken"].as_str().unwrap(),
            local.clone(),
        )
        .await
        .unwrap();
    assert_eq!(result["ordinaryUnitHandedOff"], true);
    recovery.recover().await.unwrap();
    assert!(recovery.journal().unwrap().unwrap().inverse.is_none());
    assert_eq!(
        recovery.journal().unwrap().unwrap().state,
        State::OrdinaryActiveApprovedChecks
    );
    record("ordinary-result.json", &result);
    server.abort();
}
