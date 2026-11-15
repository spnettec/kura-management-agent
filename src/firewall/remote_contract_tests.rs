use super::*;
use yofc_management_protocol::{firewall::Candidate as WireCandidate, v1::FirewallChange};

#[test]
fn remote_candidate_preserves_the_actual_complete_v3_compiler_surface() {
    let captured = include_bytes!("fixtures/v3-kura-candidate.json");
    let original: model::KuraCandidate = serde_json::from_slice(captured).unwrap();
    let wire: WireCandidate = serde_json::from_slice(captured).unwrap();
    assert!(wire.valid());
    let change = FirewallChange {
        expected_revision: 1,
        source_digest: "a".repeat(64),
        confirm_seconds: 180,
        candidate_json: serde_json::to_vec(&wire).unwrap(),
    };
    assert!(change.valid());
    let restored: model::KuraCandidate = serde_json::from_slice(&change.candidate_json).unwrap();
    assert_eq!(
        original.compile().unwrap().text,
        restored.compile().unwrap().text
    );
}

#[test]
fn optional_and_numeric_nat_protocols_keep_distinct_existing_meaning() {
    let base: Value =
        serde_json::from_slice(include_bytes!("fixtures/v3-kura-candidate.json")).unwrap();
    for protocol in [Value::Null, json!("all"), json!(6), json!(255)] {
        let mut input = base.clone();
        input["nat"][0]["protocol"] = protocol;
        let original: model::KuraCandidate = serde_json::from_value(input.clone()).unwrap();
        let wire: WireCandidate = serde_json::from_value(input).unwrap();
        let restored: model::KuraCandidate =
            serde_json::from_value(serde_json::to_value(wire).unwrap()).unwrap();
        assert_eq!(
            original.compile().unwrap().text,
            restored.compile().unwrap().text
        );
    }
}

fn command(operation: i32) -> yofc_management_protocol::v1::ReadCommand {
    yofc_management_protocol::v1::ReadCommand {
        command_id: uuid::Uuid::new_v4().to_string(),
        operation,
        idempotency_key: uuid::Uuid::new_v4().to_string(),
        expires_at_unix_ms: i64::MAX,
        ..Default::default()
    }
}
fn connection(at: u64) -> String {
    format!("{at}:{}:test-center-epoch", uuid::Uuid::new_v4())
}
fn fixture() -> Firewall {
    let root = std::env::temp_dir().join(format!("remote-firewall-{}", uuid::Uuid::new_v4()));
    Firewall::open(root, None).unwrap().enable_writes(true)
}
async fn prepare(
    fw: &Firewall,
    authority: &str,
    session: &str,
) -> (yofc_management_protocol::v1::ReadCommand, Value) {
    let view = fw
        .remote_request(&command(30), authority, session, true)
        .await
        .unwrap();
    let candidate = json!({"schemaVersion":3,"ipv4":{"inputPolicy":"accept","forwardPolicy":"drop","allowIcmp":false},
        "ipv6":{"inputPolicy":"accept","forwardPolicy":"drop","allowIcmp":false},"input":[],"portForward":[],"nat":[]});
    let mut c = command(31);
    c.firewall_change = Some(FirewallChange {
        expected_revision: view["revision"].as_u64().unwrap(),
        source_digest: view["sourceDigest"].as_str().unwrap().into(),
        confirm_seconds: 180,
        candidate_json: serde_json::to_vec(&candidate).unwrap(),
    });
    let result = fw
        .remote_request(&c, authority, session, true)
        .await
        .unwrap();
    (c, result)
}
fn action(operation: i32, prepared: &Value) -> yofc_management_protocol::v1::ReadCommand {
    let mut c = command(operation);
    c.firewall_action = Some(yofc_management_protocol::v1::FirewallAction {
        transaction_id: prepared["id"].as_str().unwrap().into(),
        confirmation_token: prepared["confirmationToken"].as_str().unwrap().into(),
    });
    c
}

#[tokio::test]
async fn only_a_new_authenticated_connection_after_apply_can_confirm_and_domain_owners_cannot_bypass_it()
 {
    let fw = fixture();
    let authority = "a".repeat(64);
    let old = connection(1);
    let (original, p) = prepare(&fw, &authority, &old).await;
    let confirm = action(32, &p);
    assert!(
        fw.remote_request(&confirm, &authority, &old, true)
            .await
            .unwrap_err()
            .to_string()
            .starts_with("FORBIDDEN")
    );
    assert!(
        fw.remote_request(&confirm, &authority, &connection(1), true)
            .await
            .unwrap_err()
            .to_string()
            .starts_with("FORBIDDEN")
    );
    assert!(
        fw.confirm(p["confirmationToken"].as_str().unwrap())
            .await
            .is_err()
    );
    assert!(
        fw.kura_request(
            "firewall.kura.confirm".into(),
            json!({"ownerKey":"a".repeat(64),"id":p["id"],"token":p["confirmationToken"]}),
            "local".into(),
            1000,
            true
        )
        .await
        .is_err()
    );
    let fresh = connection(now() + 1);
    assert_eq!(
        fw.remote_request(&command(30), &authority, &old, true)
            .await
            .unwrap()["confirmationReady"],
        false
    );
    assert_eq!(
        fw.remote_request(&command(30), &authority, &fresh, true)
            .await
            .unwrap()["confirmationReady"],
        true
    );
    assert!(
        fw.remote_request(&confirm, &"b".repeat(64), &fresh, true)
            .await
            .is_err()
    );
    assert_eq!(
        fw.remote_request(&confirm, &authority, &fresh, true)
            .await
            .unwrap()["state"],
        "COMMITTED"
    );
    assert!(
        fw.remote_request(&original, &authority, &fresh, true)
            .await
            .unwrap_err()
            .to_string()
            .starts_with("OUTCOME_UNKNOWN")
    );
    let checks = fw.0.fake.lock().unwrap().checked.len();
    assert!(
        fw.prove_remote(&confirm, &"b".repeat(64))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        fw.prove_remote(&confirm, &authority)
            .await
            .unwrap()
            .is_some()
    );
    let mut changed = confirm.clone();
    changed.expires_at_unix_ms -= 1;
    assert!(
        fw.prove_remote(&changed, &authority)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(fw.0.fake.lock().unwrap().checked.len(), checks);
}

#[tokio::test]
async fn lost_prepare_and_confirm_are_observed_without_nft_or_replay_and_survive_archiving() {
    let fw = fixture();
    let authority = "c".repeat(64);
    let session = connection(1);
    let (original, p) = prepare(&fw, &authority, &session).await;
    let checks = fw.0.fake.lock().unwrap().checked.len();
    let receipt = fw
        .prove_remote(&original, &authority)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        receipt.state,
        yofc_management_protocol::v1::TaskState::Succeeded as i32
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&receipt.result_json).unwrap()["state"],
        "WAIT_CONFIRM"
    );
    assert_eq!(fw.0.fake.lock().unwrap().checked.len(), checks);
    let confirm = action(32, &p);
    fw.remote_request(&confirm, &authority, &connection(now() + 1), true)
        .await
        .unwrap();
    let (_next, q) = prepare(&fw, &authority, &session).await;
    assert!(
        fw.prove_remote(&original, &authority)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        fw.prove_remote(&confirm, &authority)
            .await
            .unwrap()
            .is_some()
    );
    fw.remote_request(&action(33, &q), &authority, &session, true)
        .await
        .unwrap();
}

#[tokio::test]
async fn remote_is_default_off_and_explicit_compensation_survives_revoked_system_write_grant() {
    let mut fw = fixture();
    let authority = "d".repeat(64);
    let session = connection(1);
    assert!(
        fw.remote_request(&command(30), &authority, &session, false)
            .await
            .is_err()
    );
    let (original, p) = prepare(&fw, &authority, &session).await;
    assert!(
        fw.prove_remote(&original, &"e".repeat(64))
            .await
            .unwrap()
            .is_none()
    );
    fw = fw.enable_writes(false);
    let rollback = action(33, &p);
    assert_eq!(
        fw.remote_request(&rollback, &authority, &session, true)
            .await
            .unwrap()["state"],
        "ROLLED_BACK"
    );
    assert!(
        fw.prove_remote(&rollback, &authority)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn entered_apply_failure_stays_unknown_and_a_duplicate_never_reenters_nft() {
    let fw = fixture();
    let authority = "f".repeat(64);
    let session = connection(1);
    let (previous, p) = prepare(&fw, &authority, &session).await;
    fw.remote_request(&action(33, &p), &authority, &session, true)
        .await
        .unwrap();
    let mut original = previous.clone();
    original.command_id = uuid::Uuid::new_v4().to_string();
    let fresh = fw
        .remote_request(&command(30), &authority, &session, true)
        .await
        .unwrap();
    original.firewall_change.as_mut().unwrap().source_digest =
        fresh["sourceDigest"].as_str().unwrap().into();
    fw.0.fake.lock().unwrap().fail_apply = true;
    assert!(
        fw.remote_request(&original, &authority, &session, true)
            .await
            .unwrap_err()
            .to_string()
            .starts_with("OUTCOME_UNKNOWN")
    );
    let checks = fw.0.fake.lock().unwrap().checked.len();
    assert!(
        fw.prove_remote(&original, &authority)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        fw.remote_request(&original, &authority, &session, true)
            .await
            .unwrap_err()
            .to_string()
            .starts_with("OUTCOME_UNKNOWN")
    );
    assert_eq!(fw.0.fake.lock().unwrap().checked.len(), checks);
}

#[tokio::test]
async fn durable_execution_identity_rejects_another_center_generation_and_changed_request() {
    let root = std::env::temp_dir().join(format!("remote-fw-authority-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("state.sqlite");
    let db = crate::transport::database(path.to_str().unwrap())
        .await
        .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    crate::journal::bind_firewall_authority(&db, &id, &"a".repeat(64), &"1".repeat(64))
        .await
        .unwrap();
    assert_eq!(
        crate::journal::firewall_authority_matches(&db, &id, &"a".repeat(64))
            .await
            .unwrap(),
        Some(true)
    );
    assert!(
        crate::journal::bind_firewall_authority(&db, &id, &"b".repeat(64), &"1".repeat(64))
            .await
            .is_err()
    );
    // A terminal, encrypted receipt must be checked before its token is read,
    // not only while an execution is UNKNOWN.
    let mut saved = command(31);
    saved.command_id = id.clone();
    assert!(
        crate::journal::claim(&db, &saved, &"1".repeat(64))
            .await
            .unwrap()
            .is_none()
    );
    crate::journal::finish(
        &db,
        &"1".repeat(64),
        yofc_management_protocol::v1::TaskResult {
            command_id: id.clone(),
            state: yofc_management_protocol::v1::TaskState::Succeeded as i32,
            error: 0,
            result_json: serde_json::to_vec(
                &json!({"confirmationToken":"must-not-cross-authority"}),
            )
            .unwrap(),
        },
    )
    .await
    .unwrap();
    assert!(
        crate::journal::bind_firewall_authority(&db, &id, &"a".repeat(64), &"2".repeat(64))
            .await
            .is_err()
    );
    let local = crate::local::Local::new(0, 0);
    let receipt = crate::transport::query_receipt(&db, &local, &id)
        .await
        .unwrap();
    assert_eq!(
        receipt.state,
        yofc_management_protocol::v1::TaskState::Unknown as i32
    );
    assert!(
        !String::from_utf8(receipt.result_json)
            .unwrap()
            .contains("confirmationToken")
    );
}

#[tokio::test]
async fn a_failed_entered_confirmation_can_be_proved_failed_after_explicit_rollback() {
    let fw = fixture();
    let authority = "a".repeat(64);
    let session = connection(1);
    let (_, p) = prepare(&fw, &authority, &session).await;
    let confirm = action(32, &p);
    // A real semantic readback mismatch occurs before the confirmation decision.
    fw.0.fake.lock().unwrap().table = Some(json!({"nftables":[]}));
    assert!(
        fw.remote_request(&confirm, &authority, &connection(now() + 1), true)
            .await
            .unwrap_err()
            .to_string()
            .starts_with("OUTCOME_UNKNOWN")
    );
    assert!(!fw.journal().unwrap().unwrap().confirmed_decision);
    fw.remote_request(&action(33, &p), &authority, &session, true)
        .await
        .unwrap();
    let proof = fw
        .prove_remote(&confirm, &authority)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        proof.state,
        yofc_management_protocol::v1::TaskState::Failed as i32
    );
}

#[tokio::test]
async fn remote_draft_cannot_survive_an_intervening_apply_and_rollback_to_the_same_revision() {
    let fw = fixture();
    let authority = "a".repeat(64);
    let session = connection(1);
    let (mut stale, p) = prepare(&fw, &authority, &session).await;
    fw.remote_request(&action(33, &p), &authority, &session, true)
        .await
        .unwrap();
    stale.command_id = uuid::Uuid::new_v4().to_string();
    let checks = fw.0.fake.lock().unwrap().checked.len();
    assert!(
        fw.remote_request(&stale, &authority, &session, true)
            .await
            .unwrap_err()
            .to_string()
            .starts_with("CONFLICT")
    );
    assert_eq!(fw.0.fake.lock().unwrap().checked.len(), checks);
}

#[tokio::test]
async fn v4_remote_roundtrip_uses_exact_compiler_and_original_outcome_without_new_apply() {
    let fw=fixture();let authority="a".repeat(64);let old=connection(1);
    let view=fw.remote_request(&command(30),&authority,&old,true).await.unwrap();
    let mut value:Value=serde_json::from_slice(include_bytes!("fixtures/v3-kura-candidate.json")).unwrap();value["schemaVersion"]=json!(4);value["ipv4"]["outputPolicy"]=json!("drop");value["ipv6"]["outputPolicy"]=json!("accept");
    let wire:WireCandidate=serde_json::from_value(value.clone()).unwrap();assert!(wire.valid());
    let mut original=command(31);original.firewall_change=Some(FirewallChange{expected_revision:view["revision"].as_u64().unwrap(),source_digest:view["sourceDigest"].as_str().unwrap().into(),confirm_seconds:180,candidate_json:serde_json::to_vec(&wire).unwrap()});assert!(original.valid_payload());
    let prepared=fw.remote_request(&original,&authority,&old,true).await.unwrap();assert_eq!(prepared["candidate"]["schemaVersion"],4);
    assert_eq!(model::compile_original_policy(value).unwrap().text,fw.journal().unwrap().unwrap().candidate_text);
    let confirm=action(32,&prepared);assert!(fw.remote_request(&confirm,&authority,&old,true).await.is_err());
    let fresh=connection(now()+1);fw.remote_request(&confirm,&authority,&fresh,true).await.unwrap();
    let confirmed=fw.remote_request(&command(30),&authority,&fresh,true).await.unwrap();assert_eq!(confirmed["candidate"]["ipv4"]["outputPolicy"],"drop");assert_eq!(confirmed["candidate"]["ipv6"]["outputPolicy"],"accept");
    let before=fw.0.fake.lock().unwrap().checked.len();let proof=fw.prove_remote(&original,&authority).await.unwrap().unwrap();assert_eq!(serde_json::from_slice::<Value>(&proof.result_json).unwrap()["state"],"COMMITTED");
    assert!(fw.remote_request(&original,&authority,&fresh,true).await.unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));assert_eq!(fw.0.fake.lock().unwrap().checked.len(),before);
}
