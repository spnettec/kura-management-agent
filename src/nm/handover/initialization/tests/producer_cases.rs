//! Storage contracts with an explicit synthetic authority. These fixtures have
//! no committed/live owner and are never accepted as registered migration proof.
use super::*;
use crate::nm::{
    coordinator::imported::Verified,
    handover::initialization::producer::{self, Snapshot},
};
use std::time::{Duration, Instant};

fn owner(f: &Fixture, revision: u64, source: &str, epoch: u64) -> roles::Owner {
    let (journal, plan) = f.store.load().unwrap().unwrap();
    roles::Owner::new(f.baseline.roles.agent_instance,epoch,json!({"schemaVersion":2,"pid":roles::PID,
        "operationId":f.id,"planSha256":journal.plan_sha256,
        "mirrorSha256":plan.template.as_ref().unwrap().template_hash(),"roles":f.baseline.roles.roles,
        "firewall":{"schemaVersion":1,"pids":[roles::FIREWALL_V4_PID,roles::FIREWALL_V6_PID],
        "revision":revision.to_string(),"sourceDigest":source}})).unwrap()
}
pub(in crate::nm::handover::initialization) fn proof(f: &Fixture, snapshot: &Snapshot, deadline: Instant) -> Verified {
    let (journal, _) = f.store.load().unwrap().unwrap();
    let original_source = durable::hash(&fs::read(f.root.join(POLICY)).unwrap());
    let original = owner(f, 1, &original_source, f.baseline.roles.bridge_epoch);
    let current = owner(
        f,
        snapshot.revision(),
        snapshot.source(),
        f.baseline.roles.bridge_epoch + 1,
    );
    let active = Active {
        binding: Binding {
            operation_id: f.id,
            plan_sha256: journal.plan_sha256,
            lease_sha256: "e".repeat(64),
        },
        baseline: f.baseline.clone(),
    };
    Verified::storage_fixture(
        snapshot,
        active,
        original,
        current,
        "b".repeat(64),
        deadline,
    )
    .unwrap()
}
pub(in crate::nm::handover::initialization) fn fixture() -> (Fixture, Snapshot, Verified, Value) {
    let f = Fixture::new();
    f.initialize().unwrap();
    assert!(
        f.store.active_owner().unwrap().is_none(),
        "synthetic storage proof must never masquerade as a committed live owner"
    );
    assert!(f.store.current_runtime_challenge(Path::new("/nonexistent/never-run-uncommitted-runtime"))
        .err().unwrap().to_string().starts_with("FORBIDDEN:"));
    let snapshot = Snapshot::take(&f.root).unwrap();
    let proof = proof(&f, &snapshot, Instant::now() + Duration::from_secs(300));
    let input = change(&f, &snapshot);
    (f, snapshot, proof, input)
}
fn change(f: &Fixture, snapshot: &Snapshot) -> Value {
    let mut candidate = core_view(&f.root).unwrap().unwrap()["candidate"].clone();
    candidate["portForward"][0]["outPort"] =
        json!(candidate["portForward"][0]["outPort"].as_u64().unwrap() + 1);
    json!({"ownerKey":"a".repeat(64),"operationId":uuid::Uuid::new_v4(),"expectedRevision":snapshot.revision(),
        "sourceDigest":snapshot.source(),"cohortDigest":"b".repeat(64),"confirmSeconds":120,
        "candidate":candidate,"destinationPrefixes":{"ipv4":[32],"ipv6":[64]}})
}
pub(in crate::nm::handover::initialization) fn prepare(
    f: &Fixture,
    snapshot: &Snapshot,
    proof: &Verified,
    input: &Value,
    request: &str,
) -> Result<Value> {
    let _guard = crate::system_change::Guard::observe(&f.root)?;
    producer::prepare(
        &f.root,
        snapshot,
        serde_json::from_value(input.clone())?,
        77,
        request,
        proof,
    )
}
pub(in crate::nm::handover::initialization) fn outcome(input: &Value, request: &str) -> Value {
    json!({"originalRequestId":request,"change":input})
}
pub(in crate::nm::handover::initialization) fn action(input: &Value, receipt: &Value, request: &str) -> Value {
    json!({"originalRequestId":request,"ownerKey":input["ownerKey"],"id":receipt["id"],"confirmationToken":receipt["confirmationToken"]})
}
fn history(f: &Fixture, request: &str) -> PathBuf {
    f.root.join("firewall/kura-history").join(format!(
        "{}.json",
        durable::hash(format!("77:{request}").as_bytes())
    ))
}
fn plan(f: &Fixture, request: &str) -> PathBuf {
    f.root.join("firewall/kura-history").join(format!(
        "{}.artifacts/plan.json",
        durable::hash(format!("77:{request}").as_bytes())
    ))
}

  #[test]
  fn remote_decision_evidence_reads_exact_original_record_and_cannot_invent_an_ack() {
      let(f,snapshot,proof,input)=fixture();
      let request="remote-decision-audit-v51";
      let anchor=fs::read(f.root.join(POLICY)).unwrap();
      let prepared=prepare(&f,&snapshot,&proof,&input,request).unwrap();
      let _guard=crate::system_change::Guard::observe(&f.root).unwrap();
      let evidence=producer::original_evidence(&f.root,77,&prepared).unwrap();
      let audit:yofc_management_protocol::imported::DecisionEvidence=serde_json::from_value(evidence).unwrap();
      assert!(audit.valid());assert!(audit.commands.is_none());assert!(audit.resolution(40,"PREPARED",&"a".repeat(64),false).is_none());
      assert!(audit.resolution(41,"WAIT_CONFIRM",&"a".repeat(64),false).is_none());assert!(!audit.historical);
      assert!(producer::original_evidence(&f.root,78,&prepared).is_err());
      let mut forged=prepared.clone();forged["id"]=json!(uuid::Uuid::new_v4());
      assert!(producer::original_evidence(&f.root,77,&forged).is_err());
      let cancelled=producer::cancel(&f.root,77,serde_json::from_value(action(&input,&prepared,request)).unwrap()).unwrap();
      assert_eq!(cancelled["state"],"ROLLED_BACK");
      let queried=producer::outcome(&f.root,77,serde_json::from_value(outcome(&input,request)).unwrap()).unwrap();
      let evidence=producer::original_evidence(&f.root,77,&queried).unwrap();
      let audit:yofc_management_protocol::imported::DecisionEvidence=serde_json::from_value(evidence).unwrap();
      assert!(audit.historical);assert!(audit.resolution(44,"ROLLED_BACK",&"a".repeat(64),false).is_none());
      assert!(audit.resolution(43,"ROLLED_BACK",&"a".repeat(64),false).is_none());assert!(!audit.forward_intent);
      assert_eq!(fs::read(f.root.join(POLICY)).unwrap(),anchor);
  }

#[tokio::test]
async fn proposal_files_queries_and_revoked_grant_cancellation_preserve_the_original_anchor_without_a_backend_call()
 {
    let (f, snapshot, proof, input) = fixture();
    let request = "ordinary-proposal";
    let anchor = fs::read(f.root.join(POLICY)).unwrap();
    let original_owner = fs::read(f.store.journal_path()).unwrap();
    let mut review = input.clone();
    for key in ["ownerKey", "cohortDigest", "confirmSeconds"] {
        review.as_object_mut().unwrap().remove(key);
    }
    let reviewed =
        producer::review(&snapshot, serde_json::from_value(review).unwrap(), &proof).unwrap();
    assert_eq!(reviewed["nativePlan"]["targetRevision"], 2);
    assert_eq!(reviewed["cohortDigest"], "b".repeat(64));
    assert!(!f.root.join("firewall/transaction.json").exists());
    let receipt = prepare(&f, &snapshot, &proof, &input, request).unwrap();
    assert_eq!(receipt["state"], "PREPARED");
    assert_eq!(receipt["dispatchEnabled"], false);
    let record: Value =
        serde_json::from_slice(&fs::read(f.root.join("firewall/transaction.json")).unwrap())
            .unwrap();
    assert_eq!(record["schemaVersion"], 2);
    assert_eq!(record["forwardIntent"], false);
    assert_eq!(record["authorization"]["sourceStamp"], snapshot.stamp());
    assert!(record.get("ownerKey").is_none());
    assert!(plan(&f, request).is_file());
    assert!(!history(&f, request).exists());
    let view = core_view(&f.root).unwrap().unwrap();
    assert_eq!(view["journalSettled"], false);
    assert_eq!(view["transaction"]["state"], "PREPARED");
    let engine = crate::firewall::Firewall::open(f.root.clone(), None)
        .unwrap()
        .enable_writes(false);
    let queried = engine
        .imported_metadata_request(
            "firewall.kura.imported.outcome".into(),
            outcome(&input, request),
            77,
        )
        .await
        .unwrap();
    assert_eq!(queried["confirmationToken"], receipt["confirmationToken"]);
    let mut wrong = outcome(&input, request);
    wrong["change"]["ownerKey"] = json!("c".repeat(64));
    assert!(
        engine
            .imported_metadata_request("firewall.kura.imported.outcome".into(), wrong, 77)
            .await
            .unwrap_err()
            .to_string()
            .starts_with("FORBIDDEN:")
    );
    let mut wrong = outcome(&input, request);
    wrong["change"]["cohortDigest"] = json!("c".repeat(64));
    assert!(
        engine
            .imported_metadata_request("firewall.kura.imported.outcome".into(), wrong, 77)
            .await
            .unwrap_err()
            .to_string()
            .starts_with("CONFLICT:")
    );
    assert!(
        engine
            .imported_metadata_request(
                "firewall.kura.imported.outcome".into(),
                outcome(&input, request),
                78
            )
            .await
            .unwrap_err()
            .to_string()
            .starts_with("FORBIDDEN:")
    );
    let cancelled = engine
        .imported_metadata_request(
            "firewall.kura.imported.cancel".into(),
            action(&input, &receipt, request),
            77,
        )
        .await
        .unwrap();
    assert_eq!(cancelled["state"], "ROLLED_BACK");
    assert_eq!(core_view(&f.root).unwrap().unwrap()["journalSettled"], true);
    assert!(history(&f, request).is_file());
    assert!(!f.root.join("firewall/confirmed.json").exists());
    durable::json(
        &f.root.join("firewall/transaction.json"),
        &json!({"backend":"nft.imported.v1","state":"APPLYING","brokenCurrent":true}),
    )
    .unwrap();
    let historical = engine
        .imported_metadata_request(
            "firewall.kura.imported.outcome".into(),
            outcome(&input, request),
            77,
        )
        .await
        .unwrap();
    assert_eq!(historical["state"], "ROLLED_BACK");
    assert_eq!(historical["historical"], true);
    assert_eq!(engine.test_backend_invocations(), 0);
    assert_eq!(fs::read(f.root.join(POLICY)).unwrap(), anchor);
    assert_eq!(fs::read(f.store.journal_path()).unwrap(), original_owner);
}

#[test]
fn stale_cohort_version_source_owner_or_invalid_plan_refuses_before_any_publication() {
    let (f, snapshot, proof, input) = fixture();
    for defect in [
        "cohort",
        "revision",
        "source",
        "owner",
        "operation",
        "prefix",
    ] {
        let mut value = input.clone();
        match defect {
            "cohort" => value["cohortDigest"] = json!("c".repeat(64)),
            "revision" => value["expectedRevision"] = json!(0),
            "source" => value["sourceDigest"] = json!("c".repeat(64)),
            "owner" => value["ownerKey"] = json!("short"),
            "operation" => value["operationId"] = json!(uuid::Uuid::nil()),
            _ => value["destinationPrefixes"]["ipv4"] = json!([33]),
        }
        assert!(
            prepare(&f, &snapshot, &proof, &value, "never-published").is_err(),
            "{defect}"
        );
        assert!(!f.root.join("firewall/transaction.json").exists());
        assert!(!f.root.join("firewall/kura-history").exists());
    }
    f.check_original();
}

#[tokio::test]
async fn pending_or_lost_proposals_block_every_new_id_and_never_recreate_a_missing_active_record() {
    let (f, snapshot, proof, input) = fixture();
    let request = "proposal-pending";
    prepare(&f, &snapshot, &proof, &input, request).unwrap();
    let path = f.root.join("firewall/transaction.json");
    let bytes = fs::read(&path).unwrap();
    let mut another = input.clone();
    another["operationId"] = json!(uuid::Uuid::new_v4());
    for (value, request) in [(&input, request), (&another, "another-new-id")] {
        assert!(
            prepare(&f, &snapshot, &proof, value, request)
                .unwrap_err()
                .to_string()
                .starts_with("OUTCOME_UNKNOWN:")
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
    fs::rename(&path, path.with_extension("retained")).unwrap();
    assert!(
        Snapshot::take(&f.root)
            .err()
            .unwrap()
            .to_string()
            .starts_with("OUTCOME_UNKNOWN:")
    );
    let engine = crate::firewall::Firewall::open(f.root.clone(), None).unwrap();
    assert!(
        engine
            .imported_metadata_request(
                "firewall.kura.imported.outcome".into(),
                outcome(&input, request),
                77
            )
            .await
            .unwrap_err()
            .to_string()
            .starts_with("OUTCOME_UNKNOWN:")
    );
    assert!(engine.recover().await.is_err());
    assert!(!path.exists());
    assert!(!history(&f, request).exists());
    assert!(plan(&f, request).is_file());
    assert_eq!(engine.test_backend_invocations(), 0);
}

#[tokio::test]
async fn no_effect_cancellation_recovery_only_finishes_an_existing_archive_and_never_republishes_a_missing_one()
 {
    for existing in [true, false] {
        let (f, snapshot, proof, input) = fixture();
        let request = "proposal-cancel-prefix";
        let receipt = prepare(&f, &snapshot, &proof, &input, request).unwrap();
        let engine = crate::firewall::Firewall::open(f.root.clone(), None).unwrap();
        let active = f.root.join("firewall/transaction.json");
        if existing {
            engine
                .imported_metadata_request(
                    "firewall.kura.imported.cancel".into(),
                    action(&input, &receipt, request),
                    77,
                )
                .await
                .unwrap();
        }
        let mut value: Value = serde_json::from_slice(&fs::read(&active).unwrap()).unwrap();
        value["state"] = json!("ROLLING_BACK");
        durable::json(&active, &value).unwrap();
        let saved = fs::read(&active).unwrap();
        engine.recover().await.unwrap();
        let after: Value = serde_json::from_slice(&fs::read(&active).unwrap()).unwrap();
        assert_eq!(
            after["state"],
            if existing {
                "ROLLED_BACK"
            } else {
                "ROLLING_BACK"
            }
        );
        if !existing {
            assert_eq!(fs::read(&active).unwrap(), saved);
            assert!(!history(&f, request).exists());
            assert!(
                engine
                    .imported_metadata_request(
                        "firewall.kura.imported.cancel".into(),
                        action(&input, &receipt, request),
                        77
                    )
                    .await
                    .unwrap_err()
                    .to_string()
                    .starts_with("OUTCOME_UNKNOWN:")
            );
        } else {
            let marker = BoundFile::open(&active, LIMIT).unwrap().marker().unwrap();
            engine.recover().await.unwrap();
            assert!(BoundFile::open(&active, LIMIT).unwrap().marker().unwrap() == marker);
        }
        assert!(!f.root.join("firewall/confirmed.json").exists());
        assert_eq!(engine.test_backend_invocations(), 0);
    }
}

#[tokio::test]
async fn a_replaced_plan_or_downgraded_metadata_cannot_become_a_proposal_grant_or_cancel_source() {
    for defect in ["inode", "downgrade"] {
        let (f, snapshot, proof, input) = fixture();
        let request = "proposal-tampered";
        let receipt = prepare(&f, &snapshot, &proof, &input, request).unwrap();
        if defect == "inode" {
            let path = plan(&f, request);
            let bytes = fs::read(&path).unwrap();
            fs::rename(&path, path.with_extension("retained")).unwrap();
            durable::publish_new(&path, &bytes, FileMetadata::private()).unwrap();
        } else {
            let path = f.root.join("firewall/transaction.json");
            let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            record["schemaVersion"] = json!(1);
            record.as_object_mut().unwrap().remove("authorization");
            durable::json(&path, &record).unwrap();
        }
        let engine = crate::firewall::Firewall::open(f.root.clone(), None).unwrap();
        let bytes = fs::read(f.root.join("firewall/transaction.json")).unwrap();
        assert!(
            engine
                .imported_metadata_request(
                    "firewall.kura.imported.cancel".into(),
                    action(&input, &receipt, request),
                    77
                )
                .await
                .is_err()
        );
        assert!(
            engine
                .imported_metadata_request(
                    "firewall.kura.imported.outcome".into(),
                    outcome(&input, request),
                    77
                )
                .await
                .is_err()
        );
        assert_eq!(
            fs::read(f.root.join("firewall/transaction.json")).unwrap(),
            bytes
        );
        assert_eq!(engine.test_backend_invocations(), 0);
    }
}

#[test]
fn current_history_and_a_new_registration_do_not_rewrite_the_original_owner_or_accept_a_stale_firewall_proof()
 {
    let (f, snapshot) = journal_cases::committed_for_producer_test();
    let source = fs::read(f.store.journal_path()).unwrap();
    assert_eq!(snapshot.revision(), 2);
    let proof = proof(&f, &snapshot, Instant::now() + Duration::from_secs(300));
    let mut input = change(&f, &snapshot);
    input.as_object_mut().unwrap().remove("ownerKey");
    input.as_object_mut().unwrap().remove("cohortDigest");
    input.as_object_mut().unwrap().remove("confirmSeconds");
    assert_eq!(
        producer::review(&snapshot, serde_json::from_value(input).unwrap(), &proof).unwrap()["nativePlan"]
            ["targetRevision"],
        3
    );
    let (journal, _) = f.store.load().unwrap().unwrap();
    let original_source = durable::hash(&fs::read(f.root.join(POLICY)).unwrap());
    let original = owner(&f, 1, &original_source, f.baseline.roles.bridge_epoch);
    let active = Active {
        binding: Binding {
            operation_id: f.id,
            plan_sha256: journal.plan_sha256,
            lease_sha256: "e".repeat(64),
        },
        baseline: f.baseline.clone(),
    };
    assert!(
        Verified::storage_fixture(
            &snapshot,
            active,
            original.clone(),
            original,
            "b".repeat(64),
            Instant::now() + Duration::from_secs(30)
        )
        .is_err()
    );
    assert_eq!(fs::read(f.store.journal_path()).unwrap(), source);
    assert!(f.store.active_owner().unwrap().is_none());
}

#[test]
fn an_expired_synthetic_proof_cannot_publish_a_proposal() {
    let (f, snapshot, _, input) = fixture();
    let proof = proof(&f, &snapshot, Instant::now() - Duration::from_secs(1));
    assert!(prepare(&f, &snapshot, &proof, &input, "expired-proof").is_err());
    assert!(!f.root.join("firewall/transaction.json").exists());
    assert!(!f.root.join("firewall/kura-history").exists());
}
