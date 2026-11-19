//! Temporary-filesystem interruption contracts with explicit synthetic authority.
//! No registered owner,ordinary gateway or new live nft acceptance is claimed.
use super::*;
use crate::nm::coordinator::imported::Observed;
use producer::{Snapshot, observation};
use std::time::{Duration, Instant};

#[tokio::test]
async fn remote_service_source_observation_keeps_schema5_audit_and_has_no_dispatch_or_confirmation_bits() {
    let f=fixture();let snapshot=Snapshot::take(&f.root).unwrap();let native=changed(&f.current);
    let(proof,input)=proposal(&f,&snapshot,&native);
    let principal=producer::principal::storage_principal(&input,true).await;
    let _guard=crate::system_change::Guard::observe(&f.root).unwrap();
    observation::prepare_remote(&f.root,&snapshot,serde_json::from_value(input.clone()).unwrap(),&principal,&proof).unwrap();
    let record:Value=serde_json::from_slice(&fs::read(f.root.join("firewall/transaction.json")).unwrap()).unwrap();
    assert_eq!(record["schemaVersion"],5);assert_eq!(record["uid"],principal.uid());
    assert_eq!(record["origin"]["authorityKind"],"REMOTE_ORIGINAL");
    for bit in ["forwardIntent","inverseIntent","confirmedDecision"] {assert_eq!(record[bit],false);}
    let queried=observation::outcome(&f.root,principal.uid(),serde_json::from_value(outcome(&input,principal.request_id())).unwrap()).unwrap();
    assert_eq!(queried["historical"],true);assert_eq!(queried["state"],"OBSERVED");
    let current=Snapshot::take(&f.root).unwrap();assert_eq!(current.revision(),snapshot.revision());current.require_native(&native).unwrap();
}

fn fixture() -> Fixture {
    let mut f = Fixture::before_native();
    let name = format!("yofc_fwt_{}", f.id.simple());
    for entry in f.current["nftables"].as_array_mut().unwrap() {
        if entry["table"]["name"] == name {
            entry["table"]["handle"] = json!(500_001);
        }
    }
    let writes = AtomicUsize::new(0);
    f.store
        .native_change_fixture(
            f.id,
            &f.token,
            "actor",
            false,
            |_, _, _, after| {
                Ok(if after {
                    f.current.clone()
                } else {
                    f.baseline
                        .native_transfer
                        .as_ref()
                        .unwrap()
                        .original
                        .clone()
                })
            },
            |_| {
                writes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    f.initialize().unwrap();
    assert!(f.store.active_owner().unwrap().is_none());
    f
}
fn changed(native: &Value) -> Value {
    let mut value = native.clone();
    value["kernelGeneration"] = json!(value["kernelGeneration"].as_u64().unwrap() + 3);
    value["nftables"].as_array_mut().unwrap().push(
        json!({"table":{"family":"inet","name":"source-observation-foreign","handle":700_001}}),
    );
    value
}
fn proposal(f: &Fixture, snapshot: &Snapshot, native: &Value) -> (Observed, Value) {
    let id = uuid::Uuid::new_v4();
    let plan = snapshot
        .observation_plan(id, &native::epoch::Epoch::storage_fixture(), native)
        .unwrap();
    let proof = producer_cases::proof(f, snapshot, Instant::now() + Duration::from_secs(300));
    let proof = Observed::storage_fixture(snapshot, proof, plan).unwrap();
    let input = json!({"ownerKey":"a".repeat(64),"operationId":id,"expectedRevision":snapshot.revision(),
        "sourceDigest":snapshot.source(),"cohortDigest":proof.cohort(),
        "observedNativeSha256":proof.plan().parameters().unwrap()["observedNativeSha256"]});
    (proof, input)
}
fn prepare(
    f: &Fixture,
    snapshot: &Snapshot,
    proof: &Observed,
    input: &Value,
    request: &str,
) -> Result<Value> {
    let _guard = crate::system_change::Guard::observe(&f.root)?;
    observation::prepare(
        &f.root,
        snapshot,
        serde_json::from_value(input.clone())?,
        77,
        request,
        proof,
    )
}
fn history(f: &Fixture, request: &str) -> PathBuf {
    f.root.join("firewall/kura-history").join(format!(
        "{}.json",
        durable::hash(format!("77:{request}").as_bytes())
    ))
}
fn outcome(input: &Value, request: &str) -> Value {
    json!({"originalRequestId":request,"change":input})
}
fn tree(root: &Path) -> std::collections::BTreeMap<PathBuf, String> {
    fn visit(
        root: &Path,
        current: &Path,
        result: &mut std::collections::BTreeMap<PathBuf, String>,
    ) {
        for entry in fs::read_dir(current).unwrap() {
            let f = entry.unwrap().path();
            if f.is_dir() {
                visit(root, &f, result);
            } else {
                result.insert(
                    f.strip_prefix(root).unwrap().into(),
                    durable::hash(&fs::read(f).unwrap()),
                );
            }
        }
    }
    let mut result = std::collections::BTreeMap::new();
    visit(root, root, &mut result);
    result
}

#[test]
fn source_observation_controller_refuses_disabled_grant_and_foreign_installation_before_any_effect()
{
    struct NoNetworkCalls;
    impl crate::nm::Wire for NoNetworkCalls {
        fn call(&self, _: &crate::nm::BusCall, _: Instant) -> Result<Value> {
            panic!("source observation must reject before any NM call")
        }
    }
    let f = fixture();
    let snapshot = Snapshot::take(&f.root).unwrap();
    let nm = crate::nm::Nm::for_test(
        json!({"schemaVersion":1,"interfaces":["eth0"],"writeEnabled":true}),
        std::sync::Arc::new(NoNetworkCalls),
        &f.root,
    )
    .unwrap();
    let operation = uuid::Uuid::new_v4();
    let review = json!({"operationId":operation,"expectedRevision":snapshot.revision(),
        "sourceDigest":snapshot.source()});
    let change = json!({"ownerKey":"a".repeat(64),"operationId":operation,
        "expectedRevision":snapshot.revision(),"sourceDigest":snapshot.source(),
        "cohortDigest":"b".repeat(64),"observedNativeSha256":"c".repeat(64)});
    let before = tree(&f.root);
    let error = nm
        .engine
        .as_ref()
        .unwrap()
        .imported_request(
            "firewall.kura.imported.source.observe",
            change.clone(),
            77,
            "missing-live-owner",
            false,
        )
        .unwrap_err();
    assert!(error.to_string().contains("grant disabled"), "{error}");
    assert_eq!(tree(&f.root), before);
    let mismatch = nm
        .engine
        .as_ref()
        .unwrap()
        .imported_request(
            "firewall.kura.imported.source.review",
            review.clone(),
            77,
            "wrong-installation",
            true,
        )
        .unwrap_err();
    assert!(
        mismatch
            .to_string()
            .contains("initialization changed original operation/plan/baseline"),
        "{mismatch}"
    );
    let engine = nm.engine.as_ref().unwrap();
    // Production EX admission checks its actual installation marker before
    // collecting a live owner. A relocated storage fixture cannot bypass it.
    for (method, input) in [
        ("firewall.kura.imported.source.review", review),
        ("firewall.kura.imported.source.observe", change),
    ] {
        let error = engine
            .imported_request(method, input, 77, "missing-live-owner", true)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("initialization changed original operation/plan/baseline"),
            "{error}"
        );
    }
    let unchanged = Snapshot::take(&f.root).unwrap();
    assert_eq!(snapshot.revision(), unchanged.revision());
    assert_eq!(snapshot.source(), unchanged.source());
    assert!(!f.root.join("firewall/transaction.json").exists());
    assert!(!f.root.join("firewall/confirmed.json").exists());
    assert!(!f.root.join("firewall/kura-history").exists());
    assert_eq!(
        fs::read(f.store.artifact(f.id, "intent")).unwrap(),
        f.original
    );
}

#[tokio::test]
async fn source_observation_uses_same_history_advances_physical_head_without_revision_or_native_effect()
 {
    let f = fixture();
    let snapshot = Snapshot::take(&f.root).unwrap();
    let native = changed(&f.current);
    let anchor = fs::read(f.root.join(POLICY)).unwrap();
    let original = fs::read(f.store.journal_path()).unwrap();
    let (proof, input) = proposal(&f, &snapshot, &native);
    let result = prepare(&f, &snapshot, &proof, &input, "source-observation").unwrap();
    assert_eq!(result["state"], "OBSERVED");
    assert_eq!(result["kind"], "SOURCE_OBSERVATION");
    assert_eq!(result["kernelEffect"], false);
    assert_eq!(result["requiresConfirmation"], false);
    assert!(result.get("confirmationToken").is_none());
    let record: Value =
        serde_json::from_slice(&fs::read(f.root.join("firewall/transaction.json")).unwrap())
            .unwrap();
    assert_eq!(record["schemaVersion"], 3);
    assert_eq!(record["forwardIntent"], false);
    assert_eq!(record["inverseIntent"], false);
    assert_eq!(record["settlementIntent"], true);
    assert!(record.get("forwardDispatch").is_none() && record.get("inverseDispatch").is_none());
    let next = Snapshot::take(&f.root).unwrap();
    assert_eq!(next.revision(), snapshot.revision());
    assert_ne!(next.source(), snapshot.source());
    next.require_native(&native).unwrap();
    assert!(next.require_native(&f.current).is_err());
    assert_eq!(fs::read(f.root.join(POLICY)).unwrap(), anchor);
    assert_eq!(fs::read(f.store.journal_path()).unwrap(), original);
    assert_eq!(
        fs::read(f.store.artifact(f.id, "intent")).unwrap(),
        f.original
    );
    let engine = crate::firewall::Firewall::open(f.root.clone(), None)
        .unwrap()
        .enable_writes(false);
    let before = tree(&f.root);
    let queried = engine
        .imported_metadata_request(
            "firewall.kura.imported.source.outcome".into(),
            outcome(&input, "source-observation"),
            77,
        )
        .await
        .unwrap();
    assert_eq!(queried["state"], "OBSERVED");
    assert_eq!(queried["ownerGrant"], false);
    assert_eq!(tree(&f.root), before);
    // The ownership coordinator has independent admission for its own Root
    // journal, but still requires complete settlement of the imported firewall.
    drop(crate::system_change::Guard::acquire(&f.root, crate::system_change::Subsystem::NmOwnership)
        .expect("settled typed observation must be admitted by its own classifier"));
    let pointer = f.root.join("firewall/confirmed.json");
    let raw = fs::read(&pointer).unwrap();
    let mut invalid: Value = serde_json::from_slice(&raw).unwrap();
    invalid["sourceDigest"] = json!("c".repeat(64));
    durable::json(&pointer, &invalid).unwrap();
    assert!(crate::system_change::Guard::acquire(&f.root, crate::system_change::Subsystem::NmOwnership).is_err());
}

#[tokio::test]
async fn interrupted_observation_repairs_only_existing_original_history_and_never_republishes_it() {
    let f = fixture();
    let snapshot = Snapshot::take(&f.root).unwrap();
    let (proof, input) = proposal(&f, &snapshot, &changed(&f.current));
    prepare(&f, &snapshot, &proof, &input, "lost-source-pointer").unwrap();
    let path = history(&f, "lost-source-pointer");
    let retained = fs::read(&path).unwrap();
    let identity = std::os::unix::fs::MetadataExt::ino(&fs::metadata(&path).unwrap());
    // Fault model for this fresh metadata-only event,not a rewind of its original native intent.
    let mut active: Value =
        serde_json::from_slice(&fs::read(f.root.join("firewall/transaction.json")).unwrap())
            .unwrap();
    active["state"] = json!("OBSERVING");
    durable::json(&f.root.join("firewall/transaction.json"), &active).unwrap();
    fs::remove_file(f.root.join("firewall/confirmed.json")).unwrap();
    assert!(Snapshot::take(&f.root).is_err());
    let engine = crate::firewall::Firewall::open(f.root.clone(), None)
        .unwrap()
        .enable_writes(false);
    engine
        .imported_metadata_request(
            "firewall.kura.imported.source.outcome".into(),
            outcome(&input, "lost-source-pointer"),
            77,
        )
        .await
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), retained);
    assert_eq!(
        std::os::unix::fs::MetadataExt::ino(&fs::metadata(&path).unwrap()),
        identity
    );
    assert_eq!(Snapshot::take(&f.root).unwrap().revision(), 1);
    let before = tree(&f.root);
    engine
        .imported_metadata_request(
            "firewall.kura.imported.source.outcome".into(),
            outcome(&input, "lost-source-pointer"),
            77,
        )
        .await
        .unwrap();
    assert_eq!(tree(&f.root), before);
}

#[tokio::test]
async fn attempted_missing_observation_history_is_unknown_and_cannot_be_recreated_or_replaced_by_new_ids()
 {
    let f = fixture();
    let snapshot = Snapshot::take(&f.root).unwrap();
    let (proof, input) = proposal(&f, &snapshot, &changed(&f.current));
    prepare(&f, &snapshot, &proof, &input, "attempted-source").unwrap();
    let path = history(&f, "attempted-source");
    fs::remove_file(&path).unwrap();
    fs::remove_file(f.root.join("firewall/confirmed.json")).unwrap();
    let before = tree(&f.root);
    let engine = crate::firewall::Firewall::open(f.root.clone(), None)
        .unwrap()
        .enable_writes(false);
    let error = engine
        .imported_metadata_request(
            "firewall.kura.imported.source.outcome".into(),
            outcome(&input, "attempted-source"),
            77,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().starts_with("OUTCOME_UNKNOWN:"));
    assert!(!path.exists());
    assert_eq!(tree(&f.root), before);
    assert!(Snapshot::take(&f.root).is_err());
    assert!(prepare(&f, &snapshot, &proof, &input, "new-source-id").is_err());
    assert!(!history(&f, "new-source-id").exists());
}

#[tokio::test]
async fn unreachable_observation_is_not_a_no_effect_cancellation_or_a_fresh_owner_grant() {
    let f = fixture();
    let snapshot = Snapshot::take(&f.root).unwrap();
    let (proof, input) = proposal(&f, &snapshot, &changed(&f.current));
    prepare(&f, &snapshot, &proof, &input, "orphan-source").unwrap();
    fs::remove_file(f.root.join("firewall/transaction.json")).unwrap();
    fs::remove_file(f.root.join("firewall/confirmed.json")).unwrap();
    assert!(Snapshot::take(&f.root).is_err());
    let before = tree(&f.root);
    let engine = crate::firewall::Firewall::open(f.root.clone(), None)
        .unwrap()
        .enable_writes(false);
    let recorded = engine
        .imported_metadata_request(
            "firewall.kura.imported.source.outcome".into(),
            outcome(&input, "orphan-source"),
            77,
        )
        .await
        .unwrap();
    assert_eq!(recorded["ownerGrant"], false);
    assert_eq!(recorded["historical"], true);
    assert_eq!(tree(&f.root), before);
    assert!(Snapshot::take(&f.root).is_err());
}

#[tokio::test]
async fn first_unattempted_original_observation_may_publish_once_and_pending_work_blocks_every_new_id()
 {
    let f = fixture();
    let snapshot = Snapshot::take(&f.root).unwrap();
    let (proof, input) = proposal(&f, &snapshot, &changed(&f.current));
    {
        let _guard = crate::system_change::Guard::observe(&f.root).unwrap();
        let staged = observation::stage_fixture(
            &f.root,
            &snapshot,
            serde_json::from_value(input.clone()).unwrap(),
            77,
            "unattempted-source",
            &proof,
        )
        .unwrap();
        assert_eq!(staged["state"], "OBSERVING");
    }
    assert!(!history(&f, "unattempted-source").exists());
    assert!(Snapshot::take(&f.root).is_err());
    let mut new_input = input.clone();
    new_input["operationId"] = json!(uuid::Uuid::new_v4());
    assert!(prepare(&f, &snapshot, &proof, &new_input, "bypass-source-id").is_err());
    let engine = crate::firewall::Firewall::open(f.root.clone(), None)
        .unwrap()
        .enable_writes(false);
    let first = engine
        .imported_metadata_request(
            "firewall.kura.imported.source.outcome".into(),
            outcome(&input, "unattempted-source"),
            77,
        )
        .await
        .unwrap();
    assert_eq!(first["state"], "OBSERVED");
    assert!(history(&f, "unattempted-source").exists());
    let before = tree(&f.root);
    engine
        .imported_metadata_request(
            "firewall.kura.imported.source.outcome".into(),
            outcome(&input, "unattempted-source"),
            77,
        )
        .await
        .unwrap();
    assert_eq!(tree(&f.root), before);
}

#[tokio::test]
async fn lost_final_pointer_repairs_from_exact_existing_history_without_recreating_the_history() {
    let f = fixture();
    let snapshot = Snapshot::take(&f.root).unwrap();
    let (proof, input) = proposal(&f, &snapshot, &changed(&f.current));
    prepare(&f, &snapshot, &proof, &input, "final-source-pointer").unwrap();
    let path = history(&f, "final-source-pointer");
    let retained = fs::read(&path).unwrap();
    fs::remove_file(f.root.join("firewall/confirmed.json")).unwrap();
    assert!(Snapshot::take(&f.root).is_err());
    let engine = crate::firewall::Firewall::open(f.root.clone(), None)
        .unwrap()
        .enable_writes(false);
    engine
        .imported_metadata_request(
            "firewall.kura.imported.source.outcome".into(),
            outcome(&input, "final-source-pointer"),
            77,
        )
        .await
        .unwrap();
    assert_eq!(fs::read(path).unwrap(), retained);
    assert_eq!(Snapshot::take(&f.root).unwrap().revision(), 1);
}

#[test]
fn observed_parent_supports_strict_updates_but_cancellation_never_advances_its_physical_head() {
    let f = fixture();
    let snapshot = Snapshot::take(&f.root).unwrap();
    let native = changed(&f.current);
    let (proof, input) = proposal(&f, &snapshot, &native);
    prepare(&f, &snapshot, &proof, &input, "parent-source").unwrap();
    let current = Snapshot::take(&f.root).unwrap();
    let current_source = current.source().to_string();
    let mut next_native = native.clone();
    next_native["kernelGeneration"] = json!(native["kernelGeneration"].as_u64().unwrap() + 1);
    let id = serde_json::from_value(input["operationId"].clone()).unwrap();
    let plan = current
        .observation_plan(id, &native::epoch::Epoch::storage_fixture(), &next_native)
        .unwrap();
    let repeated = Observed::storage_fixture(
        &current,
        producer_cases::proof(&f, &current, Instant::now() + Duration::from_secs(300)),
        plan,
    )
    .unwrap();
    let mut duplicate = input.clone();
    duplicate["sourceDigest"] = json!(current.source());
    duplicate["observedNativeSha256"] =
        repeated.plan().parameters().unwrap()["observedNativeSha256"].clone();
    let before = tree(&f.root);
    assert!(
        prepare(
            &f,
            &current,
            &repeated,
            &duplicate,
            "duplicate-observation-uuid"
        )
        .is_err()
    );
    assert_eq!(tree(&f.root), before);
    let mut candidate = core_view(&f.root).unwrap().unwrap()["candidate"].clone();
    candidate["portForward"][0]["outPort"] =
        json!(candidate["portForward"][0]["outPort"].as_u64().unwrap() + 1);
    let change = json!({"ownerKey":"a".repeat(64),"operationId":uuid::Uuid::new_v4(),"expectedRevision":current.revision(),
        "sourceDigest":current.source(),"cohortDigest":"b".repeat(64),"confirmSeconds":120,"candidate":candidate,
        "destinationPrefixes":{"ipv4":[32],"ipv6":[64]}});
    let strict = producer_cases::proof(&f, &current, Instant::now() + Duration::from_secs(300));
    let _guard = crate::system_change::Guard::observe(&f.root).unwrap();
    let pending = producer::prepare(
        &f.root,
        &current,
        serde_json::from_value(change.clone()).unwrap(),
        77,
        "after-source-update",
        &strict,
    )
    .unwrap();
    producer::cancel(
        &f.root,
        77,
        serde_json::from_value(producer_cases::action(
            &change,
            &pending,
            "after-source-update",
        ))
        .unwrap(),
    )
    .unwrap();
    let after = Snapshot::take(&f.root).unwrap();
    assert_eq!(after.source(), current_source);
    assert_eq!(after.revision(), 1);
    after.require_native(&native).unwrap();
}

#[test]
fn source_observation_rejects_wrong_owner_context_and_schema_dispatch_bits_without_publishing() {
    let f = fixture();
    let snapshot = Snapshot::take(&f.root).unwrap();
    let (proof, input) = proposal(&f, &snapshot, &changed(&f.current));
    for field in ["cohortDigest", "observedNativeSha256", "sourceDigest"] {
        let mut wrong = input.clone();
        wrong[field] = json!("c".repeat(64));
        assert!(prepare(&f, &snapshot, &proof, &wrong, "wrong-source-context").is_err());
        assert!(!f.root.join("firewall/transaction.json").exists());
    }
    prepare(&f, &snapshot, &proof, &input, "owned-source").unwrap();
    let record: Value =
        serde_json::from_slice(&fs::read(history(&f, "owned-source")).unwrap()).unwrap();
    let active = f.root.join("firewall/transaction.json");
    for field in ["forwardIntent", "inverseIntent", "confirmedDecision"] {
        let mut wrong = record.clone();
        wrong[field] = json!(true);
        durable::json(&active, &wrong).unwrap();
        assert!(Snapshot::take(&f.root).is_err());
    }
    let mut wrong = record.clone();
    wrong["schemaVersion"] = json!(2);
    durable::json(&active, &wrong).unwrap();
    assert!(Snapshot::take(&f.root).is_err());
    durable::json(&active, &record).unwrap();
    let mut wrong = outcome(&input, "owned-source");
    wrong["change"]["ownerKey"] = json!("c".repeat(64));
    let _guard = crate::system_change::Guard::observe(&f.root).unwrap();
    assert!(
        observation::outcome(&f.root, 77, serde_json::from_value(wrong).unwrap())
            .unwrap_err()
            .to_string()
            .starts_with("FORBIDDEN:")
    );
}
