//! Actual temporary files, production plans and netlink-payload ACK fixtures.
//! These are storage/read contracts; they do not simulate an owner lease or
//! claim that an ordinary transaction has been authorized/dispatched.
use super::*;
use native::lineage::{CurrentSource, UpdatePlan};

struct Case {
    f: Fixture,
    anchor: String,
    seed: Value,
    current: CurrentSource,
    anchor_bytes: Vec<u8>,
    owner_bytes: Vec<u8>,
}
struct Transaction {
    record: Value,
    head: Value,
    plan: UpdatePlan,
    forward: Value,
    inverse: Value,
    next: CurrentSource,
    old: CurrentSource,
}

fn directory_value(path: &Path) -> Value {
    let m = fs::symlink_metadata(path).unwrap();
    json!({"device":m.dev(),"inode":m.ino()})
}
fn reference(root: &Path, path: &Path) -> Value {
    let file = BoundFile::open(path, LIMIT).unwrap();
    json!({"file":file.marker().unwrap(),"firewall":directory_value(&root.join("firewall")),
        "history":directory_value(&root.join("firewall/kura-history")),"parent":directory_value(path.parent().unwrap())})
}
fn key(uid: u32, request: &str) -> String {
    durable::hash(format!("{uid}:{request}").as_bytes())
}
fn archive_path(root: &Path, request: &str) -> PathBuf {
    root.join("firewall/kura-history")
        .join(format!("{}.json", key(77, request)))
}
fn artifact_path(root: &Path, request: &str, name: &str) -> PathBuf {
    root.join("firewall/kura-history")
        .join(format!("{}.artifacts", key(77, request)))
        .join(name)
}
fn publish(path: &Path, value: &Value) {
    durable::directory(path.parent().unwrap()).unwrap();
    durable::publish_new(
        path,
        &serde_json::to_vec(value).unwrap(),
        FileMetadata::private(),
    )
    .unwrap();
}

impl Case {
    fn new() -> Self {
        let f = Fixture::new();
        f.initialize().unwrap();
        let view = core_view(&f.root).unwrap().unwrap();
        let anchor = view["preservedSource"]["initializationReceiptSha256"]
            .as_str()
            .unwrap()
            .to_string();
        let prefixes = BTreeMap::from([("ipv4".into(), vec![24]), ("ipv6".into(), vec![64])]);
        let current = CurrentSource::from_acknowledged(
            &anchor,
            1,
            view["candidate"].clone(),
            prefixes,
            f.baseline.native_transfer.as_ref().unwrap(),
            &f.current,
            false,
        )
        .unwrap();
        let seed = json!({"kind":"INITIALIZATION","receiptSha256":anchor});
        let anchor_bytes = fs::read(f.root.join(POLICY)).unwrap();
        let owner_bytes = fs::read(f.store.journal_path()).unwrap();
        Self {
            f,
            anchor,
            seed,
            current,
            anchor_bytes,
            owner_bytes,
        }
    }
    fn transaction(&self, parent: &CurrentSource, base: &Value, request: &str) -> Transaction {
        durable::directory(&self.f.root.join("firewall/kura-history")).unwrap();
        let before = parent.witness().unwrap();
        let mut candidate = before["currentPolicy"].clone();
        candidate["portForward"][0]["outPort"] =
            json!(candidate["portForward"][0]["outPort"].as_u64().unwrap() + 1);
        let mut prefixes: BTreeMap<String, Vec<u8>> =
            serde_json::from_value(before["currentDestinationPrefixes"].clone()).unwrap();
        prefixes.insert("ipv4".into(), vec![32]);
        let id = uuid::Uuid::new_v4();
        let plan = parent.plan(id, candidate, prefixes).unwrap();
        let value = serde_json::to_value(&plan).unwrap();
        let transfer: native::Transfer = serde_json::from_value(value["transfer"].clone()).unwrap();
        let forward = native::lineage::tests::outcome(&transfer, false);
        let inverse = native::lineage::tests::outcome(&transfer, true);
        let next = plan.settled_source(parent, &forward, false).unwrap();
        for (name, value) in [
            ("plan.json", value),
            ("forward.json", forward.clone()),
            ("inverse.json", inverse.clone()),
        ] {
            publish(&artifact_path(&self.f.root, request, name), &value);
        }
        let record = json!({"backend":"nft.imported.v1","schemaVersion":1,"id":id,"uid":77,"requestId":request,"ownerSha256":"b".repeat(64),"inputSha256":"c".repeat(64),
            "initializationReceiptSha256":self.anchor,
            "state":"COMMITTED","deadlineMs":9_000_000_000_000u64,"base":base,
            "plan":reference(&self.f.root,&artifact_path(&self.f.root,request,"plan.json")),"forwardIntent":true,"inverseIntent":false,"confirmedDecision":true,
            "forward":reference(&self.f.root,&artifact_path(&self.f.root,request,"forward.json"))});
        Transaction {
            record,
            head: Value::Null,
            plan,
            forward,
            inverse,
            next,
            old: parent.clone(),
        }
    }
    fn install(&self, transaction: &mut Transaction) {
        let request = transaction.record["requestId"].as_str().unwrap();
        let path = archive_path(&self.f.root, request);
        publish(&path, &transaction.record);
        transaction.head = json!({"kind":"TRANSACTION","uid":77,"requestId":request,"reference":reference(&self.f.root,&path)});
        self.pointer(&transaction.head, &transaction.next);
        durable::json(
            &self.f.root.join("firewall/transaction.json"),
            &transaction.record,
        )
        .unwrap();
    }
    fn pointer(&self, head: &Value, current: &CurrentSource) {
        let witness = current.witness().unwrap();
        durable::json(&self.f.root.join("firewall/confirmed.json"),&json!({"backend":"nft.imported.v1","schemaVersion":1,
            "head":head,"revision":witness["revision"].as_str().unwrap().parse::<u64>().unwrap(),"sourceDigest":witness["sourceDigest"]})).unwrap();
    }
    fn unchanged_anchor(&self) {
        assert_eq!(
            fs::read(self.f.root.join(POLICY)).unwrap(),
            self.anchor_bytes
        );
        assert_eq!(
            fs::read(self.f.store.journal_path()).unwrap(),
            self.owner_bytes
        );
        let (_, plan) = self.f.store.load().unwrap().unwrap();
        assert!(plan.baseline == self.f.baseline);
    }
}

pub(super) fn committed_for_producer_test()->(Fixture,crate::nm::handover::initialization::producer::Snapshot) {
    let c=Case::new();let mut tx=c.transaction(&c.current,&c.seed,"producer-current-base");c.install(&mut tx);
    let snapshot=crate::nm::handover::initialization::producer::Snapshot::take(&c.f.root).unwrap();
    (c.f,snapshot)
}

#[test]
fn current_view_derives_revision_policy_prefixes_and_native_source_from_same_domain_history() {
    let c = Case::new();
    let mut tx = c.transaction(&c.current, &c.seed, "history-first");
    c.install(&mut tx);
    let view = core_view(&c.f.root).unwrap().unwrap();
    assert_eq!(view["revision"], 2);
    assert_eq!(view["candidate"]["portForward"][0]["outPort"], 2451);
    assert_eq!(
        view["preservedSource"]["families"]["ipv4"]["runtimePortForwardDestinationPrefixes"],
        json!([32])
    );
    assert_eq!(
        view["preservedSource"]["kernelObservation"],
        "confirmedTransactionAcknowledgement"
    );
    assert_eq!(view["journalSettled"], true);
    assert_eq!(view["writeEnabled"], false);
    assert_eq!(
        view["preservedSource"]["initializationReceiptSha256"],
        c.anchor
    );
    assert_eq!(
        view["sourceDigest"],
        tx.next.witness().unwrap()["sourceDigest"]
    );
    assert_eq!(
        confirmed_source(&c.f.root, Some(&tx.forward))
            .unwrap()
            .unwrap()["revision"],
        "2"
    );
    assert!(confirmed_source(&c.f.root, Some(&c.f.current)).is_err());
    let preview=preview_update(&c.f.root,json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":2,"sourceDigest":view["sourceDigest"],"candidate":view["candidate"],"destinationPrefixes":{"ipv4":[32],"ipv6":[64]}})).unwrap();
    assert_eq!(preview["nativePlan"]["baseRevision"], 2);
    assert_eq!(preview["nativePlan"]["targetRevision"], 3);
    assert_eq!(preview["nativePlan"]["applyReady"], false);
    c.f.store
        .initialization_original(c.f.id, "actor", |_, _, _| {
            panic!("historical committed initialization query must not inspect/drain/export again")
        })
        .unwrap();
    c.unchanged_anchor();
    println!("IMPORTED_HISTORY_CORE_VIEW_FIXTURE={view}");
}

#[test]
fn inverse_history_keeps_logical_revision_and_policy_but_publishes_a_new_physical_receipt() {
    let c = Case::new();
    let mut first = c.transaction(&c.current, &c.seed, "history-base");
    c.install(&mut first);
    let old = core_view(&c.f.root).unwrap().unwrap();
    let mut inverse = c.transaction(&first.next, &first.head, "history-inverse");
    inverse.record["state"] = json!("ROLLED_BACK");
    inverse.record["confirmedDecision"] = json!(false);
    inverse.record["inverseIntent"] = json!(true);
    inverse.record["inverse"] = reference(
        &c.f.root,
        &artifact_path(&c.f.root, "history-inverse", "inverse.json"),
    );
    inverse.next = inverse
        .plan
        .settled_source(&inverse.old, &inverse.inverse, true)
        .unwrap();
    c.install(&mut inverse);
    let view = core_view(&c.f.root).unwrap().unwrap();
    assert_eq!(view["revision"], old["revision"]);
    assert_eq!(view["candidate"], old["candidate"]);
    assert_ne!(view["sourceDigest"], old["sourceDigest"]);
    assert_eq!(
        view["sourceDigest"],
        inverse.next.witness().unwrap()["sourceDigest"]
    );
    assert!(confirmed_source(&c.f.root, Some(&first.forward)).is_err());
    assert_eq!(
        confirmed_source(&c.f.root, Some(&inverse.inverse))
            .unwrap()
            .unwrap()["sourceDigest"],
        view["sourceDigest"]
    );
    c.unchanged_anchor();
}

#[tokio::test]
async fn retained_apply_intent_blocks_new_ids_and_boot_recovery_never_calls_a_private_backend() {
    let c = Case::new();
    let mut tx = c.transaction(&c.current, &c.seed, "history-unknown");
    tx.record["state"] = json!("APPLYING");
    tx.record["confirmedDecision"] = json!(false);
    tx.record.as_object_mut().unwrap().remove("forward");
    durable::json(&c.f.root.join("firewall/transaction.json"), &tx.record).unwrap();
    let bytes = fs::read(c.f.root.join("firewall/transaction.json")).unwrap();
    let view = core_view(&c.f.root).unwrap().unwrap();
    assert_eq!(view["revision"], 1);
    assert_eq!(view["journalSettled"], false);
    assert_eq!(view["transaction"]["state"], "APPLYING");
    assert_eq!(view["transaction"]["requiresOriginalQuery"], true);
    assert!(preview_update(&c.f.root,json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":1,"sourceDigest":view["sourceDigest"],"candidate":view["candidate"],"destinationPrefixes":{"ipv4":[24],"ipv6":[64]}})).unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN:"));
    let engine = crate::firewall::Firewall::open(
        c.f.root.clone(),
        Some("/nonexistent/no-private-imported-recovery".into()),
    )
    .unwrap()
    .enable_writes(true);
    engine.recover().await.unwrap();
    assert_eq!(engine.test_backend_invocations(), 0);
    assert!(
        engine
            .kura_request(
                "firewall.kura.prepare".into(),
                json!({}),
                "another-id".into(),
                77,
                true
            )
            .await
            .is_err()
    );
    assert_eq!(
        fs::read(c.f.root.join("firewall/transaction.json")).unwrap(),
        bytes
    );
    assert!(!c.f.root.join("firewall/confirmed.json").exists());
    c.unchanged_anchor();
}

#[test]
fn caller_revision_and_rehashed_plan_metadata_cannot_manufacture_a_new_history_revision() {
    let c = Case::new();
    let mut tx = c.transaction(&c.current, &c.seed, "history-forged");
    let plan_path = artifact_path(&c.f.root, "history-forged", "plan.json");
    let mut plan: Value = serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
    plan["targetRevision"] = json!(777);
    durable::json(&plan_path, &plan).unwrap();
    tx.record["plan"] = reference(&c.f.root, &plan_path);
    c.install(&mut tx);
    let pointer = c.f.root.join("firewall/confirmed.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&pointer).unwrap()).unwrap();
    value["revision"] = json!(777);
    durable::json(&pointer, &value).unwrap();
    assert!(core_view(&c.f.root).is_err());
    assert!(confirmed_source(&c.f.root, None).is_err());
    c.unchanged_anchor();
}

#[test]
fn identical_plan_bytes_at_a_new_inode_never_replace_a_bound_history_artifact() {
    let c = Case::new();
    let mut tx = c.transaction(&c.current, &c.seed, "history-replaced");
    c.install(&mut tx);
    let path = artifact_path(&c.f.root, "history-replaced", "plan.json");
    let bytes = fs::read(&path).unwrap();
    fs::rename(&path, path.with_extension("retained")).unwrap();
    durable::publish_new(&path, &bytes, FileMetadata::private()).unwrap();
    assert!(core_view(&c.f.root).is_err());
    c.unchanged_anchor();
}

#[test]
fn missing_or_foreign_ack_never_falls_back_to_revision_one() {
    let c = Case::new();
    let mut tx = c.transaction(&c.current, &c.seed, "history-ack");
    c.install(&mut tx);
    let path = artifact_path(&c.f.root, "history-ack", "forward.json");
    fs::rename(&path, path.with_extension("retained")).unwrap();
    assert!(core_view(&c.f.root).is_err());
    let other = c.transaction(&c.current, &c.seed, "history-other");
    publish(&path, &other.forward);
    tx.record["forward"] = reference(&c.f.root, &path);
    let history = archive_path(&c.f.root, "history-ack");
    durable::json(&history, &tx.record).unwrap();
    tx.head["reference"] = reference(&c.f.root, &history);
    c.pointer(&tx.head, &tx.next);
    durable::json(&c.f.root.join("firewall/transaction.json"), &tx.record).unwrap();
    assert!(core_view(&c.f.root).is_err());
    c.unchanged_anchor();
}

#[tokio::test]
async fn committed_pointer_final_marker_is_completed_without_reapplying_or_republishing() {
    let c = Case::new();
    let mut tx = c.transaction(&c.current, &c.seed, "history-prefix");
    c.install(&mut tx);
    tx.record["state"] = json!("CONFIRMING");
    durable::json(&c.f.root.join("firewall/transaction.json"), &tx.record).unwrap();
    let bytes = fs::read(c.f.root.join("firewall/transaction.json")).unwrap();
    let view = core_view(&c.f.root).unwrap().unwrap();
    assert_eq!(view["revision"], 2);
    assert_eq!(view["journalSettled"], false);
    assert_eq!(view["transaction"]["state"], "CONFIRMING");
    let engine = crate::firewall::Firewall::open(
        c.f.root.clone(),
        Some("/nonexistent/no-confirm-reapply".into()),
    )
    .unwrap()
    .enable_writes(true);
    engine.recover().await.unwrap();
    assert_eq!(engine.test_backend_invocations(), 0);
    let after: Value =
        serde_json::from_slice(&fs::read(c.f.root.join("firewall/transaction.json")).unwrap())
            .unwrap();
    assert_eq!(after["state"], "COMMITTED");
    assert_ne!(
        fs::read(c.f.root.join("firewall/transaction.json")).unwrap(),
        bytes
    );
    assert_eq!(
        core_view(&c.f.root).unwrap().unwrap()["journalSettled"],
        true
    );
    let pointer = BoundFile::open(&c.f.root.join("firewall/confirmed.json"), LIMIT)
        .unwrap()
        .marker()
        .unwrap();
    engine.recover().await.unwrap();
    assert!(
        BoundFile::open(&c.f.root.join("firewall/confirmed.json"), LIMIT)
            .unwrap()
            .marker()
            .unwrap()
            == pointer
    );
    c.unchanged_anchor();
}

#[tokio::test]
async fn metadata_completion_never_recreates_a_missing_current_pointer_or_history_file() {
    let c = Case::new();
    let mut tx = c.transaction(&c.current, &c.seed, "history-missing-pointer");
    c.install(&mut tx);
    tx.record["state"] = json!("CONFIRMING");
    durable::json(&c.f.root.join("firewall/transaction.json"), &tx.record).unwrap();
    let pointer = c.f.root.join("firewall/confirmed.json");
    fs::rename(&pointer, pointer.with_extension("retained")).unwrap();
    let engine = crate::firewall::Firewall::open(
        c.f.root.clone(),
        Some("/nonexistent/no-missing-publication-replay".into()),
    )
    .unwrap()
    .enable_writes(true);
    engine.recover().await.unwrap();
    assert!(!pointer.exists());
    assert_eq!(
        core_view(&c.f.root).unwrap().unwrap()["journalSettled"],
        false
    );
    c.pointer(&tx.head, &tx.next);
    let path = archive_path(&c.f.root, "history-missing-pointer");
    fs::rename(&path, path.with_extension("retained")).unwrap();
    assert!(engine.recover().await.is_err());
    assert_eq!(engine.test_backend_invocations(), 0);
    assert!(!path.exists());
    c.unchanged_anchor();
}

#[test]
fn current_pointer_fields_cannot_override_the_revision_and_source_derived_from_valid_history() {
    let c = Case::new();
    let mut tx = c.transaction(&c.current, &c.seed, "history-pointer-fields");
    c.install(&mut tx);
    let path = c.f.root.join("firewall/confirmed.json");
    let original: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let mut altered = original.clone();
    altered["revision"] = json!(999);
    durable::json(&path, &altered).unwrap();
    assert!(core_view(&c.f.root).is_err());
    altered = original;
    altered["sourceDigest"] = json!("f".repeat(64));
    durable::json(&path, &altered).unwrap();
    assert!(core_view(&c.f.root).is_err());
    c.unchanged_anchor();
}

#[tokio::test]
async fn inverse_final_marker_is_completed_only_from_its_existing_acknowledged_pointer() {
    let c = Case::new();
    let mut tx = c.transaction(&c.current, &c.seed, "history-inverse-prefix");
    tx.record["state"] = json!("ROLLED_BACK");
    tx.record["confirmedDecision"] = json!(false);
    tx.record["inverseIntent"] = json!(true);
    tx.record["inverse"] = reference(
        &c.f.root,
        &artifact_path(&c.f.root, "history-inverse-prefix", "inverse.json"),
    );
    tx.next = tx.plan.settled_source(&tx.old, &tx.inverse, true).unwrap();
    c.install(&mut tx);
    tx.record["state"] = json!("ROLLING_BACK");
    durable::json(&c.f.root.join("firewall/transaction.json"), &tx.record).unwrap();
    let pointer = BoundFile::open(&c.f.root.join("firewall/confirmed.json"), LIMIT)
        .unwrap()
        .marker()
        .unwrap();
    let engine = crate::firewall::Firewall::open(c.f.root.clone(), None)
        .unwrap()
        .enable_writes(true);
    engine.recover().await.unwrap();
    let view = core_view(&c.f.root).unwrap().unwrap();
    assert_eq!(view["journalSettled"], true);
    assert_eq!(view["transaction"]["state"], "ROLLED_BACK");
    assert_eq!(view["revision"], 1);
    assert!(
        BoundFile::open(&c.f.root.join("firewall/confirmed.json"), LIMIT)
            .unwrap()
            .marker()
            .unwrap()
            == pointer
    );
    assert_eq!(engine.test_backend_invocations(), 0);
    c.unchanged_anchor();
}

#[test]
fn cancellation_before_dispatch_preserves_the_original_source_without_creating_a_current_pointer() {
    let c = Case::new();
    let before = core_view(&c.f.root).unwrap().unwrap();
    let mut tx = c.transaction(&c.current, &c.seed, "history-cancel");
    tx.record["state"] = json!("ROLLED_BACK");
    tx.record["forwardIntent"] = json!(false);
    tx.record["confirmedDecision"] = json!(false);
    tx.record.as_object_mut().unwrap().remove("forward");
    publish(&archive_path(&c.f.root, "history-cancel"), &tx.record);
    durable::json(&c.f.root.join("firewall/transaction.json"), &tx.record).unwrap();
    let after = core_view(&c.f.root).unwrap().unwrap();
    assert_eq!(after["revision"], before["revision"]);
    assert_eq!(after["sourceDigest"], before["sourceDigest"]);
    assert_eq!(after["candidate"], before["candidate"]);
    assert_eq!(after["journalSettled"], true);
    assert!(!c.f.root.join("firewall/confirmed.json").exists());
    let active = c.f.root.join("firewall/transaction.json");
    fs::rename(&active, active.with_extension("retained")).unwrap();
    assert_eq!(core_view(&c.f.root).unwrap().unwrap()["sourceDigest"], before["sourceDigest"]);
    c.unchanged_anchor();
}

#[tokio::test]
async fn orphan_plan_artifacts_block_new_ids_other_writers_and_boot_without_recreating_a_journal() {
    let c = Case::new();
    let before = core_view(&c.f.root).unwrap().unwrap();
    let _tx = c.transaction(&c.current, &c.seed, "history-orphan-plan");
    for name in ["forward.json", "inverse.json"] {
        let path = artifact_path(&c.f.root, "history-orphan-plan", name);
        fs::rename(&path, path.with_extension("retained")).unwrap();
    }
    let plan = artifact_path(&c.f.root, "history-orphan-plan", "plan.json");
    let original = BoundFile::open(&plan, LIMIT).unwrap().marker().unwrap();
    assert!(core_view(&c.f.root).unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN:"));
    assert!(preview_update(&c.f.root,json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":1,"sourceDigest":before["sourceDigest"],"candidate":before["candidate"],"destinationPrefixes":{"ipv4":[24],"ipv6":[64]}})).unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN:"));
    match crate::system_change::Guard::acquire(&c.f.root, crate::system_change::Subsystem::Network) {
        Err(error) => assert!(error.to_string().starts_with("OUTCOME_UNKNOWN:")),
        Ok(_) => panic!("orphan imported work must block other system writers"),
    }
    let engine = crate::firewall::Firewall::open(c.f.root.clone(), None).unwrap().enable_writes(true);
    assert!(engine.recover().await.unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN:"));
    assert_eq!(engine.test_backend_invocations(), 0);
    assert!(!c.f.root.join("firewall/transaction.json").exists());
    assert!(!c.f.root.join("firewall/confirmed.json").exists());
    assert!(BoundFile::open(&plan, LIMIT).unwrap().marker().unwrap() == original);
    c.unchanged_anchor();
}

#[tokio::test]
async fn losing_both_mutable_markers_never_hides_acknowledged_current_history() {
    let c = Case::new();
    let mut tx = c.transaction(&c.current, &c.seed, "history-lost-markers");
    c.install(&mut tx);
    for name in ["confirmed.json", "transaction.json"] {
        let path = c.f.root.join("firewall").join(name);
        fs::rename(&path, path.with_extension("retained")).unwrap();
    }
    assert!(confirmed_source(&c.f.root, None).unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN:"));
    let engine = crate::firewall::Firewall::open(c.f.root.clone(), None).unwrap().enable_writes(true);
    assert!(engine.recover().await.is_err());
    assert_eq!(engine.test_backend_invocations(), 0);
    assert!(archive_path(&c.f.root, "history-lost-markers").exists());
    assert!(!c.f.root.join("firewall/confirmed.json").exists());
    c.unchanged_anchor();
}

#[test]
fn an_older_valid_pointer_cannot_hide_a_later_orphan_plan_or_unreachable_physical_outcome() {
    let c = Case::new();
    let mut first = c.transaction(&c.current, &c.seed, "history-old-pointer");
    c.install(&mut first);
    let mut second = c.transaction(&first.next, &first.head, "history-new-orphan");
    assert!(core_view(&c.f.root).unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN:"));
    c.install(&mut second);
    assert_eq!(core_view(&c.f.root).unwrap().unwrap()["revision"], 3);
    c.pointer(&first.head, &first.next);
    let active = c.f.root.join("firewall/transaction.json");
    fs::rename(&active, active.with_extension("retained")).unwrap();
    assert!(core_view(&c.f.root).unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN:"));
    c.unchanged_anchor();
}

#[test]
fn retained_settled_history_from_another_initialization_is_audit_only_and_never_adopted() {
    let c = Case::new();
    let before = core_view(&c.f.root).unwrap().unwrap();
    let old_anchor = "d".repeat(64);
    let old = CurrentSource::from_acknowledged(&old_anchor, 1, before["candidate"].clone(),
        BTreeMap::from([("ipv4".into(), vec![24]), ("ipv6".into(), vec![64])]),
        c.f.baseline.native_transfer.as_ref().unwrap(), &c.f.current, false).unwrap();
    let old_seed = json!({"kind":"INITIALIZATION","receiptSha256":old_anchor});
    let mut tx = c.transaction(&old, &old_seed, "history-retained-epoch");
    tx.record["initializationReceiptSha256"] = json!(old_anchor);
    let path = archive_path(&c.f.root, "history-retained-epoch");
    publish(&path, &tx.record);
    let bytes = fs::read(&path).unwrap();
    let after = core_view(&c.f.root).unwrap().unwrap();
    assert_eq!(after["revision"], 1);
    assert_eq!(after["sourceDigest"], before["sourceDigest"]);
    assert_eq!(after["candidate"], before["candidate"]);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    // This is an epoch inventory contract, not owner retirement/readoption acceptance.
    c.unchanged_anchor();
}

#[test]
fn active_record_anchor_and_unknown_history_backend_cannot_be_relabelled_as_current_authority() {
    let c = Case::new();
    let mut tx = c.transaction(&c.current, &c.seed, "history-wrong-epoch");
    tx.record["initializationReceiptSha256"] = json!("e".repeat(64));
    c.install(&mut tx);
    assert!(core_view(&c.f.root).is_err());
    tx.record["backend"] = json!("nft.unknown.v99");
    durable::json(&archive_path(&c.f.root, "history-wrong-epoch"), &tx.record).unwrap();
    assert!(core_view(&c.f.root).is_err());
    c.unchanged_anchor();
}

#[test]
fn symlinked_artifact_directories_and_private_confirmed_formats_are_not_imported_history() {
    let c = Case::new();
    let mut tx = c.transaction(&c.current, &c.seed, "history-link");
    c.install(&mut tx);
    let directory = artifact_path(&c.f.root, "history-link", "plan.json")
        .parent()
        .unwrap()
        .to_path_buf();
    let retained = directory.with_extension("retained");
    fs::rename(&directory, &retained).unwrap();
    std::os::unix::fs::symlink(&retained, &directory).unwrap();
    assert!(core_view(&c.f.root).is_err());
    c.unchanged_anchor();
    let other = Case::new();
    durable::json(
        &other.f.root.join("firewall/confirmed.json"),
        &json!({"revision":1,"text":"private","candidate":null}),
    )
    .unwrap();
    assert!(core_view(&other.f.root).is_err());
    other.unchanged_anchor();
}
