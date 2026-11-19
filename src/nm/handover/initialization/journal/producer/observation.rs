//! SAME-domain source observations have no native sender and no confirmation path.
use super::*;
use crate::nm::coordinator::imported::Observed;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::nm) struct Review {
    pub(in crate::nm) operation_id: uuid::Uuid,
    expected_revision: u64,
    source_digest: String,
}
impl Review {
    fn require(&self, snapshot: &Snapshot, proof: &Observed) -> Result<()> {
        proof.require(snapshot)?;
        ensure!(
            self.operation_id == proof.plan().operation()
                && self.expected_revision == snapshot.revision
                && self.source_digest == snapshot.source,
            "CONFLICT: stale imported source observation review"
        );
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::nm) struct Change {
    owner_key: String,
    pub(in crate::nm) operation_id: uuid::Uuid,
    expected_revision: u64,
    source_digest: String,
    cohort_digest: String,
    observed_native_sha256: String,
}
impl Change {
    fn owner(&self) -> Result<String> {
        ensure!(
            hex(&self.owner_key, 64),
            "INVALID_ARGUMENT: source observation owner key"
        );
        Ok(durable::hash(self.owner_key.as_bytes()))
    }
    fn input(&self) -> Result<String> {
        Ok(durable::hash(&serde_json::to_vec(self)?))
    }
    fn review(&self) -> Review {
        Review {
            operation_id: self.operation_id,
            expected_revision: self.expected_revision,
            source_digest: self.source_digest.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Outcome {
    original_request_id: String,
    change: Change,
}

pub(in crate::nm) fn review(snapshot: &Snapshot, input: Review, proof: &Observed) -> Result<Value> {
    input.require(snapshot, proof)?;
    Ok(
        json!({"schemaVersion":1,"backend":BACKEND,"kind":"SOURCE_OBSERVATION",
        "revision":snapshot.revision,"sourceDigest":snapshot.source,"cohortDigest":proof.cohort(),
        "nativePlan":proof.plan().parameters()?,"kernelEffect":false,"requiresConfirmation":false,
        "dispatchEnabled":false,"ownerGrant":false}),
    )
}

fn receipt(record: &Record, historical: bool) -> Result<Value> {
    record.validate()?;
    ensure!(
        record.kind == Some(Kind::SourceObservation),
        "CONFLICT: original source observation required"
    );
    let mut value = record.projection();
    value["backend"] = json!(BACKEND);
    value["historical"] = json!(historical);
    value["requiresConfirmation"] = json!(false);
    value["dispatchEnabled"] = json!(false);
    Ok(value)
}

/// Metadata-only settlement of the original captured observation. After an
/// attempted publication,missing history is UNKNOWN forever,never reconstructed.
fn finish(root: &Path, record: &Record) -> Result<Value> {
    let original = super::super::super::original(root)?
        .context("OUTCOME_UNKNOWN: source observation initialization unavailable")?;
    let active_path = root.join("firewall/transaction.json");
    let active = BoundFile::open(&active_path, RECORD_BYTES as u64)?;
    ensure!(
        serde_json::from_slice::<Record>(&active.bytes)? == *record,
        "CONFLICT: original observation active marker changed"
    );
    let mut reachable = BTreeSet::new();
    let parent = resolve(
        root,
        &original.document,
        &original.origin,
        &original.source,
        &record.base,
        &mut reachable,
    )?;
    let plan = record.checked_observation(root, &parent, &original.source)?;
    let pointer_path = root.join("firewall/confirmed.json");
    let pointer = if present(&pointer_path)? {
        Some(BoundFile::open(&pointer_path, LIMIT)?)
    } else {
        None
    };
    let current_head = if let Some(file) = &pointer {
        let confirmed: Confirmed = serde_json::from_slice(&file.bytes)?;
        confirmed.require_head_kind()?;
        let current = resolve(
            root,
            &original.document,
            &original.origin,
            &original.source,
            &confirmed.head,
            &mut reachable,
        )?;
        let witness = current.witness()?;
        ensure!(
            witness["revision"]
                .as_str()
                .and_then(|v| v.parse::<u64>().ok())
                == Some(confirmed.revision)
                && witness["sourceDigest"] == confirmed.source_digest,
            "CONFLICT: observation pointer differs from history"
        );
        ensure!(
            confirmed.head == record.base
                || matches!(&confirmed.head,Head::Transaction{uid,request_id,..} if *uid==record.uid && *request_id==record.request_id),
            "CONFLICT: original observation cannot rewind another current head"
        );
        file.verify_binding()?;
        Some(confirmed.head)
    } else {
        None
    };
    // A missing pointer may be repaired only for this original active operation;
    // any other unreachable physical history or orphan still blocks it.
    Inventory::read(root)?.reconcile(
        &record.initialization_receipt_sha256,
        &reachable,
        Some(record),
    )?;
    active.verify_binding()?;
    let mut terminal = record.clone();
    terminal.state = State::Observed;
    terminal.settlement_intent = true;
    let path = history(root, record.uid, &record.request_id);
    if present(&path)? {
        ensure!(
            record.settlement_intent,
            "CONFLICT: observation history has no original publication intent"
        );
        let file = BoundFile::open(&path, RECORD_BYTES as u64)?;
        ensure!(
            serde_json::from_slice::<Record>(&file.bytes)? == terminal,
            "CONFLICT: source observation differs from immutable original history"
        );
        file.verify_binding()?;
    } else {
        ensure!(
            record.state == State::Observing && !record.settlement_intent,
            "OUTCOME_UNKNOWN: original observation publication attempted;never reconstruct"
        );
        let mut deciding = record.clone();
        deciding.settlement_intent = true;
        durable::json(&root.join("firewall/transaction.json"), &deciding).context(
            "OUTCOME_UNKNOWN: original observation publication intent;query original only",
        )?;
        publish(root, &terminal)
            .context("OUTCOME_UNKNOWN: original observation publication;query original only")?;
    }
    let current = plan.settled_source(&parent)?;
    let witness = current.witness()?;
    let head = Head::Transaction {
        uid: record.uid,
        request_id: record.request_id.clone(),
        reference: Reference::observe(root, &path)?,
    };
    if current_head
        .as_ref()
        .is_none_or(|head| head == &record.base)
    {
        if let Some(file) = &pointer {
            file.verify_binding()?;
        }
        let pointer = Confirmed {
            backend: Backend::Imported,
            schema_version: 1,
            head,
            revision: witness["revision"]
                .as_str()
                .context("CONFLICT: observed revision")?
                .parse()?,
            source_digest: witness["sourceDigest"]
                .as_str()
                .context("CONFLICT: observed physical source")?
                .into(),
        };
        durable::json(&root.join("firewall/confirmed.json"), &pointer).context(
            "OUTCOME_UNKNOWN: original observation pointer publication;query original only",
        )?;
    } else {
        ensure!(
            current_head.as_ref() == Some(&head),
            "CONFLICT: original observation cannot rewind a different current head"
        );
    }
    durable::json(&root.join("firewall/transaction.json"), &terminal)
        .context("OUTCOME_UNKNOWN: original observation final marker;query original only")?;
    original.file.verify_binding()?;
    receipt(&terminal, false)
}

/// The caller holds EX after rechecking a fresh typed Observed capability.
pub(in crate::nm) fn prepare(
    root: &Path,
    snapshot: &Snapshot,
    input: Change,
    uid: u32,
    request_id: &str,
    proof: &Observed,
) -> Result<Value> {
    let record = begin(root, snapshot, input, uid, request_id, proof)?;
    finish(root, &record)
        .context("OUTCOME_UNKNOWN: original source observation settlement;query original only")
}
pub(in crate::nm) fn prepare_remote(root:&Path,snapshot:&Snapshot,input:Change,
    principal:&principal::RemotePrincipal,proof:&Observed)->Result<Value> {
    principal.require_input(&serde_json::to_value(&input)?)?;
    let record=begin_owned(root,snapshot,input,principal::Preparation::remote(principal)?,proof)?;
    finish(root,&record).context("OUTCOME_UNKNOWN: original source observation settlement;query original only")
}

/// A fresh storage fault model stops before the first publication attempt.
#[cfg(test)]
pub(in crate::nm) fn stage_fixture(
    root: &Path,
    snapshot: &Snapshot,
    input: Change,
    uid: u32,
    request_id: &str,
    proof: &Observed,
) -> Result<Value> {
    receipt(
        &begin(root, snapshot, input, uid, request_id, proof)?,
        false,
    )
}

fn begin(
    root: &Path,
    snapshot: &Snapshot,
    input: Change,
    uid: u32,
    request_id: &str,
    proof: &Observed,
) -> Result<Record> {
    begin_owned(root,snapshot,input,principal::Preparation::local(uid,request_id)?,proof)
}
fn begin_owned(root:&Path,snapshot:&Snapshot,input:Change,principal:principal::Preparation<'_>,proof:&Observed)->Result<Record> {
    let principal::Preparation {uid,request_id,origin}=principal;
    input.review().require(snapshot, proof)?;
    snapshot.require_current(root)?;
    ensure!(
        hex(&input.cohort_digest, 64)
            && input.cohort_digest == proof.cohort()
            && proof.plan().parameters()?["observedNativeSha256"] == input.observed_native_sha256,
        "CONFLICT: reviewed observation native source/network cohort changed"
    );
    let inventory = Inventory::read(root)?;
    ensure!(
        snapshot.depth < MAX_HISTORY && inventory.entries + 2 <= MAX_HISTORY * 3,
        "RESOURCE_EXHAUSTED: source observation history headroom"
    );
    let path = history(root, uid, request_id);
    let directory_path = root
        .join("firewall/kura-history")
        .join(format!("{}.artifacts", key(uid, request_id)));
    ensure!(
        !present(&path)?
            && !present(&directory_path)?
            && inventory
                .records
                .values()
                .all(|record| record.id != input.operation_id),
        "OUTCOME_UNKNOWN: original imported work exists;never create another observation"
    );
    let bytes = serde_json::to_vec(proof.plan())?;
    ensure!(
        bytes.len() <= LIMIT as usize,
        "RESOURCE_EXHAUSTED: source observation artifact"
    );
    let fake = Directory {
        device: u64::MAX,
        inode: u64::MAX,
    };
    let reference = Reference {
        file: MarkerIdentity {
            device: u64::MAX,
            inode: u64::MAX,
            sha256: durable::hash(&bytes),
        },
        firewall: fake.clone(),
        history: fake.clone(),
        parent: fake,
    };
    let owner=proof.recorded_owner(snapshot)?;
    let mut record = Record {
        forward_command:None,inverse_command:None,confirmation_command:None,cancellation_command:None,
        backend: Backend::Imported,
        schema_version: if origin.is_some() {5} else if owner.is_stopped() {4} else {3},
        origin,
        kind: Some(Kind::SourceObservation),
        expiry: None,
        id: input.operation_id,
        uid,
        request_id: request_id.into(),
        owner_sha256: input.owner()?,
        input_sha256: input.input()?,
        initialization_receipt_sha256: snapshot.original["initializationReceiptSha256"]
            .as_str()
            .unwrap()
            .into(),
        state: State::Observing,
        deadline_ms: now_ms()
            .checked_add(60_000)
            .context("RESOURCE_EXHAUSTED: observation deadline")?,
        base: snapshot.head.clone(),
        plan: reference,
        forward_intent: false,
        inverse_intent: false,
        confirmed_decision: false,
        forward: None,
        inverse: None,
        forward_dispatch: None,
        inverse_dispatch: None,
        negative: None,
        forward_capture_intent: false,
        inverse_capture_intent: false,
        negative_capture_intent: false,
        settlement_intent: false,
        authorization: Some(Authorization {
            token: uuid::Uuid::new_v4().simple().to_string(),
            delegation: proof.binding().clone(),
            owner,
            network_cohort_sha256: proof.cohort().into(),
            source_stamp: snapshot.stamp.clone(),
            runtime_sha256: proof.runtime_hash().into(),
        }),
    };
    let mut terminal = record.clone();
    terminal.state = State::Observed;
    terminal.settlement_intent = true;
    bounded(&record)?;
    ensure!(
        bounded(&terminal)?.len() <= RECORD_BYTES - 1024,
        "RESOURCE_EXHAUSTED: observation record headroom"
    );
    proof.require(snapshot)?;
    durable::directory(&root.join("firewall/kura-history"))
        .context("OUTCOME_UNKNOWN: source observation history directory;preserve original work")?;
    durable::directory(&directory_path)
        .context("OUTCOME_UNKNOWN: original observation artifact directory;query original only")?;
    let plan_path = directory_path.join("plan.json");
    durable::publish_new(&plan_path, &bytes, FileMetadata::private()).context(
        "OUTCOME_UNKNOWN: original observation artifact publication;query original only",
    )?;
    record.plan = Reference::observe(root, &plan_path)?;
    record.checked_observation(root, &snapshot.current, &snapshot.original)?;
    durable::json(&root.join("firewall/transaction.json"), &record)
        .context("OUTCOME_UNKNOWN: original observation intent publication;query original only")?;
    Ok(record)
}

pub(crate) fn outcome(root: &Path, uid: u32, input: Outcome) -> Result<Value> {
    principal::original_request(uid, &input.original_request_id)?;
    let path = history(root, uid, &input.original_request_id);
    let historical = present(&path)?;
    let active_path = root.join("firewall/transaction.json");
    let file = BoundFile::open(
        if historical { &path } else { &active_path },
        RECORD_BYTES as u64,
    )
    .context("OUTCOME_UNKNOWN: original source observation unavailable")?;
    let record: Record = serde_json::from_slice(&file.bytes)?;
    record.validate()?;
    ensure!(
        record.kind == Some(Kind::SourceObservation)
            && record.uid == uid
            && record.request_id == input.original_request_id
            && record.owner_sha256 == input.change.owner()?,
        "FORBIDDEN: original source observation owner"
    );
    ensure!(
        record.input_sha256 == input.change.input()?,
        "CONFLICT: original source observation input changed"
    );
    file.verify_binding()?;
    if historical {
        ensure!(
            record.state == State::Observed,
            "CONFLICT: immutable observation outcome is not settled"
        );
        let active_path = root.join("firewall/transaction.json");
        if present(&active_path)? {
            let active_file = BoundFile::open(&active_path, RECORD_BYTES as u64)?;
            let active: Record = serde_json::from_slice(&active_file.bytes)?;
            active.validate()?;
            active_file.verify_binding()?;
            if active.uid == uid && active.request_id == input.original_request_id {
                let already_current = if let Some(original) =
                    super::super::super::original(root).ok().flatten()
                {
                    read(root, &original.document, &original.origin, &original.source)
                        .ok()
                        .flatten()
                        .is_some_and(|view| {
                            view.settled
                                && matches!(&view.head,Head::Transaction{uid:owner,request_id,..}
                            if *owner==uid && *request_id==input.original_request_id)
                        })
                } else {
                    false
                };
                if !already_current {
                    return finish(root,&active)
                    .context("OUTCOME_UNKNOWN: original observation metadata repair unavailable;preserve original work");
                }
            }
        }
        return receipt(&record, true);
    }
    finish(root, &record).context(
        "OUTCOME_UNKNOWN: original observation metadata unavailable;preserve original work",
    )
}
