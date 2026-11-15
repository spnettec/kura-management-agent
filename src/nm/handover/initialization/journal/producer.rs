//! Create-only ordinary proposals in the SAME firewall transaction/history.
//! Preparation and pre-dispatch cancellation never dispatch a kernel batch.
use super::*;
use crate::nm::coordinator::imported::Verified;

pub(in crate::nm) mod execution;
pub(in crate::nm) mod authority;
pub(in crate::nm) mod expiry;
  pub(crate) mod principal;
use authority::OwnerAuthority;
pub(crate) mod observation;
const RECORD_BYTES: usize = 16_384;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Authorization {
    token: String,
    delegation: Binding,
    owner: OwnerAuthority,
    network_cohort_sha256: String,
    source_stamp: String,
    runtime_sha256: String,
}
impl Authorization {
    pub(super) fn stopped_authority(&self)->bool { self.owner.is_stopped() }
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            hex(&self.token, 32)
                && hex(&self.network_cohort_sha256, 64)
                && hex(&self.source_stamp, 64)
                && hex(&self.runtime_sha256, 64)
                && !self.delegation.operation_id.is_nil()
                && hex(&self.delegation.plan_sha256, 64)
                && hex(&self.delegation.lease_sha256, 64),
            "CONFLICT: imported proposal authorization shape"
        );
        self.owner.require_complete()?;
        self.owner.require_runtime(&self.runtime_sha256)?;
        self.owner.require_original(
            self.delegation.operation_id,
            &self.delegation.plan_sha256,
            self.owner.mirror_hash(),
            self.owner.role_configuration(),
        )
    }
    pub(super) fn require_source(
        &self,
        root: &Path,
        head: &Head,
        current: &CurrentSource,
        original: &Value,
    ) -> Result<()> {
        let (revision, source) = identity(head, current, original)?;
        self.owner.require_firewall(revision, &source)?;
        ensure!(
            original["operationId"] == json!(self.delegation.operation_id)
                && original["planSha256"] == self.delegation.plan_sha256
                && self.source_stamp == stamp(root, head, current, original)?,
            "CONFLICT: proposal authorization differs from the original/current source"
        );
        Ok(())
    }
}

fn identity(head: &Head, current: &CurrentSource, original: &Value) -> Result<(u64, String)> {
    let witness = current.witness()?;
    let revision = witness["revision"]
        .as_str()
        .context("CONFLICT: current revision")?
        .parse()?;
    let source = if matches!(head, Head::Initialization { .. }) {
        &original["sourceDigest"]
    } else {
        &witness["sourceDigest"]
    };
    Ok((
        revision,
        source.as_str().context("CONFLICT: current source")?.into(),
    ))
}
fn stamp(root: &Path, head: &Head, current: &CurrentSource, original: &Value) -> Result<String> {
    let file = BoundFile::open(&root.join(POLICY), LIMIT)?;
    let (revision, source) = identity(head, current, original)?;
    digest(
        &json!({"initialization":file.marker()?,"head":head,"revision":revision,
        "sourceDigest":source,"physicalSource":current.witness()?}),
    )
}

pub(in crate::nm) struct Snapshot {
    current: CurrentSource,
    head: Head,
    original: Value,
    revision: u64,
    source: String,
    stamp: String,
    depth: usize,
    pending: Option<MarkerIdentity>,
    physical: Option<CurrentSource>,
}
impl Snapshot {
    pub(in crate::nm) fn take(root: &Path) -> Result<Self> {
        let original = super::super::original(root)?
            .context("UNSUPPORTED: imported initialization required")?;
        let (current, head, depth) = if let Some(view) =
            read(root, &original.document, &original.origin, &original.source)?
        {
            ensure!(
                view.settled,
                "OUTCOME_UNKNOWN: query the original imported transaction before a new proposal"
            );
            (view.current, view.head, view.history_depth)
        } else {
            (
                initial(&original.document, &original.origin, &original.source)?,
                Head::Initialization {
                    receipt_sha256: original.source["initializationReceiptSha256"]
                        .as_str()
                        .unwrap()
                        .into(),
                },
                0,
            )
        };
        let (revision, source) = identity(&head, &current, &original.source)?;
        let stamp = stamp(root, &head, &current, &original.source)?;
        original.file.verify_binding()?;
        Ok(Self {
            current,
            head,
            original: original.source,
            revision,
            source,
            stamp,
            depth,
            pending: None,
            physical: None,
        })
    }
    /// A pending ticket is derived from the SAME checked parent/history/plan.
    /// It never turns persisted proposal authorization into fresh authority.
    pub(in crate::nm) fn pending(root: &Path, uid: u32, action: &Cancel) -> Result<Self> {
        let record = owned(root, uid, action)?;
        Self::pending_record(root,record)
    }
    fn pending_record(root:&Path,record:Record)->Result<Self> {
        let original = super::super::original(root)?
            .context("OUTCOME_UNKNOWN: original imported initialization missing")?;
        let view = read(root, &original.document, &original.origin, &original.source)?
            .context("OUTCOME_UNKNOWN: original pending transaction missing")?;
        ensure!(
            !view.settled && view.head == record.base,
            "OUTCOME_UNKNOWN: pending source has already been decided;query original only"
        );
        let plan = record.checked_plan(root, &view.current, &original.source)?;
        let physical = record
            .forward
            .as_ref()
            .map(|reference| -> Result<CurrentSource> {
                let kernel: Value = serde_json::from_slice(
                    &reference.read(root, &record.path(root, "forward.json"))?,
                )?;
                plan.settled_source(&view.current, &kernel, false)
            })
            .transpose()?;
        let (revision, source) = identity(&view.head, &view.current, &original.source)?;
        let stamp = stamp(root, &view.head, &view.current, &original.source)?;
        let file = BoundFile::open(&root.join("firewall/transaction.json"), LIMIT)?;
        ensure!(
            serde_json::from_slice::<Record>(&file.bytes)? == record,
            "CONFLICT: original pending record changed"
        );
        original.file.verify_binding()?;
        file.verify_binding()?;
        Ok(Self {
            current: view.current,
            head: view.head,
            original: original.source,
            revision,
            source,
            stamp,
            depth: view.history_depth,
            pending: Some(file.marker()?),
            physical,
        })
    }
    pub(in crate::nm) fn require_current(&self, root: &Path) -> Result<()> {
        if let Some(marker) = &self.pending {
            let file = BoundFile::open(&root.join("firewall/transaction.json"), LIMIT)?;
            ensure!(
                &file.marker()? == marker,
                "CONFLICT: pending imported ticket changed"
            );
            let original = super::super::original(root)?
                .context("OUTCOME_UNKNOWN: original initialization missing")?;
            let view = read(root, &original.document, &original.origin, &original.source)?
                .context("OUTCOME_UNKNOWN: original pending transaction missing")?;
            ensure!(
                !view.settled
                    && view.head == self.head
                    && stamp(root, &view.head, &view.current, &original.source)? == self.stamp,
                "CONFLICT: pending imported parent changed"
            );
            file.verify_binding()?;
            original.file.verify_binding()?;
        } else {
            ensure!(
                Self::take(root)?.stamp == self.stamp,
                "CONFLICT: reviewed imported source changed"
            );
        }
        Ok(())
    }
    pub(in crate::nm) fn require_native(&self, kernel: &Value) -> Result<()> {
        self.physical
            .as_ref()
            .unwrap_or(&self.current)
            .require_native(kernel)
    }
    pub(in crate::nm) fn require_native_epoch(&self, epoch: &native::epoch::Epoch) -> Result<()> {
        self.physical.as_ref().unwrap_or(&self.current).require_epoch(epoch)
    }
    pub(in crate::nm) fn observation_plan(&self, id: uuid::Uuid, epoch: &native::epoch::Epoch,
        kernel: &Value) -> Result<native::lineage::ObservationPlan> {
        ensure!(self.pending.is_none() && self.physical.is_none(),
            "OUTCOME_UNKNOWN: pending imported work cannot create a source observation");
        self.current.observe_source(id, epoch, kernel)
    }
    pub(in crate::nm) fn require_observation(&self, plan: &native::lineage::ObservationPlan) -> Result<()> {
        ensure!(self.pending.is_none() && self.physical.is_none(),
            "OUTCOME_UNKNOWN: source observation requires a settled original source");
        plan.settled_source(&self.current)?;
        Ok(())
    }
    /// Reject an issued/expired action before collecting reverse Core witnesses.
    pub(in crate::nm) fn admit_action(&self, root: &Path, method: &str) -> Result<()> {
        self.require_current(root)?;
        let record = active(root)?;
        let admissible = match method {
            "firewall.kura.imported.apply" => {
                record.state == State::Prepared
                    && !record.forward_intent
                    && now_ms() < record.deadline_ms
            }
            "firewall.kura.imported.confirm" => {
                record.state == State::WaitConfirm
                    && !record.inverse_intent
                    && now_ms() < record.deadline_ms
            }
            "firewall.kura.imported.rollback" => {
                record.state == State::WaitConfirm && !record.inverse_intent
            }
            _ => false,
        };
        ensure!(
            admissible,
            "OUTCOME_UNKNOWN: original action issued,decided or expired;query original only"
        );
        Ok(())
    }
    pub(in crate::nm) fn forwarding_families(
        &self,
        root: &Path,
        inverse: bool,
    ) -> Result<(bool, bool)> {
        let value = if inverse {
            self.current.witness()?["currentPolicy"].clone()
        } else {
            let record = active(root)?;
            serde_json::to_value(record.checked_plan(root,&self.current,&self.original)?)?["candidate"].clone()
        };
        crate::firewall::original_forwarding_families(&value)
    }
    pub(in crate::nm) fn revision(&self) -> u64 {
        self.revision
    }
    pub(in crate::nm) fn source(&self) -> &str {
        &self.source
    }
    pub(in crate::nm) fn stamp(&self) -> &str {
        &self.stamp
    }
    pub(in crate::nm) fn require_original(&self, binding: &Binding) -> Result<()> {
        ensure!(
            self.original["operationId"] == json!(binding.operation_id)
                && self.original["planSha256"] == binding.plan_sha256,
            "CONFLICT: current policy belongs to another original ownership plan"
        );
        Ok(())
    }
    fn plan(&self, input: &Review) -> Result<UpdatePlan> {
        ensure!(
            input.expected_revision == self.revision && input.source_digest == self.source,
            "CONFLICT: stale imported review"
        );
        self.current.plan(
            input.operation_id,
            input.candidate.clone(),
            input.destination_prefixes.clone(),
        )
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::nm) struct Review {
    operation_id: uuid::Uuid,
    expected_revision: u64,
    source_digest: String,
    candidate: Value,
    destination_prefixes: BTreeMap<String, Vec<u8>>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::nm) struct Change {
    owner_key: String,
    operation_id: uuid::Uuid,
    expected_revision: u64,
    source_digest: String,
    cohort_digest: String,
    confirm_seconds: u64,
    candidate: Value,
    destination_prefixes: BTreeMap<String, Vec<u8>>,
}
impl Change {
    fn review(&self) -> Review {
        Review {
            operation_id: self.operation_id,
            expected_revision: self.expected_revision,
            source_digest: self.source_digest.clone(),
            candidate: self.candidate.clone(),
            destination_prefixes: self.destination_prefixes.clone(),
        }
    }
    fn owner(&self) -> Result<String> {
        ensure!(
            hex(&self.owner_key, 64),
            "INVALID_ARGUMENT: imported owner key"
        );
        Ok(durable::hash(self.owner_key.as_bytes()))
    }
    fn input(&self) -> Result<String> {
        Ok(durable::hash(&serde_json::to_vec(self)?))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Outcome {
    original_request_id: String,
    change: Change,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Cancel {
    original_request_id: String,
    owner_key: String,
    id: uuid::Uuid,
    confirmation_token: String,
}

pub(in crate::nm) fn review(snapshot: &Snapshot, input: Review, proof: &Verified) -> Result<Value> {
    proof.require(snapshot)?;
    let plan = snapshot.plan(&input)?;
    Ok(
        json!({"schemaVersion":1,"backend":BACKEND,"revision":snapshot.revision,
        "sourceDigest":snapshot.source,"cohortDigest":proof.cohort(),"nativePlan":plan.parameters()?,
        "writeEnabled":false,"dispatchEnabled":false,"ownerGrant":false}),
    )
}
fn bounded(record: &Record) -> Result<Vec<u8>> {
    record.validate()?;
    let bytes = serde_json::to_vec(record)?;
    ensure!(
        bytes.len() <= RECORD_BYTES,
        "RESOURCE_EXHAUSTED: imported transaction record"
    );
    Ok(bytes)
}
fn publish(root: &Path, record: &Record) -> Result<()> {
    durable::publish_new(
        &history(root, record.uid, &record.request_id),
        &bounded(record)?,
        FileMetadata::private(),
    )
}
fn receipt(record: &Record, historical: bool) -> Result<Value> {
    let authorization = record
        .authorization
        .as_ref()
        .context("UNSUPPORTED: historical metadata has no ordinary proposal grant")?;
    let mut value = record.projection();
    value["backend"] = json!(BACKEND);
    value["deadlineUnixMs"] = json!(record.deadline_ms);
    value["confirmationToken"] = json!(authorization.token);
    value["historical"] = json!(historical);
    value["dispatchEnabled"] = json!(false);
    Ok(value)
}

/// Requires the caller's system EX guard and freshly collected real authority.
pub(in crate::nm) fn prepare(
    root: &Path,
    snapshot: &Snapshot,
    input: Change,
    uid: u32,
    request_id: &str,
    proof: &Verified,
) -> Result<Value> {
    prepare_owned(root,snapshot,input,principal::Preparation::local(uid,request_id)?,proof)
}
pub(in crate::nm) fn prepare_remote(
    root:&Path,snapshot:&Snapshot,input:Change,principal:&principal::RemotePrincipal,proof:&Verified,
)->Result<Value> {
    principal.require_input(&serde_json::to_value(&input)?)?;
    prepare_owned(root,snapshot,input,principal::Preparation::remote(principal)?,proof)
}
fn prepare_owned(root:&Path,snapshot:&Snapshot,input:Change,principal:principal::Preparation<'_>,proof:&Verified)->Result<Value> {
    let principal::Preparation {uid,request_id,origin}=principal;
    proof.require(snapshot)?;
    snapshot.require_current(root)?;
    ensure!(
        hex(&input.cohort_digest, 64) && input.cohort_digest == proof.cohort(),
        "CONFLICT: reviewed network cohort changed"
    );
    ensure!(
        (30..=300).contains(&input.confirm_seconds),
        "INVALID_ARGUMENT: imported confirmation window"
    );
    let inventory = Inventory::read(root)?;
    ensure!(
        snapshot.depth < MAX_HISTORY && inventory.entries + 2 <= MAX_HISTORY * 3,
        "RESOURCE_EXHAUSTED: imported history headroom"
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
        "OUTCOME_UNKNOWN: query original imported work;never prepare again"
    );
    let plan = snapshot.plan(&input.review())?;
    let bytes = serde_json::to_vec(&plan)?;
    ensure!(
        bytes.len() <= LIMIT as usize,
        "RESOURCE_EXHAUSTED: imported plan artifact"
    );
    let deadline_ms = now_ms()
        .checked_add(input.confirm_seconds * 1000)
        .context("RESOURCE_EXHAUSTED: imported deadline")?;
    let fake_directory = Directory {
        device: u64::MAX,
        inode: u64::MAX,
    };
    let reference = Reference {
        file: MarkerIdentity {
            device: u64::MAX,
            inode: u64::MAX,
            sha256: durable::hash(&bytes),
        },
        firewall: fake_directory.clone(),
        history: fake_directory.clone(),
        parent: fake_directory,
    };
    let owner = proof.recorded_owner(snapshot)?;
    let mut record = Record {
        forward_command:None,inverse_command:None,confirmation_command:None,cancellation_command:None,
        backend: Backend::Imported,
        schema_version: if origin.is_some() {5} else if owner.is_stopped() {4} else {2},
        origin,
        kind: None,
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
        state: State::Prepared,
        deadline_ms,
        base: snapshot.head.clone(),
        plan: reference.clone(),
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
    // Reserve room for both ACK references before even publishing a proposal.
    let mut terminal = record.clone();
    terminal.schema_version = terminal.schema_version.max(4);
    terminal.state = State::RolledBack;
    terminal.forward_intent = true;
    terminal.inverse_intent = true;
    terminal.forward_dispatch = Some(execution::Intent::reserve(
        &record.authorization.as_ref().unwrap().owner,
    )?);
    terminal.inverse_dispatch = Some(execution::Intent::reserve(
        &record.authorization.as_ref().unwrap().owner,
    )?);
    terminal.forward_capture_intent = true;
    terminal.inverse_capture_intent = true;
    terminal.settlement_intent = true;
    terminal.forward = Some(reference.clone());
    terminal.inverse = Some(reference);
    terminal.expiry = Some(expiry::Decision::reserved(record.deadline_ms));
    if let Some(origin)=&record.origin {
        terminal.forward_command=Some(principal::CommandAudit::reserved(origin,41));
        terminal.inverse_command=Some(principal::CommandAudit::reserved(origin,43));
        terminal.expiry=None;
    }
    ensure!(
        bounded(&terminal)?.len() <= RECORD_BYTES - 1024,
        "RESOURCE_EXHAUSTED: imported terminal record headroom"
    );
    proof.require(snapshot)?;
    durable::directory(&root.join("firewall/kura-history"))?;
    durable::directory(&directory_path)?;
    let plan_path = directory_path.join("plan.json");
    durable::publish_new(&plan_path, &bytes, FileMetadata::private())
        .context("OUTCOME_UNKNOWN: imported plan publication unavailable;query original only")?;
    record.plan = Reference::observe(root, &plan_path)?;
    record.checked_plan(root, &snapshot.current, &snapshot.original)?;
    durable::json(&root.join("firewall/transaction.json"), &record).context(
        "OUTCOME_UNKNOWN: imported preparation publication unavailable;query original only",
    )?;
    receipt(&record, false)
}

fn active(root: &Path) -> Result<Record> {
    (|| -> Result<Record> {
        let file = BoundFile::open(&root.join("firewall/transaction.json"), RECORD_BYTES as u64)?;
        let record: Record = serde_json::from_slice(&file.bytes)?;
        record.validate()?;
        file.verify_binding()?;
        ensure!(
            record.authorization.is_some() && record.kind.is_none(),
            "UNSUPPORTED: ordinary proposal record required"
        );
        Ok(record)
    })()
    .context("OUTCOME_UNKNOWN: original imported proposal record unavailable;preserve evidence")
}
pub(crate) fn outcome(root: &Path, uid: u32, input: Outcome) -> Result<Value> {
    principal::original_request(uid, &input.original_request_id)?;
    let path = history(root, uid, &input.original_request_id);
    let historical = present(&path)?;
    let record = if historical {
        let file = BoundFile::open(&path, LIMIT)?;
        let record: Record = serde_json::from_slice(&file.bytes)?;
        record.validate()?;
        file.verify_binding()?;
        ensure!(
            record.state.settled(),
            "CONFLICT: imported immutable outcome is not settled"
        );
        record
    } else {
        active(root)?
    };
    ensure!(
        record.uid == uid
            && record.request_id == input.original_request_id
            && record.owner_sha256 == input.change.owner()?,
        "FORBIDDEN: imported original owner"
    );
    ensure!(
        record.input_sha256 == input.change.input()?,
        "CONFLICT: original imported input differs"
    );
    if !historical {
        let original = super::super::original(root)?
            .context("OUTCOME_UNKNOWN: original imported initialization missing")?;
        read(root, &original.document, &original.origin, &original.source)
            .context("OUTCOME_UNKNOWN: active imported proposal evidence unavailable")?;
    }
    receipt(&record, historical)
}
  /// Called under the SAME OS guard after an authenticated original outcome.
  /// Reads the exact original record; no reconstruction, native send or grant.
  pub(crate) fn original_evidence(root:&Path,uid:u32,receipt:&Value)->Result<Value> {
      let request_id=receipt["requestId"].as_str().context("CONFLICT: original receipt request")?;
      principal::original_request(uid,request_id)?;
      let historical=receipt["historical"].as_bool().context("CONFLICT: original receipt kind")?;
      let path=if historical {history(root,uid,request_id)} else {root.join("firewall/transaction.json")};
      let file=BoundFile::open(&path,RECORD_BYTES as u64)?;
      let record:Record=serde_json::from_slice(&file.bytes)?;
      record.validate()?;
      ensure!(record.uid==uid && record.request_id==request_id && json!(record.id)==receipt["id"]
          && json!(record.state)==receipt["state"] && (!historical||record.state.settled()),
          "CONFLICT: original receipt/record identity");
      file.verify_binding()?;
      Ok(json!(yofc_management_protocol::imported::DecisionEvidence {
          record_sha256:durable::hash(&file.bytes),historical,source_observation:record.kind==Some(Kind::SourceObservation),
          forward_intent:record.forward_intent,forward_acknowledged:record.forward.is_some(),
          inverse_intent:record.inverse_intent,inverse_acknowledged:record.inverse.is_some(),
          negative_acknowledged:record.negative.is_some(),confirmed_decision:record.confirmed_decision,
          commands:record.origin.as_ref().map(|origin|yofc_management_protocol::imported::OriginalCommands {
              original_sha256:origin.command_sha256().into(),
              forward_sha256:record.forward_command.as_ref().map(|v|v.command_sha256().into()),
              inverse_sha256:record.inverse_command.as_ref().map(|v|v.command_sha256().into()),
              confirmation_sha256:record.confirmation_command.as_ref().map(|v|v.command_sha256().into()),
              cancellation_sha256:record.cancellation_command.as_ref().map(|v|v.command_sha256().into()),
              expiry_decision:record.expiry.is_some(),
          }),
      }))
  }
fn owned(root: &Path, uid: u32, input: &Cancel) -> Result<Record> {
    principal::original_request(uid, &input.original_request_id)?;
    let record = active(root)?;
    ensure!(
        hex(&input.owner_key, 64)
            && record.uid == uid
            && record.request_id == input.original_request_id
            && record.id == input.id
            && record.owner_sha256 == durable::hash(input.owner_key.as_bytes())
            && record.authorization.as_ref().unwrap().token == input.confirmation_token,
        "FORBIDDEN: imported original action owner/token"
    );
    Ok(record)
}
pub(crate) fn cancel(root: &Path, uid: u32, input: Cancel) -> Result<Value> {
    let record = owned(root, uid, &input)?;
    cancel_original(root,record,None,None)
}
pub(crate) fn cancel_remote(root:&Path,principal:&principal::RemotePrincipal,input:Cancel)->Result<Value> {
    let command=principal.require_action_dto(&input,44)?;
    let record=owned(root,principal.uid(),&input)?;
    cancel_original(root,record,None,Some(command))
}
fn cancel_original(root:&Path,mut record:Record,expiry:Option<expiry::Decision>,command:Option<principal::CommandAudit>)->Result<Value> {
    if let Some(origin)=&record.origin {
        if expiry.is_none() {command.as_ref().context("FORBIDDEN: original cancellation admission")?.require(origin,44)?;}
    } else {ensure!(command.is_none(),"FORBIDDEN: local cancellation cannot use remote audit");}
    ensure!(
        record.state == State::Prepared
            && !record.forward_intent
            && !present(&history(root, record.uid, &record.request_id))?,
        "OUTCOME_UNKNOWN: query original imported work;never cancel an issued or already decided action"
    );
    let original = super::super::original(root)?
        .context("CONFLICT: original imported initialization missing")?;
    read(root, &original.document, &original.origin, &original.source)?;
    record.state = State::RollingBack;
    record.cancellation_command=command;
    if let Some(expiry)=expiry {record.schema_version=record.schema_version.max(4);record.expiry=Some(expiry);}
    bounded(&record)?;
    durable::json(&root.join("firewall/transaction.json"), &record)?;
    let mut settled = record.clone();
    settled.state = State::RolledBack;
    publish(root, &settled)
        .context("OUTCOME_UNKNOWN: original cancellation publication unavailable;query only")?;
    finish_marker(root, &original.document, &original.origin, &original.source)?;
    receipt(&settled, false)
}
