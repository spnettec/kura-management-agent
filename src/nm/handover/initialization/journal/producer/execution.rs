//! One-shot original native transactions. Every effect uses a fresh, opaque
//! authority and an exact pending ticket. Observation and confirmation never
//! dispatch; missing publications never cause a retry or reconstruction.
use super::*;
use native::raw::{wire, writer};
use std::time::Instant;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::nm::handover::initialization::journal) struct Intent {
    runtime_sha256: String,
    owner_sha256: String,
    owner: OwnerAuthority,
    network_cohort_sha256: String,
    source_stamp: String,
    batch_sha256: String,
    wire_sha256: String,
}
impl Intent {
    pub(super) fn reserve(owner: &OwnerAuthority) -> Result<Self> {
        let owner=owner.reserved();
        Ok(Self {
            runtime_sha256: "f".repeat(64),
            owner_sha256: digest(&serde_json::to_value(&owner)?)?,
            owner,
            network_cohort_sha256: "f".repeat(64),
            source_stamp: "f".repeat(64),
            batch_sha256: "f".repeat(64),
            wire_sha256: "f".repeat(64),
        })
    }
    pub(in crate::nm::handover::initialization::journal) fn validate(&self) -> Result<()> {
        ensure!(
            [
                &self.runtime_sha256,
                &self.owner_sha256,
                &self.network_cohort_sha256,
                &self.source_stamp,
                &self.batch_sha256,
                &self.wire_sha256
            ]
            .into_iter()
            .all(|v| hex(v, 64)),
            "CONFLICT: native intent proof shape"
        );
        self.owner.require_complete()?;
        self.owner.require_runtime(&self.runtime_sha256)?;
        ensure!(
            self.owner_sha256 == digest(&serde_json::to_value(&self.owner)?)?,
            "CONFLICT: native intent owner digest"
        );
        Ok(())
    }
    fn fresh(snapshot: &Snapshot, proof: &Verified, batch: &Value) -> Result<Self> {
        proof.require(snapshot)?;
        let (bytes, _) = writer::encode(batch)?;
        let owner=proof.recorded_owner(snapshot)?;
        Ok(Self {
            runtime_sha256: proof.runtime_hash().into(),
            owner_sha256: digest(&serde_json::to_value(&owner)?)?,
            owner,
            network_cohort_sha256: proof.cohort().into(),
            source_stamp: snapshot.stamp().into(),
            batch_sha256: digest(batch)?,
            wire_sha256: durable::hash(&bytes),
        })
    }
    fn require_batch(&self, batch: &Value) -> Result<()> {
        self.validate()?;
        ensure!(
            self.batch_sha256 == digest(batch)?
                && self.wire_sha256 == durable::hash(&writer::encode(batch)?.0),
            "CONFLICT: original dispatch differs from its exact bound native batch"
        );
        Ok(())
    }
    pub(in crate::nm::handover::initialization::journal) fn stopped_authority(&self)->bool {
        self.owner.is_stopped()
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Negative {
    schema_version: u8,
    inverse: bool,
    batch_sha256: String,
    wire_sha256: String,
    errno: i32,
    sequence: u32,
    reply_sha256: String,
    reply_hex: String,
}
impl Negative {
    fn new(batch: &Value, inverse: bool, error: &wire::Rejected) -> Result<Self> {
        let checked = writer::rejection(batch, &error.reply)?;
        ensure!(
            checked.errno == error.errno
                && checked.sequence == error.sequence
                && checked.reply_sha256 == error.reply_sha256,
            "CONFLICT: negative ACK differs from its original raw reply"
        );
        Ok(Self {
            schema_version: 1,
            inverse,
            batch_sha256: digest(batch)?,
            wire_sha256: durable::hash(&writer::encode(batch)?.0),
            errno: checked.errno,
            sequence: checked.sequence,
            reply_sha256: checked.reply_sha256,
            reply_hex: checked
                .reply
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        })
    }
    fn check(&self, batch: &Value, inverse: bool) -> Result<()> {
        ensure!(
            !self.reply_hex.is_empty()
                && self.reply_hex.len() <= 512 * 1024
                && self.reply_hex.len().is_multiple_of(2)
                && hex(&self.reply_hex, self.reply_hex.len()),
            "CONFLICT: original negative ACK encoding bounds"
        );
        let reply = self
            .reply_hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
            .collect::<Result<Vec<_>>>()?;
        let checked = writer::rejection(batch, &reply)?;
        ensure!(
            self.schema_version == 1
                && self.inverse == inverse
                && self.batch_sha256 == digest(batch)?
                && self.wire_sha256 == durable::hash(&writer::encode(batch)?.0)
                && self.errno == checked.errno
                && self.sequence == checked.sequence
                && self.reply_sha256 == checked.reply_sha256,
            "CONFLICT: original negative ACK identity"
        );
        Ok(())
    }
}
fn forward(root: &Path, record: &Record) -> Result<Value> {
    let reference = record
        .forward
        .as_ref()
        .context("OUTCOME_UNKNOWN: original forward ACK missing")?;
    Ok(serde_json::from_slice(
        &reference.read(root, &record.path(root, "forward.json"))?,
    )?)
}
fn original_batch(root: &Path, record: &Record, plan: &UpdatePlan, inverse: bool) -> Result<Value> {
    let source = if inverse {
        forward(root, record)?
    } else {
        plan.original_native().clone()
    };
    plan.batch(&source, inverse)
}
pub(in crate::nm::handover::initialization::journal) fn check_evidence(
    root: &Path,
    record: &Record,
    plan: &UpdatePlan,
) -> Result<()> {
    for (inverse, intent) in [
        (false, &record.forward_dispatch),
        (true, &record.inverse_dispatch),
    ] {
        if let Some(intent) = intent {
            intent.require_batch(&original_batch(root, record, plan, inverse)?)?;
            let auth = record
                .authorization
                .as_ref()
                .context("CONFLICT: native intent has no proposal")?;
            intent.owner.require_original(
                auth.delegation.operation_id,
                &auth.delegation.plan_sha256,
                auth.owner.mirror_hash(),
                auth.owner.role_configuration(),
            )?;
            intent.owner.require_same_firewall(&auth.owner)?;
            ensure!(
                intent.source_stamp == auth.source_stamp
                    && intent.network_cohort_sha256 == auth.network_cohort_sha256,
                "CONFLICT: native intent changed proposal parent or network cohort"
            );
        }
    }
    if let Some(reference) = &record.negative {
        let value: Negative =
            serde_json::from_slice(&reference.read(root, &record.path(root, "negative.json"))?)?;
        value.check(
            &original_batch(root, record, plan, record.inverse_intent)?,
            record.inverse_intent,
        )?;
    }
    Ok(())
}
fn save(root: &Path, record: &Record) -> Result<()> {
    bounded(record)?;
    durable::json(&root.join("firewall/transaction.json"), record)
        .context("OUTCOME_UNKNOWN: original native journal publication;never repeat action")
}
fn artifact(root: &Path, record: &Record, name: &str, value: &Value) -> Result<Reference> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= LIMIT as usize,
        "RESOURCE_EXHAUSTED: imported native evidence artifact"
    );
    let path = record.path(root, name);
    durable::publish_new(&path, &bytes, FileMetadata::private())
        .context("OUTCOME_UNKNOWN: original native artifact publication;query only")?;
    Reference::observe(root, &path)
}
fn reserve(record: &Record, plan: &UpdatePlan, batch: &Value) -> Result<()> {
    writer::encode(batch)?;
    let (forward_bound, inverse_bound) = plan.evidence_bounds()?;
    ensure!(
        forward_bound <= 512 * 1024 && inverse_bound <= 512 * 1024,
        "RESOURCE_EXHAUSTED: original native forward/inverse evidence headroom ({forward_bound}/{inverse_bound})"
    );
    let mut terminal = record.clone();
    terminal.schema_version = terminal.schema_version.max(4);
    let mut reference = terminal.plan.clone();
    reference.file.device = u64::MAX;
    reference.file.inode = u64::MAX;
    reference.firewall.device = u64::MAX;
    reference.firewall.inode = u64::MAX;
    reference.history.device = u64::MAX;
    reference.history.inode = u64::MAX;
    reference.parent.device = u64::MAX;
    reference.parent.inode = u64::MAX;
    terminal.state = State::RolledBack;
    terminal.forward_intent = true;
    terminal.inverse_intent = true;
    terminal.forward_dispatch = Some(Intent::reserve(
        &record
            .authorization
            .as_ref()
            .context("FORBIDDEN: ordinary proposal required")?
            .owner,
    )?);
    terminal.inverse_dispatch = Some(Intent::reserve(
        &record
            .authorization
            .as_ref()
            .context("FORBIDDEN: ordinary proposal required")?
            .owner,
    )?);
    terminal.forward_capture_intent = true;
    terminal.inverse_capture_intent = true;
    terminal.settlement_intent = true;
    terminal.forward = Some(reference.clone());
    terminal.inverse = Some(reference);
    terminal.expiry = Some(expiry::Decision::reserved(record.deadline_ms));
    if let Some(origin)=&record.origin {
        terminal.forward_command=Some(super::principal::CommandAudit::reserved(origin,41));
        terminal.inverse_command=Some(super::principal::CommandAudit::reserved(origin,43));
        terminal.confirmation_command=None;terminal.cancellation_command=None;terminal.confirmed_decision=false;
        terminal.expiry=None;
    }
    ensure!(
        bounded(&terminal)?.len() <= RECORD_BYTES - 1024,
        "RESOURCE_EXHAUSTED: native settled record reserve"
    );
    Ok(())
}
fn checked(root: &Path, record: &Record) -> Result<(Snapshot, UpdatePlan)> {
    let original = super::super::super::original(root)?
        .context("OUTCOME_UNKNOWN: original initialization missing")?;
    let view = read(root, &original.document, &original.origin, &original.source)?
        .context("OUTCOME_UNKNOWN: original native transaction missing")?;
    ensure!(
        view.head == record.base && !view.settled,
        "OUTCOME_UNKNOWN: original native transaction already published;query only"
    );
    let plan = record.checked_plan(root, &view.current, &original.source)?;
    let (revision, source) = identity(&view.head, &view.current, &original.source)?;
    let stamp = stamp(root, &view.head, &view.current, &original.source)?;
    original.file.verify_binding()?;
    Ok((
        Snapshot {
            current: view.current,
            head: view.head,
            original: original.source,
            revision,
            source,
            stamp,
            depth: view.history_depth,
            pending: None,
            physical: None,
        },
        plan,
    ))
}
/// Publish settled history/current exactly once. Recovery never invokes this.
fn settle(
    root: &Path,
    record: &Record,
    parent: &CurrentSource,
    plan: &UpdatePlan,
    inverse: bool,
) -> Result<Value> {
    ensure!(
        !record.settlement_intent,
        "OUTCOME_UNKNOWN: original settlement already attempted;never reconstruct"
    );
    let mut deciding = record.clone();
    deciding.settlement_intent = true;
    save(root, &deciding)?;
    let mut terminal = deciding;
    terminal.state = if inverse {
        State::RolledBack
    } else {
        State::Committed
    };
    let kernel = if inverse {
        let reference = terminal
            .inverse
            .as_ref()
            .context("OUTCOME_UNKNOWN: original inverse ACK missing")?;
        serde_json::from_slice(&reference.read(root, &terminal.path(root, "inverse.json"))?)?
    } else {
        forward(root, record)?
    };
    let current = plan.settled_source(parent, &kernel, inverse)?;
    let witness = current.witness()?;
    publish(root, &terminal)
        .context("OUTCOME_UNKNOWN: original settled history publication;never reconstruct")?;
    let head = Head::Transaction {
        uid: terminal.uid,
        request_id: terminal.request_id.clone(),
        reference: Reference::observe(root, &history(root, terminal.uid, &terminal.request_id))?,
    };
    let pointer = Confirmed {
        backend: Backend::Imported,
        schema_version: 1,
        head,
        revision: witness["revision"]
            .as_str()
            .context("CONFLICT: current revision")?
            .parse()?,
        source_digest: witness["sourceDigest"]
            .as_str()
            .context("CONFLICT: current source")?
            .into(),
    };
    durable::json(&root.join("firewall/confirmed.json"), &pointer)
        .context("OUTCOME_UNKNOWN: original current publication;never reconstruct")?;
    save(root, &terminal)?;
    receipt(&terminal, false)
}
fn reject(
    root: &Path,
    record: &mut Record,
    plan: &UpdatePlan,
    inverse: bool,
    error: &wire::Rejected,
) -> Result<Value> {
    let batch = original_batch(root, record, plan, inverse)?;
    let negative = Negative::new(&batch, inverse, error)?;
    record.negative_capture_intent = true;
    save(root, record)?;
    record.negative = Some(artifact(
        root,
        record,
        "negative.json",
        &serde_json::to_value(negative)?,
    )?);
    record.state = if inverse {
        State::RecoveryRequired
    } else {
        State::Rejecting
    };
    save(root, record)?;
    if inverse {
        return receipt(record, false);
    }
    reject_settle(root, record)
}
fn reject_settle(root: &Path, record: &mut Record) -> Result<Value> {
    ensure!(
        !record.settlement_intent,
        "OUTCOME_UNKNOWN: original rejection settlement already attempted;never reconstruct"
    );
    record.settlement_intent = true;
    save(root, record)?;
    let mut terminal = record.clone();
    terminal.state = State::Rejected;
    publish(root, &terminal)
        .context("OUTCOME_UNKNOWN: original rejected history publication;query only")?;
    save(root, &terminal)?;
    receipt(&terminal, false)
}

fn capture(
    root: &Path,
    record: &mut Record,
    plan: &UpdatePlan,
    inverse: bool,
    observe: impl FnOnce() -> Result<Value>,
) -> Result<()> {
    let already = if inverse {
        record.inverse_capture_intent
    } else {
        record.forward_capture_intent
    };
    let name = if inverse {
        "inverse.json"
    } else {
        "forward.json"
    };
    let reference = if already {
        // Adopt only an already-published original artifact. If it is missing,
        // no new observation or publication is attempted.
        let reference = Reference::observe(root, &record.path(root, name)).context(
            "OUTCOME_UNKNOWN: original capture intent has no artifact;never reconstruct",
        )?;
        let value: Value =
            serde_json::from_slice(&reference.read(root, &record.path(root, name))?)?;
        plan.acknowledge(&value, inverse)?;
        reference
    } else {
        let value = native::canonical_source(&observe()?)?;
        plan.acknowledge(&value, inverse)?;
        if inverse {
            record.inverse_capture_intent = true;
        } else {
            record.forward_capture_intent = true;
        }
        save(root, record)?;
        artifact(root, record, name, &value)?
    };
    if inverse {
        record.inverse = Some(reference);
    } else {
        record.forward = Some(reference);
        record.state = State::WaitConfirm;
    }
    save(root, record)
}
fn authorize(root: &Path, snapshot: &Snapshot, proof: &Verified, record: &Record) -> Result<()> {
    proof.require(snapshot)?;
    snapshot.require_current(root)?;
    let auth = record
        .authorization
        .as_ref()
        .context("FORBIDDEN: ordinary proposal required")?;
    ensure!(
        snapshot.pending.is_some()
            && auth.source_stamp == snapshot.stamp()
            && auth.delegation == *proof.binding()
            && auth.network_cohort_sha256 == proof.cohort(),
        "CONFLICT: native action requires fresh original source/delegation/network authority"
    );
    ensure!(
        !present(&history(root, record.uid, &record.request_id))?,
        "OUTCOME_UNKNOWN: original settlement exists;query only"
    );
    Ok(())
}
/// Only this production wrapper selects the real once-only native sender.
#[allow(clippy::too_many_arguments)]
pub(in crate::nm) fn execute(
    root: &Path,
    snapshot: &Snapshot,
    proof: &Verified,
    uid: u32,
    action: Cancel,
    inverse: bool,
    deadline: Instant,
    observe: impl FnOnce() -> Result<Value>,
) -> Result<Value> {
    run(
        root,
        snapshot,
        proof,
        uid,
        action,
        inverse,
        |batch| {
            ensure!(
                Instant::now() < deadline,
                "OUTCOME_UNKNOWN: original native intent expired before transport;never repeat"
            );
            writer::dispatch(batch, deadline)
        },
        observe,
    )
}

struct OriginalAction {
    record:Record,
    inverse:bool,
    expiry:Option<expiry::Decision>,
    command:Option<super::principal::CommandAudit>,
}
pub(in crate::nm) struct RemoteAction<'a> {
    pub(in crate::nm) principal:&'a super::principal::RemotePrincipal,
    pub(in crate::nm) action:Cancel,
    pub(in crate::nm) inverse:bool,
}
pub(in crate::nm) fn execute_remote(root:&Path,snapshot:&Snapshot,proof:&Verified,
    work:RemoteAction<'_>,deadline:Instant,observe:impl FnOnce()->Result<Value>)->Result<Value> {
    let command=work.principal.require_action_dto(&work.action,if work.inverse {43}else{41})?;
    let record=owned(root,work.principal.uid(),&work.action)?;
    run_original(root,snapshot,proof,OriginalAction {record,inverse:work.inverse,expiry:None,command:Some(command)},
        |batch|{ensure!(Instant::now()<deadline,"OUTCOME_UNKNOWN: original native intent expired before transport;never repeat");writer::dispatch(batch,deadline)},observe)
}

pub(in crate::nm) fn expire(
    root:&Path,snapshot:&Snapshot,proof:&Verified,work:&expiry::Scheduled,
    deadline:Instant,observe:impl FnOnce()->Result<Value>,
)->Result<Value> {
    run_original(root,snapshot,proof,OriginalAction{record:work.original(root)?,inverse:true,expiry:Some(work.rollback_decision()?),command:None},
        |batch| {
            ensure!(Instant::now()<deadline,
                "OUTCOME_UNKNOWN: original expiry intent expired before transport;never repeat");
            writer::dispatch(batch,deadline)
        },observe)
}

#[cfg(test)]
pub(in crate::nm) fn expire_fixture(
    root:&Path,snapshot:&Snapshot,proof:&Verified,work:&expiry::Scheduled,
    send:impl FnOnce(&Value)->Result<()>,observe:impl FnOnce()->Result<Value>,
)->Result<Value> {
    run_original(root,snapshot,proof,OriginalAction{record:work.original(root)?,inverse:true,expiry:Some(work.rollback_decision()?),command:None},send,observe)
}
#[allow(clippy::too_many_arguments)]
fn run(
    root: &Path,
    snapshot: &Snapshot,
    proof: &Verified,
    uid: u32,
    action: Cancel,
    inverse: bool,
    send: impl FnOnce(&Value) -> Result<()>,
    observe: impl FnOnce() -> Result<Value>,
) -> Result<Value> {
    let record = owned(root, uid, &action)?;
    run_original(root,snapshot,proof,OriginalAction{record,inverse,expiry:None,command:None},send,observe)
}

fn run_original(
    root:&Path,snapshot:&Snapshot,proof:&Verified,action:OriginalAction,
    send:impl FnOnce(&Value)->Result<()>,observe:impl FnOnce()->Result<Value>,
)->Result<Value> {
    let OriginalAction{mut record,inverse,expiry,command}=action;
    if let Some(origin)=&record.origin {
        if expiry.is_none() {command.as_ref().context("FORBIDDEN: original remote dispatch admission")?.require(origin,if inverse {43}else{41})?;}
        else {ensure!(command.is_none(),"FORBIDDEN: expiry cannot acquire remote dispatch audit");}
    } else {ensure!(command.is_none(),"FORBIDDEN: local dispatch cannot use remote action audit");}
    authorize(root, snapshot, proof, &record)?;
    ensure!(
        if inverse {
            record.state == State::WaitConfirm && !record.inverse_intent
        } else {
            record.state == State::Prepared
                && !record.forward_intent
                && now_ms() < record.deadline_ms
        },
        "OUTCOME_UNKNOWN: original native action already issued or deadline expired;query only"
    );
    let plan = record.checked_plan(root, &snapshot.current, &snapshot.original)?;
    let batch = original_batch(root, &record, &plan, inverse)?;
    reserve(&record, &plan, &batch)?;
    let inventory = Inventory::read(root)?;
    ensure!(
        snapshot.depth < MAX_HISTORY && inventory.entries < MAX_HISTORY * 3,
        "RESOURCE_EXHAUSTED: native settlement history headroom"
    );
    let intent = Intent::fresh(snapshot, proof, &batch)?;
    if intent.stopped_authority() {record.schema_version=record.schema_version.max(4);}
    if let Some(expiry)=expiry {
        ensure!(inverse && now_ms()>=record.deadline_ms,
            "OUTCOME_UNKNOWN: original expiry cannot issue an early or forward action");
        record.schema_version=record.schema_version.max(4);record.expiry=Some(expiry);
    }
    if inverse {
        record.state = State::RollingBack;
        record.inverse_command=command;
        record.inverse_intent = true;
        record.inverse_dispatch = Some(intent);
    } else {
        record.state = State::Applying;
        record.forward_command=command;
        record.forward_intent = true;
        record.forward_dispatch = Some(intent);
    }
    // Fresh authority's deadline must still be live at the last admission point.
    proof.require(snapshot)?;
    save(root, &record)?;
    match send(&batch) {
        Ok(()) => {}
        Err(error) => {
            if let Some(negative) = error.downcast_ref::<wire::Rejected>() {
                return reject(root, &mut record, &plan, inverse, negative);
            }
            anyhow::bail!(
                "OUTCOME_UNKNOWN: original native dispatch ambiguous;query original only: {error}"
            );
        }
    }
    capture(root, &mut record, &plan, inverse, observe)
        .context("OUTCOME_UNKNOWN: original native outcome not fully published;query only")?;
    if inverse {
        settle(root, &record, &snapshot.current, &plan, true)
    } else {
        receipt(&record, false)
    }
}
pub(in crate::nm) fn confirm(
    root: &Path,
    snapshot: &Snapshot,
    proof: &Verified,
    uid: u32,
    action: Cancel,
) -> Result<Value> {
    confirm_owned(root,snapshot,proof,owned(root,uid,&action)?,None)
}
pub(in crate::nm) fn confirm_remote(root:&Path,snapshot:&Snapshot,proof:&Verified,
    principal:&super::principal::RemotePrincipal,action:Cancel)->Result<Value> {
    let command=principal.require_action_dto(&action,42)?;
    confirm_owned(root,snapshot,proof,owned(root,principal.uid(),&action)?,Some(command))
}
fn confirm_owned(root:&Path,snapshot:&Snapshot,proof:&Verified,mut record:Record,
    command:Option<super::principal::CommandAudit>)->Result<Value> {
    if let Some(origin)=&record.origin {command.as_ref().context("FORBIDDEN: original remote confirmation admission")?.require(origin,42)?;}
    else {ensure!(command.is_none(),"FORBIDDEN: local confirmation cannot use remote action audit");}
    authorize(root, snapshot, proof, &record)?;
    ensure!(
        record.state == State::WaitConfirm
            && !record.inverse_intent
            && now_ms() < record.deadline_ms,
        "OUTCOME_UNKNOWN: original confirmation no longer admissible;query only"
    );
    let plan = record.checked_plan(root, &snapshot.current, &snapshot.original)?;
    record.state = State::Confirming;
    record.confirmation_command=command;
    record.confirmed_decision = true;
    proof.require(snapshot)?;
    save(root, &record)?;
    settle(root, &record, &snapshot.current, &plan, false)
}
/// An authenticated original query may observe/adopt the issued batch's exact
/// kernel receipt. It never sends, reverses or recreates missing publications.
pub(crate) fn outcome(
    root: &Path,
    uid: u32,
    input: Outcome,
    observe: impl FnOnce() -> Result<Value>,
) -> Result<Value> {
    let value = super::outcome(root, uid, input)?;
    if value["historical"] == true {
        return Ok(value);
    }
    let mut record = active(root)?;
    if !matches!(
        record.state,
        State::Applying
            | State::RollingBack
            | State::RecoveryRequired
            | State::Confirming
            | State::Rejecting
    ) || !record.forward_intent
    {
        return Ok(value);
    }
    let (snapshot, plan) = checked(root, &record)?;
    if record.settlement_intent {
        return Ok(value);
    }
    if record.state == State::Confirming {
        return settle(root, &record, &snapshot.current, &plan, false);
    }
    if record.negative_capture_intent {
        let reference = record
            .negative
            .clone()
            .map(Ok)
            .unwrap_or_else(|| Reference::observe(root, &record.path(root, "negative.json")))
            .context(
                "OUTCOME_UNKNOWN: original negative ACK publication missing;never reconstruct",
            )?;
        let negative: Negative =
            serde_json::from_slice(&reference.read(root, &record.path(root, "negative.json"))?)?;
        negative.check(
            &original_batch(root, &record, &plan, record.inverse_intent)?,
            record.inverse_intent,
        )?;
        let expected_state = if record.inverse_intent {
            State::RecoveryRequired
        } else {
            State::Rejecting
        };
        if record.negative.as_ref() != Some(&reference) || record.state != expected_state {
            record.negative = Some(reference);
            record.state = expected_state;
            save(root, &record)?;
        }
        return if record.inverse_intent {
            receipt(&record, false)
        } else {
            reject_settle(root, &mut record)
        };
    }
    let inverse = record.inverse_intent;
    if inverse && record.inverse.is_some() {
        return settle(root, &record, &snapshot.current, &plan, true);
    }
    capture(root, &mut record, &plan, inverse, observe)
        .context("OUTCOME_UNKNOWN: original native observation incomplete;never redispatch")?;
    if inverse {
        settle(root, &record, &snapshot.current, &plan, true)
    } else {
        receipt(&record, false)
    }
}
#[cfg(test)]
mod tests;
