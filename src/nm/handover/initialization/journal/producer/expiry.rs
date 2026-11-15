//! Opaque original work for the internal deadline scheduler. No caller-selected
//! identity,owner key or replay operation is accepted by this interface.
use super::*;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Phase {
    BeforeDispatch,
    AfterForward,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::nm::handover::initialization::journal) struct Decision {
    schema_version: u8,
    phase: Phase,
    deadline_ms: u64,
    observed_at_ms: u64,
}
impl Decision {
    pub(super) fn reserved(deadline: u64) -> Self {
        Self {
            schema_version: 1,
            phase: Phase::AfterForward,
            deadline_ms: deadline,
            observed_at_ms: i64::MAX as u64,
        }
    }
    pub(in crate::nm::handover::initialization::journal) fn require_record(
        &self,
        record: &Record,
    ) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && record.kind.is_none()
                && matches!(record.schema_version,4|5)
                && self.deadline_ms == record.deadline_ms
                && self.observed_at_ms >= self.deadline_ms
                && self.observed_at_ms <= i64::MAX as u64
                && !record.confirmed_decision,
            "CONFLICT: original expiry decision identity/deadline"
        );
        let shape = match self.phase {
            Phase::BeforeDispatch => {
                matches!(record.state, State::RollingBack | State::RolledBack)
                    && !record.forward_intent
                    && !record.inverse_intent
                    && record.forward.is_none()
                    && record.inverse.is_none()
                    && record.forward_dispatch.is_none()
                    && record.inverse_dispatch.is_none()
            }
            Phase::AfterForward => {
                matches!(
                    record.state,
                    State::RollingBack | State::RolledBack | State::RecoveryRequired
                ) && record.forward_intent
                    && record.forward.is_some()
                    && record.inverse_intent
                    && record.forward_dispatch.is_some()
                    && record.inverse_dispatch.is_some()
            }
        };
        ensure!(
            shape,
            "CONFLICT: expiry cannot turn unknown/unissued work into a native rollback"
        );
        Ok(())
    }
}

/// No Deserialize/Clone and no public constructor. Each instance pins the exact
/// original record plus its parent; every action verifies it again under EX.
pub(in crate::nm) struct Scheduled {
    original: Record,
    marker: MarkerIdentity,
    snapshot: Snapshot,
    observed_at_ms: u64,
}
pub(in crate::nm) enum Tick {
    Idle,
    Pending,
    Cancel(Scheduled),
    Rollback(Scheduled),
}
impl Scheduled {
    pub(in crate::nm) fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub(super) fn original(&self, root: &Path) -> Result<Record> {
        let file = BoundFile::open(&root.join("firewall/transaction.json"), RECORD_BYTES as u64)?;
        let current: Record = serde_json::from_slice(&file.bytes)?;
        current.validate()?;
        ensure!(
            file.marker()? == self.marker
                && current == self.original
                && current.expiry.is_none()
                && now_ms() >= self.observed_at_ms
                && now_ms() >= current.deadline_ms,
            "OUTCOME_UNKNOWN: original expiry work changed,already issued or deadline no longer due"
        );
        self.snapshot.require_current(root)?;
        file.verify_binding()?;
        Ok(current)
    }
    fn decision(&self, phase: Phase) -> Decision {
        Decision {
            schema_version: 1,
            phase,
            deadline_ms: self.original.deadline_ms,
            observed_at_ms: self.observed_at_ms,
        }
    }
    pub(super) fn rollback_decision(&self) -> Result<Decision> {
        ensure!(
            self.original.state == State::WaitConfirm
                && self.original.forward.is_some()
                && !self.original.inverse_intent,
            "OUTCOME_UNKNOWN: original forward ACK required for expiry"
        );
        Ok(self.decision(Phase::AfterForward))
    }
}

/// Caller holds the EX observation guard. Only already existing exact metadata
/// can settle here. No native read,sender,Core callback or new operation ID.
pub(in crate::nm) fn poll(root: &Path) -> Result<Tick> {
    if !super::super::super::owns_firewall_domain(root)? {
        return Ok(Tick::Idle);
    }
    let path = root.join("firewall/transaction.json");
    if !present(&path)? {
        return Ok(Tick::Idle);
    }
    let file = BoundFile::open(&path, RECORD_BYTES as u64)?;
    let record: Record = serde_json::from_slice(&file.bytes)?;
    record.validate()?;
    file.verify_binding()?;
    if record.state.settled() {
        return Ok(Tick::Idle);
    }
    if matches!(
        record.state,
        State::Confirming | State::RollingBack | State::Rejecting
    ) || record.kind == Some(Kind::SourceObservation) && record.settlement_intent
    {
        let result = super::super::super::recover_imported_transaction(root)?
            .context("OUTCOME_UNKNOWN: original imported initialization unavailable")?;
        return Ok(if result["journalSettled"] == true {
            Tick::Idle
        } else {
            Tick::Pending
        });
    }
    if record.kind.is_some()
        || record.authorization.is_none()
        || record.expiry.is_some()
        || now_ms() < record.deadline_ms
    {
        return Ok(Tick::Pending);
    }
    let cancellation = record.state == State::Prepared && !record.forward_intent;
    let rollback =
        record.state == State::WaitConfirm && record.forward.is_some() && !record.inverse_intent;
    if !cancellation && !rollback {
        return Ok(Tick::Pending);
    }
    let snapshot = Snapshot::pending_record(root, record.clone())?;
    let marker = file.marker()?;
    file.verify_binding()?;
    let work = Scheduled {
        original: record,
        marker,
        snapshot,
        observed_at_ms: now_ms(),
    };
    work.original(root)?;
    Ok(if cancellation {
        Tick::Cancel(work)
    } else {
        Tick::Rollback(work)
    })
}

pub(in crate::nm) fn cancel(root: &Path, work: &Scheduled) -> Result<Value> {
    let record = work.original(root)?;
    ensure!(
        record.state == State::Prepared && !record.forward_intent,
        "OUTCOME_UNKNOWN: issued original work cannot expire as a no-effect cancellation"
    );
    cancel_original(root, record, Some(work.decision(Phase::BeforeDispatch)),None)
}
