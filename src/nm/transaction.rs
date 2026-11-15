//! Retained joint-NM transaction admission. This reader never repairs or deletes
//! evidence and does not execute NM/nft actions. The coordinator writer is pending.
use super::*;
use std::{fs, os::unix::fs::MetadataExt};

#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum State {
    Prepared,
    CheckpointIntent,
    CheckpointCreated,
    ProfileIntent,
    ProfileApplied,
    FirewallIntent,
    WaitConfirm,
    ConfirmDecided,
    RollbackDecided,
    RollbackRunning,
    RecoveryRequired,
    Committed,
    RolledBack,
    Cancelled,
}
impl State {
    pub(super) fn terminal(&self) -> bool {
        matches!(self, Self::Committed | Self::RolledBack | Self::Cancelled)
    }
}
/// Fields the admission reader does not interpret; the coordinator writer owns
/// their meaning. All default so reader-only journals keep parsing unchanged.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct ActionIntent {
    pub(super) action: String,
    pub(super) sha256: String,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RemoteBinding {
    pub(super) authority: String,
    pub(super) command_id: String,
    pub(super) command_hash: String,
    pub(super) connection: String,
    pub(super) applied_at_ms: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RemoteAction {
    pub(super) command_id: String,
    pub(super) command_hash: String,
    pub(super) operation: i32,
    pub(super) new_connection_proved: bool,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct FirewallBinding {
    pub(super) revision: u64,
    pub(super) confirmed_sha256: String,
    pub(super) journal_settled: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Journal {
    pub(super) schema_version: u8,
    pub(super) operation_id: uuid::Uuid,
    pub(super) source_digest: String,
    pub(super) candidate_digest: String,
    pub(super) intent_sha256: String,
    pub(super) state: State,
    pub(super) terminal_receipt_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) deadline_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) checkpoint_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) nm_identity: Option<BusBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) nat_before: Option<Value>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) rollback_dispatched: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) nat_restore_dispatched: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) checkpoint_destroy_dispatched: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) firewall_binding: Option<FirewallBinding>,
    /// The validated coordinator input (typed changes, NAT set, confirm
    /// window). Stages recompile deterministically from it under fresh
    /// observation, so a lost reply never invents a payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) input: Option<Value>,
    /// Checkpoints that already existed before this operation touched NM.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) pre_existing_checkpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) remote_binding: Option<RemoteBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) remote_actions: Vec<RemoteAction>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) action_intents: Vec<ActionIntent>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) confirmed_decision: bool,
}
impl Journal {
    /// Base journal exactly as the reader-only generation produced it.
    pub(super) fn new(
        operation_id: uuid::Uuid,
        source_digest: String,
        candidate_digest: String,
        intent_sha256: String,
        state: State,
    ) -> Self {
        Self {
            schema_version: 1,
            operation_id,
            source_digest,
            candidate_digest,
            intent_sha256,
            state,
            terminal_receipt_sha256: None,
            token: None,
            deadline_ms: None,
            checkpoint_path: None,
            nm_identity: None,
            nat_before: None,
            rollback_dispatched: false,
            nat_restore_dispatched: false,
            checkpoint_destroy_dispatched: false,
            firewall_binding: None,
            input: None,
            pre_existing_checkpoints: Vec::new(),
            remote_binding: None,
            remote_actions: Vec::new(),
            action_intents: Vec::new(),
            confirmed_decision: false,
        }
    }
}
// The admission reader binds the immutable intent's identity; typed payload
// validation belongs to the coordinator before any backend call.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct IntentHeader {
    pub(super) schema_version: u8,
    pub(super) operation_id: uuid::Uuid,
    pub(super) source_digest: String,
    pub(super) candidate_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) nm_identity: Option<BusBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) nat_before: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) nat_target: Option<Value>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Receipt {
    pub(super) schema_version: u8,
    pub(super) operation_id: uuid::Uuid,
    pub(super) source_digest: String,
    pub(super) candidate_digest: String,
    pub(super) intent_sha256: String,
    pub(super) state: State,
}
fn hash_shape(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn private_directory(path: &Path) -> Result<bool> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o777 == 0o700,
        "FORBIDDEN: unsafe retained NM directory"
    );
    Ok(true)
}
fn read_private(path: &Path) -> Result<Vec<u8>> {
    let (bytes, meta) = crate::durable::read(path, 1_048_576)?;
    ensure!(
        meta.uid == unsafe { libc::geteuid() } && meta.mode == 0o600,
        "FORBIDDEN: unsafe retained NM evidence"
    );
    Ok(bytes)
}
/// Token-free retained status for an observer. Admission validates evidence even
/// when it is pending; false is a write fence, not a reason to hide the record.
pub(super) fn view(root: &Path) -> Result<(Option<String>, Option<Value>)> {
    let _settled=admission(root)?;
    let path=root.join("nm/transaction.json");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind()==std::io::ErrorKind::NotFound=>return Ok((None,None)),
        Err(error)=>return Err(error.into()),Ok(_)=>{},
    }
    let journal:Journal=serde_json::from_slice(&read_private(&path)?)?;
    Ok((Some(journal.candidate_digest),Some(json!({"id":journal.operation_id.to_string(),
        "state":journal.state,"deadlineUnixMs":journal.deadline_ms}))))
}
/// True means a fully bound terminal file receipt. It is an admission decision,
/// not a fresh NM/kernel health check, operation success query, or write grant.
pub(crate) fn admission(root: &Path) -> Result<bool> {
    let dir = root.join("nm");
    if !private_directory(&dir)? {
        return Ok(true);
    }
    let journal = dir.join("transaction.json");
    let exists = match fs::symlink_metadata(&journal) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if !exists {
        for name in ["intents", "receipts"] {
            let path = dir.join(name);
            if private_directory(&path)? {
                ensure!(
                    fs::read_dir(path)?.next().is_none(),
                    "CONFLICT: orphan NM transaction evidence; preserve state"
                );
            }
        }
        return Ok(true);
    }
    let j: Journal = serde_json::from_slice(&read_private(&journal)?)?;
    ensure!(
        j.schema_version == 1
            && !j.operation_id.is_nil()
            && [&j.source_digest, &j.candidate_digest, &j.intent_sha256]
                .into_iter()
                .all(|s| hash_shape(s)),
        "CONFLICT: NM transaction identity"
    );
    ensure!(
        private_directory(&dir.join("intents"))?,
        "CONFLICT: missing NM intent directory"
    );
    let intent = read_private(&dir.join("intents").join(format!("{}.json", j.operation_id)))?;
    ensure!(
        crate::durable::hash(&intent) == j.intent_sha256,
        "CONFLICT: NM intent changed"
    );
    let i: IntentHeader = serde_json::from_slice(&intent)?;
    ensure!(
        i.schema_version == 1
            && i.operation_id == j.operation_id
            && i.source_digest == j.source_digest
            && i.candidate_digest == j.candidate_digest,
        "CONFLICT: NM intent binding"
    );
      ensure!(i.nm_identity == j.nm_identity, "CONFLICT: NM original bus binding changed");
      ensure!(i.nat_before == j.nat_before, "CONFLICT: NM original NAT binding changed");
    if let Some(target) = &i.nat_target {
        ensure!(target.as_object().is_some_and(|v| v.len() == 1 && v.contains_key("nat"))
            && target.get("nat") == j.input.as_ref().and_then(|v| v.get("nat")),
            "CONFLICT: NM automatic NAT target changed");
    }
    if !j.state.terminal() {
        ensure!(
            j.terminal_receipt_sha256.is_none(),
            "CONFLICT: contradictory NM terminal receipt"
        );
        return Ok(false);
    }
    let receipt_hash = j
        .terminal_receipt_sha256
        .as_deref()
        .filter(|s| hash_shape(s))
        .context("CONFLICT: NM terminal receipt required")?;
    ensure!(
        private_directory(&dir.join("receipts"))?,
        "CONFLICT: missing NM receipt directory"
    );
    let bytes = read_private(
        &dir.join("receipts")
            .join(format!("{}.json", j.operation_id)),
    )?;
    ensure!(
        crate::durable::hash(&bytes) == receipt_hash,
        "CONFLICT: NM terminal receipt changed"
    );
    let receipt: Receipt = serde_json::from_slice(&bytes)?;
    ensure!(
        receipt.schema_version == 1
            && receipt.operation_id == j.operation_id
            && receipt.source_digest == j.source_digest
            && receipt.candidate_digest == j.candidate_digest
            && receipt.intent_sha256 == j.intent_sha256
            && receipt.state == j.state,
        "CONFLICT: NM terminal receipt binding"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_change::{Guard, Subsystem};
    struct Fixture {
        root: std::path::PathBuf,
        journal: Journal,
    }
    impl Fixture {
        fn new(state: State) -> Self {
            let root =
                std::env::temp_dir().join(format!("yofc-nm-admission-{}", uuid::Uuid::new_v4()));
            crate::durable::directory(&root).unwrap();
            crate::durable::directory(&root.join("nm")).unwrap();
            for name in ["nm/intents", "nm/receipts"] {
                crate::durable::directory(&root.join(name)).unwrap();
            }
            let id = uuid::Uuid::new_v4();
            let i = IntentHeader {
                schema_version: 1,
                operation_id: id,
                source_digest: "a".repeat(64),
                candidate_digest: "b".repeat(64),
                  nm_identity: None,
                  nat_before: None,
                  nat_target: None,
            };
            let bytes = serde_json::to_vec(&i).unwrap();
            crate::durable::publish_new(
                &root.join("nm/intents").join(format!("{id}.json")),
                &bytes,
                crate::durable::FileMetadata::private(),
            )
            .unwrap();
            let f = Self {
                root,
                journal: Journal::new(
                    id,
                    i.source_digest,
                    i.candidate_digest,
                    crate::durable::hash(&bytes),
                    state,
                ),
            };
            f.save();
            f
        }
        fn save(&self) {
            crate::durable::json(&self.root.join("nm/transaction.json"), &self.journal).unwrap();
        }
        fn receipt(&mut self) {
            let j = &self.journal;
            let receipt = Receipt {
                schema_version: 1,
                operation_id: j.operation_id,
                source_digest: j.source_digest.clone(),
                candidate_digest: j.candidate_digest.clone(),
                intent_sha256: j.intent_sha256.clone(),
                state: serde_json::from_value(serde_json::to_value(&j.state).unwrap()).unwrap(),
            };
            let bytes = serde_json::to_vec(&receipt).unwrap();
            crate::durable::publish_new(
                &self
                    .root
                    .join("nm/receipts")
                    .join(format!("{}.json", j.operation_id)),
                &bytes,
                crate::durable::FileMetadata::private(),
            )
            .unwrap();
            self.journal.terminal_receipt_sha256 = Some(crate::durable::hash(&bytes));
            self.save();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    #[test]
    fn unresolved_nm_blocks_every_other_system_writer_including_configuration() {
        for state in [
            State::Prepared,
            State::CheckpointIntent,
            State::CheckpointCreated,
            State::ProfileIntent,
            State::ProfileApplied,
            State::FirewallIntent,
            State::WaitConfirm,
            State::ConfirmDecided,
            State::RollbackDecided,
            State::RollbackRunning,
            State::RecoveryRequired,
        ] {
            let f = Fixture::new(state);
            assert!(!admission(&f.root).unwrap());
            for caller in [
                Subsystem::Network,
                Subsystem::Firewall,
                Subsystem::Recovery,
                Subsystem::Configuration,
                Subsystem::Identity,
                Subsystem::OrdinaryBoot,
                Subsystem::SystemControl,
            ] {
                assert!(Guard::acquire(&f.root, caller).is_err());
            }
            assert!(Guard::observe_shared(&f.root, Duration::from_millis(20)).is_ok());
        }
    }
    #[test]
    fn terminal_string_alone_does_not_admit_but_matching_immutable_receipt_does() {
        for state in [State::Committed, State::RolledBack, State::Cancelled] {
            let mut f = Fixture::new(state);
            assert!(admission(&f.root).is_err());
            f.receipt();
            let before = fs::read(f.root.join("nm/transaction.json")).unwrap();
            assert!(admission(&f.root).unwrap());
            assert!(Guard::acquire(&f.root, Subsystem::Firewall).is_ok());
            assert_eq!(
                before,
                fs::read(f.root.join("nm/transaction.json")).unwrap()
            );
        }
    }
    #[test]
    fn changed_intent_receipt_and_generation_mismatch_never_unlock() {
        for part in ["intent", "receipt", "operation", "candidate", "state"] {
            let mut f = Fixture::new(State::Committed);
            f.receipt();
            match part {
                "intent" => crate::durable::json(
                    &f.root
                        .join("nm/intents")
                        .join(format!("{}.json", f.journal.operation_id)),
                    &json!({"changed":true}),
                )
                .unwrap(),
                "receipt" => crate::durable::json(
                    &f.root
                        .join("nm/receipts")
                        .join(format!("{}.json", f.journal.operation_id)),
                    &json!({"changed":true}),
                )
                .unwrap(),
                "operation" => {
                    f.journal.operation_id = uuid::Uuid::new_v4();
                    f.save();
                }
                "candidate" => {
                    f.journal.candidate_digest = "c".repeat(64);
                    f.save();
                }
                _ => {
                    f.journal.state = State::RolledBack;
                    f.save();
                }
            }
            assert!(admission(&f.root).is_err(), "{part}");
        }
    }
    #[test]
    fn missing_current_journal_with_retained_intents_is_not_absence() {
        let f = Fixture::new(State::Prepared);
        fs::remove_file(f.root.join("nm/transaction.json")).unwrap();
        assert!(admission(&f.root).is_err());
        assert!(Guard::acquire(&f.root, Subsystem::Firewall).is_err());
    }
    #[test]
    fn corrupt_public_or_symlinked_evidence_is_not_ignored() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        for part in ["public", "symlink", "state"] {
            let mut f = Fixture::new(State::Prepared);
            let p = f.root.join("nm/transaction.json");
            match part {
                "public" => fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap(),
                "symlink" => {
                    let target = f.root.join("saved.json");
                    fs::rename(&p, &target).unwrap();
                    symlink(&target, &p).unwrap();
                }
                _ => {
                    f.journal.state = State::Prepared;
                    f.save();
                    let mut v = serde_json::to_value(&f.journal).unwrap();
                    v["state"] = json!("FAILED");
                    crate::durable::json(&p, &v).unwrap();
                }
            }
            assert!(admission(&f.root).is_err(), "{part}");
        }
    }
}

#[cfg(test)]
mod own_admission_tests {
    use super::*;
    #[test]
    fn nm_caller_cannot_bypass_malformed_retained_state() {
        let root = std::env::temp_dir().join(format!("nm-own-admission-{}", uuid::Uuid::new_v4()));
        crate::durable::directory(&root).unwrap();
        crate::durable::directory(&root.join("nm")).unwrap();
        crate::durable::json(
            &root.join("nm/transaction.json"),
            &json!({"state":"COMMITTED"}),
        )
        .unwrap();
        assert!(
            crate::system_change::Guard::acquire(&root, crate::system_change::Subsystem::Nm)
                .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
