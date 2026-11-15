//! Command-bound decisions for an ordinary handoff. Proof reads immutable
//! evidence only; recording and archival belong to the native write transaction.
use super::*;
use prost::Message;
use yofc_management_protocol::v1::{ErrorCode, ReadCommand, TaskResult, TaskState};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Binding {
    pub(super) command_id: String,
    pub(super) operation: i32,
    request_sha256: String,
}
fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Binding {
    pub(super) fn from_command(command: &ReadCommand) -> Result<Self> {
        ensure!(
            matches!(command.operation, 21 | 22 | 29)
                && command.valid_payload()
                && uuid(&command.command_id)
                && !command.idempotency_key.is_empty()
                && command.idempotency_key.len() <= 64
                && command.expires_at_unix_ms > 0,
            "INVALID_ARGUMENT"
        );
        Ok(Self {
            command_id: command.command_id.clone(),
            operation: command.operation,
            request_sha256: durable::hash(&command.encode_to_vec()),
        })
    }
    pub(super) fn valid(&self) -> bool {
        uuid(&self.command_id)
            && matches!(self.operation, 21 | 22 | 29)
            && digest(&self.request_sha256)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Decision {
    schema: u32,
    binding: Binding,
    recovery_id: String,
    handoff_id: String,
    result: Value,
}
pub(super) fn private(path: &std::path::Path) -> Result<Vec<u8>> {
    let parent = fs::symlink_metadata(path.parent().context("handoff evidence parent")?)?;
    ensure!(
        parent.is_dir() && parent.uid() == unsafe { libc::geteuid() } && parent.mode() & 0o077 == 0,
        "CONFLICT: private handoff evidence directory required"
    );
    let (bytes, m) = durable::read(path, 1 << 20)?;
    ensure!(
        m.uid == unsafe { libc::geteuid() } && m.mode == 0o600,
        "CONFLICT: private handoff evidence required"
    );
    Ok(bytes)
}
pub(crate) fn has_evidence(state: &std::path::Path) -> Result<bool> {
    let path = state.join("commands");
    let meta = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    ensure!(
        meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
        "CONFLICT: unsafe handoff command directory"
    );
    Ok(fs::read_dir(path)?.next().is_some())
}
fn ordinary_file(root: &std::path::Path, p: &Plan, suffix: &str) -> PathBuf {
    root.join("receipts").join(format!("{}{suffix}", p.id))
}
pub(super) fn archived_inputs(root: &std::path::Path, j: &Journal, p: &Plan) -> Result<Config> {
    ensure!(
        p.id.strip_prefix("handoff-")
            .is_some_and(|v| uuid::Uuid::parse_str(v).is_ok_and(|id| id.to_string() == v)),
        "CONFLICT: handoff identity"
    );
    let read = |path: &std::path::Path, limit| -> Result<Vec<u8>> {
        let (bytes, m) = durable::read(path, limit)?;
        ensure!(
            m.mode & 0o077 == 0 && m.uid == unsafe { libc::geteuid() },
            "CONFLICT: private ordinary evidence required"
        );
        Ok(bytes)
    };
    let source = read(&ordinary_file(root, p, ".ordinary-source.json"), 1 << 20)?;
    ensure!(
        durable::hash(&source) == p.source_sha256,
        "CONFLICT: handoff source changed"
    );
    let original: Journal = serde_json::from_slice(&source)?;
    let strip = |j: &Journal| -> Result<Value> {
        let mut v = serde_json::to_value(j)?;
        for k in ["state", "error", "ordinary"] {
            v.as_object_mut().context("journal object")?.remove(k);
        }
        Ok(v)
    };
    ensure!(
        original.state == State::CompletedApprovedChecks
            && original.ordinary.is_none()
            && strip(&original)? == strip(j)?,
        "CONFLICT: handoff source identity changed"
    );
    let grant = read(&ordinary_file(root, p, ".ordinary-grant.json"), 256 << 10)?;
    ensure!(
        durable::hash(&grant) == p.grant_sha256,
        "CONFLICT: handoff grant archive changed"
    );
    let c: Config = serde_json::from_slice(&grant)?;
    Profile::config(&c)?;
    let mut hashes = vec![durable::hash(&grant)];
    hashes.extend(c.profile_files.iter().map(|f| f.sha256.clone()));
    ensure!(
        durable::hash(hashes.join("\n").as_bytes()) == p.profile_digest
            && c.unit == p.unit
            && c.profile_id == p.profile_id,
        "CONFLICT: handoff profile identity changed"
    );
    Ok(c)
}
pub(super) fn validate_commands(root: &std::path::Path, j: &Journal, p: &Plan) -> Result<()> {
    ensure!(
        p.command_decisions.len() <= 2,
        "CONFLICT: handoff command quota"
    );
    if let Some(binding) = &p.issued_command {
        ensure!(
            binding.valid()
                && binding.operation == 22
                && p.issued
                && (!p.verified || p.command_decisions.contains_key(&binding.command_id)),
            "CONFLICT: issued handoff binding"
        );
    }
    if let Some(binding) = &p.cancel_command {
        ensure!(
            binding.valid() && binding.operation == 29 && p.cancelled && !p.issued,
            "CONFLICT: cancellation binding"
        );
    }
    ensure!(
        !p.cancelled
            || (!p.issued && p.issued_command.is_none() && !p.verified && p.observation.is_none()),
        "CONFLICT: issued handoff cannot be cancelled"
    );
    for (id, hash) in &p.command_decisions {
        ensure!(
            uuid(id) && digest(hash),
            "CONFLICT: handoff command reference"
        );
        let bytes = private(&root.join("commands").join(format!("{id}.json")))?;
        let d: Decision = serde_json::from_slice(&bytes)?;
        ensure!(
            durable::hash(&bytes) == *hash
                && d.schema == 1
                && d.binding.valid()
                && d.binding.command_id == *id
                && d.recovery_id == j.id
                && d.handoff_id == p.id
                && (d.binding.operation != 22 || p.issued_command.as_ref() == Some(&d.binding))
                && (d.binding.operation != 29 || p.cancel_command.as_ref() == Some(&d.binding)),
            "CONFLICT: handoff command evidence"
        );
        let expected = match d.binding.operation {
            21 => Recovery::ordinary_prepare_value(p, &archived_inputs(root, j, p)?),
            22 => Recovery::ordinary_execute_value(p),
            29 => super::cancel::value(p),
            _ => anyhow::bail!("CONFLICT: handoff decision operation"),
        };
        ensure!(
            d.result == expected,
            "CONFLICT: original handoff decision changed"
        );
    }
    Ok(())
}
impl Recovery {
    fn ordinary_command_path(&self, id: &str) -> PathBuf {
        self.0.state.join("commands").join(format!("{id}.json"))
    }
    pub(super) fn ordinary_prepare_value(p: &Plan, c: &Config) -> Value {
        json!({"transactionId":p.id,"confirmToken":p.confirm_token,"state":"ORDINARY_PREPARED",
            "scope":"administrator-selected-checks","kuraRecoveryVerified":false,"normalBootVerified":false,
            "profileId":p.profile_id,"unit":p.unit,"profileDigest":p.profile_digest,"grantSha256":p.grant_sha256,
            "sourceJournalSha256":p.source_sha256,"snapshotSha256":p.highest_sha256,"expiresAtUnixMs":p.expires_at,
            "previousPid":p.old_normal_pid,"componentPids":c.component_pids,"checkIds":c.check_ids})
    }
    pub(super) fn ordinary_execute_value(p: &Plan) -> Value {
        let mut final_plan = p.clone();
        final_plan.verified = true;
        let mut value = final_plan.status();
        value["state"] = json!("ORDINARY_ACTIVE_APPROVED_CHECKS");
        value["normalBootVerified"] = json!(false);
        value
    }
    pub(super) fn record_ordinary_command(
        &self,
        recovery: &str,
        p: &mut Plan,
        binding: Binding,
        result: &Value,
    ) -> Result<()> {
        ensure!(
            binding.valid()
                && p.command_decisions.len() < 2
                && !p.command_decisions.contains_key(&binding.command_id),
            "CONFLICT: handoff command decision quota or identity"
        );
        durable::directory(&self.0.state.join("commands"))?;
        let bytes = serde_json::to_vec(&Decision {
            schema: 1,
            recovery_id: recovery.into(),
            handoff_id: p.id.clone(),
            binding: binding.clone(),
            result: result.clone(),
        })?;
        durable::publish_new(
            &self.ordinary_command_path(&binding.command_id),
            &bytes,
            FileMetadata::private(),
        )?;
        p.command_decisions
            .insert(binding.command_id, durable::hash(&bytes));
        Ok(())
    }
    pub(super) fn validate_ordinary_commands(&self, j: &Journal, p: &Plan) -> Result<()> {
        validate_commands(&self.0.state, j, p)
    }
    pub(in crate::recovery) fn archive_ordinary_journal(&self, j: &Journal) -> Result<()> {
        let Some(p) = &j.ordinary else {
            return Ok(());
        };
        if p.command_decisions.is_empty() && !p.cancelled {
            return Ok(());
        }
        if j.state == State::OrdinaryCancelled {
            super::cancel::validate(&self.0.state, j, true)?;
        } else {
            ensure!(
                j.state == State::OrdinaryActiveApprovedChecks && p.verified,
                "CONFLICT: unproven handoff history"
            );
            self.validate_ordinary_commands(j, p)?;
            let receipt = private(&self.ordinary_file(p, ".ordinary.json"))?;
            ensure!(
                receipt == self.ordinary_receipt_body(p)?
                    && p.receipt_sha256.as_ref() == Some(&durable::hash(&receipt)),
                "CONFLICT: handoff archive receipt changed"
            );
        }
        let path = self.0.state.join("transaction.json");
        let bytes = private(&path)?;
        ensure!(
            serde_json::from_slice::<Value>(&bytes)? == serde_json::to_value(j)?,
            "CONFLICT: handoff history drift"
        );
        let archive = self.ordinary_file(p, ".ordinary-journal.json");
        if archive.exists() {
            ensure!(
                private(&archive)? == bytes,
                "CONFLICT: handoff archive changed"
            );
        } else {
            durable::publish_new(&archive, &bytes, FileMetadata::private())?;
        }
        Ok(())
    }
    fn prove_ordinary_inner(&self, command: &ReadCommand) -> Result<Option<Value>> {
        let binding = Binding::from_command(command)?;
        let path = self.ordinary_command_path(&binding.command_id);
        let bytes = private(&path)?;
        let d: Decision = serde_json::from_slice(&bytes)?;
        ensure!(
            d.schema == 1
                && d.binding == binding
                && d.handoff_id.strip_prefix("handoff-").is_some_and(uuid)
                && d.recovery_id.strip_prefix("rec-").is_some_and(uuid),
            "CONFLICT: original handoff identity"
        );
        let current_path = self.0.state.join("transaction.json");
        let current_bytes = private(&current_path)?;
        let current: Journal = serde_json::from_slice(&current_bytes)?;
        let journal_path = if current
            .ordinary
            .as_ref()
            .is_some_and(|p| p.id == d.handoff_id)
        {
            current_path.clone()
        } else {
            self.0
                .state
                .join("receipts")
                .join(format!("{}.ordinary-journal.json", d.handoff_id))
        };
        let journal_bytes = private(&journal_path)?;
        let j: Journal = serde_json::from_slice(&journal_bytes)?;
        let p = j
            .ordinary
            .as_ref()
            .context("CONFLICT: no original handoff")?;
        let hash = durable::hash(&bytes);
        ensure!(
            j.id == d.recovery_id
                && p.id == d.handoff_id
                && p.command_decisions.get(&binding.command_id) == Some(&hash),
            "CONFLICT: unlinked handoff decision"
        );
        self.validate_ordinary_commands(&j, p)?;
        let mut inputs = vec![
            self.ordinary_file(p, ".ordinary-source.json"),
            self.ordinary_file(p, ".ordinary-grant.json"),
        ];
        if matches!(command.operation, 22 | 29) {
            inputs.push(self.ordinary_file(
                p,
                if command.operation == 29 {
                    ".ordinary-cancel.json"
                } else {
                    ".ordinary.json"
                },
            ));
        }
        let before = inputs
            .iter()
            .map(|path| private(path))
            .collect::<Result<Vec<_>>>()?;
        let c = self.ordinary_archive_inputs(&j, p)?;
        let expected = match command.operation {
            21 => Self::ordinary_prepare_value(p, &c),
            29 => {
                super::cancel::validate(&self.0.state, &j, true)?;
                ensure!(
                    p.cancel_command.as_ref() == Some(&binding),
                    "CONFLICT: original cancel binding"
                );
                let a = command.ordinary_handoff_action.as_ref().unwrap();
                ensure!(
                    a.transaction_id == p.id && a.confirmation_token == p.confirm_token,
                    "CONFLICT: cancel action changed"
                );
                super::cancel::value(p)
            }
            22 => {
                ensure!(
                    j.state == State::OrdinaryActiveApprovedChecks
                        && p.issued
                        && p.verified
                        && p.issued_command.as_ref() == Some(&binding),
                    "CONFLICT: handoff is not committed"
                );
                let a = command.ordinary_handoff_action.as_ref().unwrap();
                ensure!(
                    a.transaction_id == p.id && a.confirmation_token == p.confirm_token,
                    "CONFLICT: handoff action changed"
                );
                let receipt = private(&self.ordinary_file(p, ".ordinary.json"))?;
                ensure!(
                    receipt == self.ordinary_receipt_body(p)?
                        && p.receipt_sha256.as_ref() == Some(&durable::hash(&receipt)),
                    "CONFLICT: handoff receipt changed"
                );
                let observed = p
                    .observation
                    .as_ref()
                    .context("CONFLICT: missing handoff observation")?;
                self.ordinary_report(p, &c, &observed.report, observed.report.process_id)?;
                ensure!(
                    observed.report.schema == 2
                        && observed.report.ready
                        && observed.report.checks.iter().all(|v| v.passed),
                    "CONFLICT: unproven selected checks"
                );
                Self::ordinary_execute_value(p)
            }
            _ => return Ok(None),
        };
        ensure!(
            inputs
                .iter()
                .zip(before)
                .all(|(path, bytes)| private(path).is_ok_and(|v| v == bytes)),
            "CONFLICT: immutable handoff inputs changed"
        );
        ensure!(
            d.result == expected
                && private(&journal_path)? == journal_bytes
                && private(&path)? == bytes
                && private(&current_path)? == current_bytes,
            "CONFLICT: handoff evidence drift during query"
        );
        let mut result = d.result;
        result["reconciliation"] = json!({"source":"ordinary.handoff.journal.v1","commandId":binding.command_id,
            "operation":binding.operation,"requestSha256":binding.request_sha256,"transactionId":p.id,
            "journalSha256":durable::hash(&journal_bytes),"decisionSha256":hash});
        Ok(Some(result))
    }
    pub(crate) async fn prove_ordinary_command(
        &self,
        command: &ReadCommand,
    ) -> Result<Option<TaskResult>> {
        if !matches!(command.operation, 21 | 22 | 29) {
            return Ok(None);
        }
        let this = self.clone();
        let command = command.clone();
        tokio::task::spawn_blocking(move || {
            let proof = this.prove_ordinary_inner(&command);
            let Ok(Some(value)) = proof else {
                return Ok(None);
            };
            Ok(Some(TaskResult {
                command_id: command.command_id,
                state: TaskState::Succeeded as i32,
                error: ErrorCode::Unspecified as i32,
                result_json: serde_json::to_vec(&value)?,
            }))
        })
        .await?
    }
}
