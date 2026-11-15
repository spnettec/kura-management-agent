//! Immutable original-command decisions. This path never observes live units,
//! runs application checks, completes a native transaction or reissues work.
use super::*;
use prost::Message;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Binding {
    pub command_id: String,
    pub operation: i32,
    pub request_sha256: String,
}
impl Binding {
    pub fn from_command(c: &ReadCommand) -> Result<Self> {
        ensure!(
            matches!(c.operation, 24..=28)
                && c.valid_payload()
                && canonical(&c.command_id)
                && !c.idempotency_key.is_empty()
                && c.idempotency_key.len() <= 64
                && c.expires_at_unix_ms > 0,
            "INVALID_ARGUMENT"
        );
        Ok(Self {
            command_id: c.command_id.clone(),
            operation: c.operation,
            request_sha256: durable::hash(&c.encode_to_vec()),
        })
    }
    fn valid(&self) -> bool {
        canonical(&self.command_id)
            && matches!(self.operation, 24..=28)
            && hash(&self.request_sha256)
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Decision {
    pub state: i32,
    pub error: i32,
    pub value: Value,
}
impl Decision {
    pub fn success(value: Value) -> Self {
        Self {
            state: TaskState::Succeeded as i32,
            error: 0,
            value,
        }
    }
    pub fn task(&self, id: &str) -> Result<TaskResult> {
        Ok(TaskResult {
            command_id: id.into(),
            state: self.state,
            error: self.error,
            result_json: serde_json::to_vec(&self.value)?,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Bound {
    schema: u32,
    binding: Binding,
    plan_id: String,
    result: Decision,
}
impl Native {
    fn decision_path(&self, id: &str) -> PathBuf {
        self.state().join("commands").join(format!("{id}.json"))
    }
    pub(super) fn record(
        &self,
        j: &mut Journal,
        binding: Option<&Binding>,
        result: Decision,
    ) -> Result<()> {
        if let Some(b) = binding {
            ensure!(
                b.valid()
                    && j.command_decisions.len() < 2
                    && !j.command_decisions.contains_key(&b.command_id),
                "CONFLICT: system command decision identity/quota"
            );
            let bytes = serde_json::to_vec(&Bound {
                schema: 1,
                binding: b.clone(),
                plan_id: j.id.clone(),
                result: result.clone(),
            })?;
            durable::publish_new(
                &self.decision_path(&b.command_id),
                &bytes,
                FileMetadata::private(),
            )?;
            j.command_decisions
                .insert(b.command_id.clone(), durable::hash(&bytes));
        }
        j.outcome = Some(result);
        Ok(())
    }
    pub(super) fn validate_links(&self, j: &Journal) -> Result<()> {
        ensure!(
            j.command_decisions.len() <= 2
                && j.issued_command
                    .as_ref()
                    .is_none_or(|b| b.valid() && matches!(b.operation, 25 | 27) && j.issued),
            "CONFLICT: system command links"
        );
        for (id, hash) in &j.command_decisions {
            ensure!(
                canonical(id) && super::hash(hash),
                "CONFLICT: system command reference"
            );
            let bytes = private(&self.decision_path(id), 1 << 20)?;
            let d: Bound = serde_json::from_slice(&bytes)?;
            ensure!(
                durable::hash(&bytes) == *hash
                    && d.schema == 1
                    && d.binding.valid()
                    && d.binding.command_id == *id
                    && d.plan_id == j.id
                    && (!matches!(d.binding.operation, 25 | 27)
                        || j.issued_command.as_ref() == Some(&d.binding)),
                "CONFLICT: system command evidence changed"
            );
        }
        Ok(())
    }
    pub(super) fn prepare_value(j: &Journal) -> Value {
        let mut j = j.clone();
        j.state = State::Prepared;
        j.issued = false;
        j.issued_command = None;
        j.issued_at = None;
        j.request_accepted = false;
        j.scheduled_unit = None;
        j.after = None;
        j.after_boot_id = None;
        j.observation = None;
        j.error = None;
        let mut v = j.status();
        v["confirmToken"] = json!(j.token);
        v["grantSha256"] = json!(j.config_sha256);
        v["unitDefinitionSha256"] = json!(j.definition_sha256);
        v["componentPids"] = json!(j.profile.as_ref().map(|p| &p.component_pids));
        v["checkIds"] = json!(j.profile.as_ref().map(|p| &p.check_ids));
        v
    }
    pub(super) fn final_decision(j: &Journal) -> Result<Decision> {
        ensure!(
            j.issued
                && j.request_accepted
                && j.issued_at.is_some()
                && j.after_boot_id.as_ref().is_some_and(|s| canonical(s)),
            "CONFLICT: system action acknowledgement missing"
        );
        let reboot =
            j.action == Action::Reboot && j.after_boot_id.as_deref() != Some(&j.before_boot_id);
        let restarted = j
            .after
            .as_ref()
            .is_some_and(|u| u.running() && u.invocation_id != j.before.invocation_id)
            && match j.action {
                Action::Restart => j.after_boot_id.as_deref() == Some(&j.before_boot_id),
                Action::Reboot => reboot,
            };
        ensure!(
            match j.action {
                Action::Restart => restarted,
                Action::Reboot => reboot,
            },
            "CONFLICT: actual process/host transition missing"
        );
        let observed = j
            .observation
            .as_ref()
            .context("CONFLICT: application verification stage missing")?;
        let verified = observed["verified"] == true;
        if verified {
            ensure!(
                j.profile.is_some() && restarted,
                "CONFLICT: application proof scope"
            );
            let report: crate::ordinary_observation::Report =
                serde_json::from_value(observed["report"].clone())?;
            j.probe
                .as_ref()
                .context("CONFLICT: original application challenge missing")?
                .validate(&report, j.after.as_ref().unwrap().pid)?;
            ensure!(
                report.schema == 2
                    && report.ready
                    && report.providers.iter().all(|p| p.available && p.unique)
                    && report.checks.iter().all(|c| c.passed),
                "CONFLICT: selected application checks unproven"
            );
        }
        let passed = restarted && (j.profile.is_none() || verified);
        let mut value = j.status();
        value["state"] = json!(State::Completed);
        value["stage"] = json!(if j.action == Action::Reboot {
            "HOST_REBOOT_OBSERVED"
        } else {
            "SERVICE_RESTART_OBSERVED"
        });
        value["processRestartVerified"] = json!(restarted);
        value["hostRebootVerified"] = json!(reboot);
        value["applicationVerified"] = json!(verified);
        value["application"] = observed.clone();
        Ok(Decision {
            state: if passed {
                TaskState::Succeeded
            } else {
                TaskState::Failed
            } as i32,
            error: if passed {
                ErrorCode::Unspecified
            } else {
                ErrorCode::KuraUnavailable
            } as i32,
            value,
        })
    }
    fn proof(&self, command: &ReadCommand) -> Result<Decision> {
        let binding = Binding::from_command(command)?;
        let decision_path = self.decision_path(&binding.command_id);
        let decision_bytes = private(&decision_path, 1 << 20)?;
        let d: Bound = serde_json::from_slice(&decision_bytes)?;
        ensure!(
            d.schema == 1
                && d.binding == binding
                && d.plan_id.strip_prefix("system-").is_some_and(canonical),
            "CONFLICT: original system decision identity"
        );
        let current_bytes = private(&self.path(), 1 << 20)?;
        let current: Journal = serde_json::from_slice(&current_bytes)?;
        let path = if current.id == d.plan_id {
            self.path()
        } else {
            self.state()
                .join("history")
                .join(format!("{}.json", d.plan_id))
        };
        let bytes = private(&path, 1 << 20)?;
        let j: Journal = serde_json::from_slice(&bytes)?;
        ensure!(
            j.schema == 1
                && j.id == d.plan_id
                && j.command_decisions.get(&binding.command_id)
                    == Some(&durable::hash(&decision_bytes)),
            "CONFLICT: unlinked original system decision"
        );
        self.validate_links(&j)?;
        let config_bytes = private(&self.file(&j.id, ".config.json"), 512 << 10)?;
        let config: Config = serde_json::from_slice(&config_bytes)?;
        config.bounds()?;
        ensure!(
            durable::hash(&config_bytes) == j.config_sha256
                && config.unit == j.unit
                && config.unit_definition_sha256 == j.definition_sha256
                && canonical(&j.before_boot_id),
            "CONFLICT: archived fixed system grant"
        );
        let expected = match command.operation {
            24 | 26 => {
                ensure!(
                    j.action
                        == if command.operation == 24 {
                            Action::Restart
                        } else {
                            Action::Reboot
                        },
                    "CONFLICT: original system action"
                );
                Decision::success(Self::prepare_value(&j))
            }
            28 => {
                let a = command.system_control_action.as_ref().unwrap();
                ensure!(
                    a.transaction_id == j.id
                        && a.confirmation_token == j.token
                        && j.state == State::Cancelled
                        && !j.issued,
                    "CONFLICT: cancellation not committed"
                );
                Decision::success(j.status())
            }
            25 | 27 => {
                let a = command.system_control_action.as_ref().unwrap();
                ensure!(
                    j.state == State::Completed
                        && j.issued_command.as_ref() == Some(&binding)
                        && a.transaction_id == j.id
                        && a.confirmation_token == j.token
                        && j.action
                            == if command.operation == 25 {
                                Action::Restart
                            } else {
                                Action::Reboot
                            },
                    "CONFLICT: original system execution is not committed"
                );
                let receipt = private(&self.file(&j.id, ".completed.json"), 1 << 20)?;
                let expected = Self::final_decision(&j)?;
                ensure!(
                    j.receipt_sha256.as_ref() == Some(&durable::hash(&receipt))
                        && j.outcome.as_ref() == Some(&expected)
                        && receipt == serde_json::to_vec(&expected)?,
                    "CONFLICT: system completion receipt changed"
                );
                expected
            }
            _ => anyhow::bail!("INVALID_ARGUMENT"),
        };
        ensure!(
            expected == d.result
                && private(&decision_path, 1 << 20)? == decision_bytes
                && private(&path, 1 << 20)? == bytes
                && private(&self.path(), 1 << 20)? == current_bytes
                && private(&self.file(&j.id, ".config.json"), 512 << 10)? == config_bytes,
            "CONFLICT: system outcome evidence drift"
        );
        let mut result = d.result;
        result.value["reconciliation"] = json!({"source":"system.control.journal.v1","commandId":binding.command_id,"operation":binding.operation,
            "requestSha256":binding.request_sha256,"transactionId":j.id,"journalSha256":durable::hash(&bytes),"decisionSha256":durable::hash(&decision_bytes)});
        Ok(result)
    }
    pub(super) fn commit_result(&self, j: &mut Journal) -> Result<Value> {
        let result = Self::final_decision(j)?;
        let bytes = serde_json::to_vec(&result)?;
        durable::publish_new(
            &self.file(&j.id, ".completed.json"),
            &bytes,
            FileMetadata::private(),
        )?;
        j.receipt_sha256 = Some(durable::hash(&bytes));
        j.state = State::Completed;
        let binding = j.issued_command.clone();
        self.record(j, binding.as_ref(), result.clone())?;
        self.persist(j)?;
        Ok(result.value)
    }
    pub(super) fn recover_completed(&self, j: &mut Journal) -> Result<()> {
        let bytes = private(&self.file(&j.id, ".completed.json"), 1 << 20)?;
        let result = Self::final_decision(j)?;
        ensure!(
            bytes == serde_json::to_vec(&result)?,
            "CONFLICT: system completion evidence changed"
        );
        if let Some(binding) = j.issued_command.clone() {
            let p = self.decision_path(&binding.command_id);
            if p.try_exists()? {
                let raw = private(&p, 1 << 20)?;
                let d: Bound = serde_json::from_slice(&raw)?;
                ensure!(
                    d.schema == 1
                        && d.binding == binding
                        && d.plan_id == j.id
                        && d.result == result,
                    "CONFLICT: retained system decision changed"
                );
                j.command_decisions
                    .insert(binding.command_id, durable::hash(&raw));
            } else {
                self.record(j, Some(&binding), result.clone())?;
            }
        }
        j.state = State::Completed;
        j.outcome = Some(result);
        j.receipt_sha256 = Some(durable::hash(&bytes));
        self.persist(j)
    }
}
impl Control {
    pub(crate) async fn prove(&self, command: &ReadCommand) -> Result<Option<TaskResult>> {
        if !matches!(command.operation, 24..=28) {
            return Ok(None);
        }
        let n = self.native.clone();
        let command = command.clone();
        tokio::task::spawn_blocking(move || {
            let Ok(result) = n.proof(&command) else {
                return Ok(None);
            };
            Ok(Some(result.task(&command.command_id)?))
        })
        .await?
    }
    pub(crate) async fn command_result(
        &self,
        command: &ReadCommand,
        value: Value,
    ) -> Result<TaskResult> {
        if !matches!(command.operation, 25 | 27) {
            return Decision::success(value).task(&command.command_id);
        }
        if command.operation == 27 && value["state"] == "AWAITING_BOOT" {
            return Ok(TaskResult {
                command_id: command.command_id.clone(),
                state: TaskState::Unknown as i32,
                error: ErrorCode::OutcomeUnknown as i32,
                result_json: serde_json::to_vec(&value)?,
            });
        }
        let n = self.native.clone();
        let id = command.command_id.clone();
        tokio::task::spawn_blocking(move || {
            let j = n
                .journal()?
                .context("OUTCOME_UNKNOWN: missing system decision")?;
            let decision = j
                .outcome
                .context("OUTCOME_UNKNOWN: no completed system outcome")?;
            decision.task(&id)
        })
        .await?
    }
}
