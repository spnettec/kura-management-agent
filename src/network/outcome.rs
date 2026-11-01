//! Prove retained network outcomes without applying, confirming or rolling back.
use super::*;
use yofc_management_protocol::v1::{ErrorCode, Operation, ReadCommand, TaskResult, TaskState};

impl Network {
    pub async fn prove_outcome(&self, command: &ReadCommand) -> Result<Option<TaskResult>> {
        let this = self.clone();
        let command = command.clone();
        tokio::task::spawn_blocking(move || {
            // Do not observe a system operation halfway through a durable write.
            let Ok(engine) = this.0.try_lock() else {
                return Ok(None);
            };
            engine.prove_outcome(&command)
        })
        .await?
    }
}

impl Engine {
    fn outcome_journal(&self, command: &ReadCommand) -> Result<Option<(Journal, Vec<u8>)>> {
        let prepare = matches!(command.operation, 5 | 10);
        let path = if prepare {
            self.state.join(format!(
                "receipt-{}.json",
                hash(command.command_id.as_bytes())
            ))
        } else {
            let Some(action) = &command.network_action else {
                return Ok(None);
            };
            if Uuid::parse_str(&action.transaction_id).is_err() {
                return Ok(None);
            }
            self.state
                .join(format!("transaction-{}.json", action.transaction_id))
        };
        // The current journal is authoritative. Archived receipts are needed
        // only once a newer transaction has replaced it.
        for candidate in [self.state.join("transaction.json"), path] {
            if !candidate.try_exists()? {
                continue;
            }
            let bytes = read(&candidate)?;
            let journal: Journal = serde_json::from_slice(&bytes)?;
            let matches = if prepare {
                journal.key == command.command_id
            } else {
                command
                    .network_action
                    .as_ref()
                    .is_some_and(|a| a.transaction_id == journal.id)
            };
            if matches {
                return Ok(Some((journal, bytes)));
            }
        }
        Ok(None)
    }

    pub(super) fn prove_outcome(&self, command: &ReadCommand) -> Result<Option<TaskResult>> {
        let Ok(
            op @ (Operation::NetworkPrepare
            | Operation::NetworkTakeoverPrepare
            | Operation::NetworkConfirm
            | Operation::NetworkRollback),
        ) = Operation::try_from(command.operation)
        else {
            return Ok(None);
        };
        ensure!(
            Uuid::parse_str(&command.command_id).is_ok(),
            "INVALID_ARGUMENT"
        );
        let Some((journal, bytes)) = self.outcome_journal(command)? else {
            return Ok(None);
        };
        // Only a terminal, internally consistent business outcome can close an
        // interrupted admission. RECOVERY_REQUIRED and incomplete decisions stay UNKNOWN.
        let committed = journal.state == "COMMITTED" && journal.confirmed_decision;
        let rolled_back = journal.state == "ROLLED_BACK" && !journal.confirmed_decision;
        if !committed && !rolled_back {
            return Ok(None);
        }
        let matched = match op {
            Operation::NetworkPrepare => {
                journal.transfer.is_none()
                    && command
                        .network_change
                        .as_ref()
                        .map(|v| serde_json::to_vec(v))
                        .transpose()?
                        .is_some_and(|v| journal.request_hash == hash(&v))
            }
            Operation::NetworkTakeoverPrepare => {
                journal.transfer.is_some()
                    && command
                        .network_takeover
                        .as_ref()
                        .map(|v| serde_json::to_vec(v))
                        .transpose()?
                        .is_some_and(|v| journal.request_hash == hash(&v))
            }
            Operation::NetworkConfirm => {
                committed
                    && journal.confirmation_command.as_deref() == Some(command.command_id.as_str())
                    && command.network_action.as_ref().is_some_and(|a| {
                        !a.confirmation_token.is_empty() && a.confirmation_token == journal.token
                    })
            }
            Operation::NetworkRollback => {
                rolled_back
                    && journal.rollback_command.as_deref() == Some(command.command_id.as_str())
            }
            _ => false,
        };
        if !matched {
            return Ok(None);
        }
        let succeeded = !matches!(
            op,
            Operation::NetworkPrepare | Operation::NetworkTakeoverPrepare
        ) || committed;
        let mut value = self.view(&journal);
        value["reconciliation"] = json!({
            "source":"network.journal.v1", "commandId":command.command_id,
            "transactionId":journal.id, "operation":command.operation,
            "state":journal.state, "journalSha256":hash(&bytes), "observedAtUnixMs":now(),
        });
        Ok(Some(TaskResult {
            command_id: command.command_id.clone(),
            state: if succeeded {
                TaskState::Succeeded
            } else {
                TaskState::Failed
            } as i32,
            error: if succeeded {
                ErrorCode::Unspecified
            } else {
                ErrorCode::Conflict
            } as i32,
            result_json: serde_json::to_vec(&value)?,
        }))
    }
}
