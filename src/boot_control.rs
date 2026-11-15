//! Optional fixed local authority shared by administrative UDS and bound-center tasks.
use crate::ordinary_boot::{Boot, CommandBinding};
use anyhow::{Result, ensure};
use serde_json::Value;
use sqlx::SqlitePool;
use std::path::PathBuf;
use yofc_management_protocol::v1::{
    ErrorCode, OrdinaryBootAction, ReadCommand, TaskResult, TaskState,
};

pub fn error_code(error: &anyhow::Error) -> &'static str {
    if error.to_string().starts_with("OUTCOME_UNKNOWN") {
        "OUTCOME_UNKNOWN"
    } else {
        crate::network::error_code(error)
    }
}

#[derive(Clone)]
pub struct Control {
    boot: Boot,
    request: PathBuf,
    db: SqlitePool,
}
impl Control {
    pub fn new(root: PathBuf, request: PathBuf, db: SqlitePool) -> Result<Self> {
        Boot::validate_request_file(&request)?;
        Ok(Self {
            boot: Boot::new(root)?,
            request,
            db,
        })
    }
    #[cfg(test)]
    pub(crate) fn fixture(boot: Boot, request: PathBuf, db: SqlitePool) -> Self {
        Self { boot, request, db }
    }
    pub async fn request(
        &self,
        method: &str,
        params: Value,
        command: Option<&ReadCommand>,
    ) -> Result<Value> {
        let operation = match method {
            "ordinary.boot.status" => 15,
            "ordinary.boot.prepare" => 16,
            "ordinary.boot.execute" => 17,
            "ordinary.boot.cancel" => 18,
            "ordinary.boot.reconcile" => 19,
            _ => anyhow::bail!("UNSUPPORTED"),
        };
        let action = if matches!(operation, 17 | 18) {
            let action: OrdinaryBootAction =
                serde_json::from_value(params).map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT"))?;
            ensure!(action.valid(), "INVALID_ARGUMENT");
            Some(action)
        } else {
            ensure!(
                params.is_null() || params == serde_json::json!({}),
                "INVALID_ARGUMENT"
            );
            None
        };
        let binding = if operation != 15 {
            command.map(CommandBinding::from_command).transpose()?
        } else {
            None
        };
        if let Some(c) = command {
            ensure!(
                c.operation == operation
                    && c.valid_payload()
                    && c.ordinary_boot_action.as_ref() == action.as_ref(),
                "INVALID_ARGUMENT"
            );
        }
        if operation != 15 {
            // Cancellation/reconciliation may settle a boot uncertainty. They
            // still cannot outrun unrelated admitted or uncertain system work.
            let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM executions WHERE command_id<>? AND state IN ('RUNNING','UNKNOWN') AND operation NOT IN (1,2,3,4,8,9,11,15,20,23) AND (?=0 OR operation NOT BETWEEN 16 AND 19))")
                .bind(command.map(|c| c.command_id.as_str()).unwrap_or("")).bind(i32::from(matches!(operation, 18 | 19)))
                .fetch_one(&self.db).await?;
            ensure!(!pending, "CONFLICT: unresolved admitted system operation");
        }
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let before = this.boot.view()?;
            let result = match operation {
                15 => return Ok(before),
                16 => this.boot.prepare_bound(&this.request, binding.as_ref()),
                17 => {
                    let a = action.as_ref().unwrap();
                    this.boot.execute_bound(
                        &a.transaction_id,
                        &a.confirmation_token,
                        binding.as_ref(),
                    )
                }
                18 => {
                    let a = action.as_ref().unwrap();
                    this.boot.cancel_bound(
                        &a.transaction_id,
                        &a.confirmation_token,
                        binding.as_ref(),
                    )
                }
                _ => this.boot.reconcile_bound(binding.as_ref()),
            };
            result.map_err(|error| {
                // A changed or unreadable durable decision cannot become a
                // definite failed command. Receipt queries never replay it.
                match this.boot.view() {
                    Ok(after) if after == before => error,
                    _ => anyhow::anyhow!("OUTCOME_UNKNOWN: boot decision changed or is unproven"),
                }
            })
        })
        .await?
    }
    pub async fn prove(&self, command: &ReadCommand) -> Result<Option<TaskResult>> {
        if !matches!(command.operation, 16..=19) {
            return Ok(None);
        }
        let boot = self.boot.clone();
        let command = command.clone();
        // Missing, legacy, changed or unsafe evidence stays UNKNOWN. A query never repairs it.
        tokio::task::spawn_blocking(move || {
            let Ok(Some(value)) = boot.prove_command(&command) else {
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
