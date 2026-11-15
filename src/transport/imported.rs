//! Authenticated center task bridge into the SAME imported producer. Never uses
//! the private firewall's prepare/apply/commit path or caller-selected OS identity.
use super::*;
use crate::journal::imported::connection;
use crate::nm::handover::initialization::producer::principal::RemotePrincipal;
use prost::Message;
use yofc_management_protocol::imported::{DecisionEvidence, Envelope, Request};

pub(super) fn write_grant(local: &Local) -> bool {
    local.firewall_remote && local.kura_firewall_write
}
pub(super) fn authority(local: &Local) -> Result<String> {
    let view = local
        .remote
        .as_ref()
        .context("UNSUPPORTED: no remote binding")?
        .status();
    ensure!(
        view["bound"] == true && view["enabled"] == true && view["recoveryRequired"] == false,
        "FORBIDDEN: remote authority unavailable"
    );
    let endpoint = view["endpoint"].as_str().context("FORBIDDEN: endpoint")?;
    let gateway = view["gatewayId"].as_str().context("FORBIDDEN: gateway")?;
    let generation = view["bindingGeneration"]
        .as_str()
        .context("FORBIDDEN: binding generation")?;
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&[
            "firewall.imported.original.v1",
            endpoint,
            gateway,
            generation
        ])?)
    ))
}
fn current_connection(local: &Local) -> Result<Option<String>> {
    Ok(local
        .management_connection
        .lock()
        .map_err(|_| anyhow::anyhow!("CONFLICT: management connection state poisoned"))?
        .clone())
}
fn service_uid() -> Result<u32> {
    // Actual process identity; neither the browser nor the center supplies it.
    let uid = unsafe { libc::geteuid() };
    ensure!(
        uid <= i32::MAX as u32,
        "FORBIDDEN: agent service identity out of range"
    );
    Ok(uid)
}
async fn execute(
    db: &SqlitePool,
    local: &Local,
    command: &ReadCommand,
    hash: &str,
    session: &str,
) -> Result<serde_json::Value> {
    let authority = authority(local)?;
    let envelope = Envelope::from_wire(
        command
            .imported_firewall
            .as_ref()
            .context("INVALID_ARGUMENT")?,
        command.operation,
    )?;
    let uid = service_uid()?;
    let firewall = local
        .firewall
        .as_ref()
        .context("UNSUPPORTED: firewall observer unavailable")?;
    let grant = write_grant(local);
    if matches!(command.operation, 40..=44 | 47) {
        if command.operation != 44 {
            ensure!(grant, "FORBIDDEN: imported remote write grant disabled");
        }
        journal::imported::bind(db, command, &authority, hash).await?;
    }
    let mut connection_verified = false;
    let (mut receipt, original_id, original_hash, evidence) = if let Some(id) =
        envelope.request.original_task()
    {
        let target = journal::imported::load(db, &id.to_string(), &authority).await?;
        let target_envelope = Envelope::from_wire(
            target
                .command
                .imported_firewall
                .as_ref()
                .context("CONFLICT")?,
            target.command.operation,
        )?;
        let query = matches!(
            envelope.request,
            Request::Outcome { .. } | Request::SourceOutcome { .. }
        );
        let original = if let Some(parent) = target_envelope.request.original_task() {
            ensure!(
                query && matches!(target.command.operation, 41..=44),
                "CONFLICT: action must name its original preparation"
            );
            journal::imported::load(db, &parent.to_string(), &authority).await?
        } else {
            journal::imported::load(db, &target.command.command_id, &authority).await?
        };
        let original_envelope = Envelope::from_wire(
            original
                .command
                .imported_firewall
                .as_ref()
                .context("CONFLICT")?,
            original.command.operation,
        )?;
        let observation = matches!(envelope.request, Request::SourceOutcome { .. });
        ensure!(
            original.command.operation == if observation { 47 } else { 40 },
            "CONFLICT: original imported operation family"
        );
        let method = if observation {
            "firewall.kura.imported.remote.source.outcome"
        } else {
            "firewall.kura.imported.remote.outcome"
        };
        let bundle = firewall
            .imported_metadata_request(
                method.into(),
                json!({
            "originalRequestId":original.request_id,"change":original_envelope.original_input()?}),
                uid,
            )
            .await?;
        let outcome = bundle["receipt"].clone();
        if !observation && outcome["state"] == "WAIT_CONFIRM" {
            let audit: DecisionEvidence =
                serde_json::from_value(bundle["decisionEvidence"].clone())?;
            let current = current_connection(local)?;
            connection::note_ack(
                db,
                &original,
                &audit,
                current
                    .as_deref()
                    .context("CONFLICT: authenticated management connection unavailable")?,
                journal::now(),
            )
            .await?;
            connection_verified =
                connection::ready(db, &original, session, current.as_deref(), journal::now())
                    .await?;
        }
        if query && target.command.operation == 42 {
            connection_verified = connection::confirmed(db, &original, &target).await?;
        }
        let receipt = if matches!(
            envelope.request,
            Request::Outcome { .. } | Request::SourceOutcome { .. }
        ) {
            outcome
        } else {
            let admitted = journal::imported::load(db, &command.command_id, &authority).await?;
            let principal = RemotePrincipal::for_action(&original, &admitted)?;
            if command.operation == 42 {
                ensure!(
                    grant && outcome["state"] == "WAIT_CONFIRM" && connection_verified,
                    "CONFLICT: new management connection required before confirmation"
                );
                let current = current_connection(local)?;
                connection::record_confirmation(
                    db,
                    &original,
                    &admitted,
                    session,
                    current.as_deref(),
                    journal::now(),
                )
                .await?;
            }
            let action = json!({"originalRequestId":original.request_id,
                "ownerKey":original_envelope.owner_key.as_ref().context("CONFLICT")?,
                "id":original_envelope.request.original_operation().context("CONFLICT")?,
                "confirmationToken":outcome["confirmationToken"].as_str().context("OUTCOME_UNKNOWN: original token unavailable")?});
            let applied = if matches!(envelope.request, Request::Cancel { .. }) {
                // A pre-dispatch cancellation needs its original capability,
                // not a fresh write grant or a running JVM.
                firewall.imported_remote_cancel(action, principal).await?
            } else {
                ensure!(grant, "FORBIDDEN: imported remote write grant disabled");
                local
                    .nm
                    .as_ref()
                    .context("UNSUPPORTED: NM coordinator unavailable")?
                    .imported_firewall_remote_request(
                        envelope.request.method().into(),
                        action,
                        principal,
                        grant,
                    )
                    .await?
            };
            if command.operation == 41 && applied["state"] == "WAIT_CONFIRM" {
                let checked=firewall.imported_metadata_request(method.into(),json!({"originalRequestId":original.request_id,"change":original_envelope.original_input()?}),uid).await?;
                if checked["receipt"]["state"] == "WAIT_CONFIRM" {
                    let audit: DecisionEvidence =
                        serde_json::from_value(checked["decisionEvidence"].clone())?;
                    let current = current_connection(local)?;
                    connection::note_ack(
                        db,
                        &original,
                        &audit,
                        current
                            .as_deref()
                            .context("CONFLICT: authenticated management connection unavailable")?,
                        journal::now(),
                    )
                    .await?;
                    connection_verified = connection::ready(
                        db,
                        &original,
                        session,
                        current.as_deref(),
                        journal::now(),
                    )
                    .await?;
                }
                checked["receipt"].clone()
            } else {
                applied
            }
        };
        (
            receipt,
            Some(target.command.command_id.clone()),
            Some(format!(
                "{:x}",
                Sha256::digest(target.command.encode_to_vec())
            )),
            if query {
                bundle["decisionEvidence"].clone()
            } else {
                serde_json::Value::Null
            },
        )
    } else if matches!(envelope.request, Request::View) {
        (
            firewall
                .imported_metadata_request(envelope.request.method().into(), json!({}), uid)
                .await?,
            None,
            None,
            serde_json::Value::Null,
        )
    } else {
        if envelope.request.needs_owner_key() {
            ensure!(grant, "FORBIDDEN: imported remote write grant disabled");
        }
        let nm = local
            .nm
            .as_ref()
            .context("UNSUPPORTED: NM coordinator unavailable")?;
        let receipt = if envelope.request.needs_owner_key() {
            let original = journal::imported::load(db, &command.command_id, &authority).await?;
            nm.imported_firewall_remote_request(
                envelope.request.method().into(),
                envelope.original_input()?,
                RemotePrincipal::authenticated(&original)?,
                grant,
            )
            .await?
        } else {
            nm.imported_firewall_remote_review(
                envelope.request.method().into(),
                envelope.original_input()?,
                command.command_id.clone(),
            )
            .await?
        };
        let original = envelope.request.needs_owner_key();
        (
            receipt,
            original.then(|| command.command_id.clone()),
            original.then(|| hash.into()),
            serde_json::Value::Null,
        )
    };
    // The agent retains capabilities; browser-visible receipts carry only
    // value-free original correlation and the checked business projection.
    if let Some(object) = receipt.as_object_mut() {
        object.remove("confirmationToken");
    }
    let now = crate::journal::now() as u64;
    let actionable = grant
        && connection_verified
        && receipt["state"] == "WAIT_CONFIRM"
        && receipt["deadlineUnixMs"]
            .as_u64()
            .is_some_and(|deadline| deadline > now);
    Ok(
        json!({"schemaVersion":1,"operation":command.operation,"originalTaskId":original_id,
        "originalCommandSha256":original_hash,"writeEnabled":grant,"confirmationReady":actionable,"newManagementConnectionVerified":connection_verified,"receipt":receipt,"decisionEvidence":evidence}),
    )
}
pub(super) async fn perform(
    db: &SqlitePool,
    local: &Local,
    command: &ReadCommand,
    hash: &str,
    session: &str,
) -> Result<TaskResult> {
    let mut state = TaskState::Succeeded;
    let mut error = ErrorCode::Unspecified;
    let data = if crate::journal::now() >= command.expires_at_unix_ms {
        state = TaskState::Expired;
        error = ErrorCode::Timeout;
        json!({})
    } else if !command.valid_payload() {
        state = TaskState::Failed;
        error = ErrorCode::InvalidArgument;
        json!({})
    } else {
        match execute(db, local, command, hash, session).await {
            Ok(value) => value,
            Err(e) => {
                let code = crate::boot_control::error_code(&e);
                error = ErrorCode::from_str_name(code).unwrap_or(ErrorCode::Internal);
                state = if error == ErrorCode::OutcomeUnknown
                    || (error == ErrorCode::Internal
                        && yofc_management_protocol::has_side_effect(command.operation))
                {
                    error = ErrorCode::OutcomeUnknown;
                    TaskState::Unknown
                } else {
                    TaskState::Failed
                };
                tracing::debug!(
                    code,
                    operation = command.operation,
                    "imported remote task refused"
                );
                json!({})
            }
        }
    };
    Ok(TaskResult {
        command_id: command.command_id.clone(),
        state: state as i32,
        error: error as i32,
        result_json: serde_json::to_vec(&data)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn remote(root: &std::path::Path, generation: u64) -> crate::remote::Remote {
        crate::remote::Remote::open(
            root.into(),
            true,
            Some((
                "https://center.invalid".into(),
                "owned-gateway".into(),
                generation,
            )),
        )
        .unwrap()
    }
    #[test]
    fn imported_reconnect_is_limited_to_ack_waiting_apply_or_original_query_without_connection() {
        let result = |state, ready, verified| TaskResult {
            command_id: uuid::Uuid::new_v4().to_string(),
            state,
            error: 0,
            result_json: serde_json::to_vec(
                &json!({"receipt":{"state":"WAIT_CONFIRM","deadlineExpired":false,"deadlineUnixMs":journal::now()+120000},"writeEnabled":true,
                "confirmationReady":ready,"newManagementConnectionVerified":verified}),
            )
            .unwrap(),
        };
        assert!(super::super::needs_reconnect(
            &result(TaskState::Succeeded as i32, false, false),
            false,
            true
        ));
        assert!(!super::super::needs_reconnect(
            &result(TaskState::Unknown as i32, false, false),
            false,
            true
        ));
        assert!(!super::super::needs_reconnect(
            &result(TaskState::Succeeded as i32, true, true),
            false,
            true
        ));
        assert!(!super::super::needs_reconnect(
            &result(TaskState::Succeeded as i32, false, false),
            false,
            false
        ));
    }
    #[tokio::test]
    async fn cached_imported_receipt_uses_original_binding_even_with_writes_off_and_no_jvm() {
        let root = std::env::temp_dir().join(format!(
            "imported-receipt-authority-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root).unwrap();
        let db = crate::transport::database(root.join("state.sqlite").to_str().unwrap())
            .await
            .unwrap();
        let mut local = Local::new(1000, 1001);
        local.remote = Some(remote(&root.join("first"), 7));
        assert!(!write_grant(&local));
        assert!(local.nm.is_none());
        assert!(local.firewall.is_none());
        let envelope = Envelope {
            request: Request::View,
            owner_key: None,
        };
        let command = ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation: 38,
            idempotency_key: "read-original".into(),
            expires_at_unix_ms: i64::MAX,
            imported_firewall: Some(envelope.to_wire().unwrap()),
            ..Default::default()
        };
        let hash = format!("{:x}", Sha256::digest(command.encode_to_vec()));
        let authority = authority(&local).unwrap();
        journal::bind_firewall_authority(&db, &command.command_id, &authority, &hash)
            .await
            .unwrap();
        journal::claim(&db, &command, &hash).await.unwrap();
        let result = TaskResult {
            command_id: command.command_id.clone(),
            state: TaskState::Succeeded as i32,
            error: 0,
            result_json: serde_json::to_vec(&json!({"receipt":{"sourceDigest":"a".repeat(64)}}))
                .unwrap(),
        };
        journal::finish(&db, &hash, result.clone()).await.unwrap();
        assert_eq!(
            crate::transport::query_receipt(&db, &local, &command.command_id)
                .await
                .unwrap(),
            result
        );
        local.remote = Some(remote(&root.join("second"), 8));
        let refused = crate::transport::query_receipt(&db, &local, &command.command_id)
            .await
            .unwrap();
        assert_eq!(refused.state, TaskState::Unknown as i32);
        assert!(
            !String::from_utf8(refused.result_json)
                .unwrap()
                .contains("sourceDigest")
        );
        db.close().await;
        std::fs::remove_dir_all(root).unwrap();
    }
}
