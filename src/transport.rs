use crate::{journal, local::Local};
use anyhow::{Result, ensure};
use rand_core::{OsRng, RngCore};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::{fs, time::Duration};
use tokio::sync::{Semaphore, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
use yofc_management_protocol::{
    MAX_FRAME,
    v1::{agent_frame, console_frame, control_client::ControlClient, *},
};

pub struct Config {
    pub endpoint: String,
    pub gateway: String,
    pub binding_generation: u64,
    pub ca: String,
    pub cert: String,
    pub key: String,
    pub state: String,
    pub boot_id: String,
}
pub async fn database(path: &str) -> Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(2));
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS results(command_id TEXT PRIMARY KEY,operation INTEGER NOT NULL,idempotency_key TEXT NOT NULL,result BLOB NOT NULL,created_at INTEGER NOT NULL)").execute(&pool).await?;
    let columns = sqlx::query("PRAGMA table_info(results)")
        .fetch_all(&pool)
        .await?;
    if !columns
        .iter()
        .any(|r| r.get::<String, _>("name") == "request_hash")
    {
        sqlx::query("ALTER TABLE results ADD COLUMN request_hash TEXT")
            .execute(&pool)
            .await?;
    }
    journal::initialize(&pool).await?;
    Ok(pool)
}
pub async fn run(config: Config, local: Local) -> Result<()> {
    let db = database(&config.state).await?;
    let slots = std::sync::Arc::new(Semaphore::new(2));
    let mut delay = 1;
    loop {
        let started = std::time::Instant::now();
        if let Err(e) = connect(&config, &local, &db, &slots).await {
            tracing::warn!(error=%e,"control disconnected; reconnect scheduled");
        }
        if started.elapsed() > Duration::from_secs(30) {
            delay = 1;
        }
        let jitter = OsRng.next_u32() as u64 % 500;
        tokio::time::sleep(Duration::from_millis(delay * 1000 + jitter)).await;
        delay = (delay * 2).min(30);
    }
}
async fn connect(
    config: &Config,
    local: &Local,
    db: &SqlitePool,
    slots: &std::sync::Arc<Semaphore>,
) -> Result<()> {
    ensure!(
        config.endpoint.starts_with("https://"),
        "HTTPS gRPC endpoint required"
    );
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(fs::read(&config.ca)?))
        .identity(Identity::from_pem(
            fs::read(&config.cert)?,
            fs::read(&config.key)?,
        ));
    let channel = Endpoint::from_shared(config.endpoint.clone())?
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(5))
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_timeout(Duration::from_secs(5))
        .connect()
        .await?;
    let mut client = ControlClient::new(channel)
        .max_decoding_message_size(MAX_FRAME)
        .max_encoding_message_size(MAX_FRAME);
    let (tx, rx) = mpsc::channel(16);
    let mut capabilities = vec![
        "agent.status".into(),
        "task.reconcile.v1".into(),
        "task.network-outcome.v1".into(),
        "task.configuration-outcome.v1".into(),
        "kura.configuration.list".into(),
        "kura.configuration.get".into(),
        "kura.snapshot.list".into(),
        "network.inspect".into(),
        "network.prepare".into(),
        "network.confirm".into(),
        "network.rollback".into(),
        "network.transaction".into(),
        "network.takeover.plan".into(),
        "network.takeover.prepare".into(),
    ];
    if local.configuration_updates_enabled() {
        capabilities.push("kura.configuration.update".into());
    }
    if local.snapshots_enabled() {
        capabilities.push("kura.snapshot.write".into());
    }
    tx.send(AgentFrame {
        payload: Some(agent_frame::Payload::Hello(Hello {
            protocol_major: 1,
            gateway_id: config.gateway.clone(),
            binding_generation: config.binding_generation,
            agent_version: env!("CARGO_PKG_VERSION").into(),
            boot_id: config.boot_id.clone(),
            capabilities,
        })),
    })
    .await?;
    let mut stream = client.connect(ReceiverStream::new(rx)).await?.into_inner();
    let welcome = tokio::time::timeout(Duration::from_secs(5), stream.message())
        .await??
        .ok_or_else(|| anyhow::anyhow!("missing welcome"))?;
    let Some(console_frame::Payload::Welcome(welcome)) = welcome.payload else {
        anyhow::bail!("PROTOCOL_MISMATCH")
    };
    ensure!(
        (1..=10).contains(&welcome.heartbeat_seconds),
        "invalid heartbeat interval"
    );
    tracing::info!(epoch=%welcome.connection_epoch,"control connected");
    let mut heartbeat =
        tokio::time::interval(Duration::from_secs(welcome.heartbeat_seconds as u64));
    let mut sequence = 0;
    let (control_tx, mut control_rx) = mpsc::channel::<anyhow::Error>(4);
    loop {
        tokio::select! {
            _=heartbeat.tick()=>{
                sequence+=1;
                let status=local.status().await;
                tx.try_send(AgentFrame{payload:Some(agent_frame::Payload::Heartbeat(Heartbeat{sequence,kura_available:status["kuraAvailable"].as_bool().unwrap_or(false),uptime_seconds:local.started.elapsed().as_secs()}))})?;
            }
            incoming=stream.message()=>{
                let Some(frame)=incoming? else{break};
                match frame.payload {
                    Some(console_frame::Payload::TaskQuery(query))=>{
                        ensure!(!query.command_ids.is_empty() && query.command_ids.len()<=16,"INVALID_ARGUMENT");
                        for id in query.command_ids {
                            let result=query_receipt(db,local,&id).await?;
                            tx.try_send(AgentFrame{payload:Some(agent_frame::Payload::Result(result))})?;
                        }
                    }
                    Some(console_frame::Payload::Command(command))=>{
                        let Ok(permit)=slots.clone().try_acquire_owned() else{anyhow::bail!("RESOURCE_EXHAUSTED")};
                        let db=db.clone();let local=local.clone();let tx=tx.clone();let session=welcome.connection_epoch.clone();
                        let control=control_tx.clone();
                        // This worker belongs to the process, not this connection.
                        // Losing gRPC must not cancel a system change after admission.
                        tokio::spawn(async move {
                            let _permit=permit;
                            let action=async {
                                let prepare=matches!(command.operation, 5 | 10);
                                let result=execute_in_session(&db,&local,command,&session).await?;
                                let reconnect=prepare && serde_json::from_slice::<serde_json::Value>(&result.result_json).ok().is_some_and(|v|v["state"]=="WAIT_CONFIRM");
                                // A disconnected recipient does not invalidate the durable receipt.
                                if tx.send(AgentFrame{payload:Some(agent_frame::Payload::Result(result))}).await.is_err() {return Ok(());}
                                if reconnect {tokio::time::sleep(Duration::from_millis(500)).await;anyhow::bail!("network candidate requires a fresh management connection");}
                                Ok::<_,anyhow::Error>(())
                            }.await;
                            if let Err(error)=action {let _=control.try_send(error);}
                        });
                    }
                    _=>anyhow::bail!("PROTOCOL_MISMATCH"),
                }
            }
            Some(error)=control_rx.recv()=>{return Err(error);}

        }
    }
    Ok(())
}
#[cfg(test)]
pub async fn execute(db: &SqlitePool, local: &Local, command: ReadCommand) -> Result<TaskResult> {
    execute_in_session(db, local, command, "").await
}

pub(crate) async fn query_receipt(db: &SqlitePool, local: &Local, id: &str) -> Result<TaskResult> {
    let current = journal::receipt(db, id).await?;
    if current.state != TaskState::Unknown as i32 {
        return Ok(current);
    }
    let Some((command, hash)) = journal::pending_plan(db, id).await? else {
        return Ok(current);
    };
    let configuration_write = command.operation == Operation::KuraConfigurationUpdate as i32;
    if let Some(network) = &local.network {
        if !configuration_write {
            if let Some(proof) = network.prove_outcome(&command).await? {
                return journal::resolve(db, &hash, proof).await;
            }
        }
    }
    // A missing journal stays unknown. Current configuration is not evidence.
    if configuration_write {
        if let Some(proof) = crate::configuration_outcome::prove(local, &command).await? {
            return journal::resolve(db, &hash, proof).await;
        }
    }
    Ok(current)
}
async fn execute_in_session(
    db: &SqlitePool,
    local: &Local,
    command: ReadCommand,
    session: &str,
) -> Result<TaskResult> {
    use prost::Message;
    let request_hash = format!("{:x}", Sha256::digest(command.encode_to_vec()));
    ensure!(
        uuid::Uuid::parse_str(&command.command_id).is_ok()
            && !command.idempotency_key.is_empty()
            && command.idempotency_key.len() <= 64,
        "INVALID_ARGUMENT"
    );
    // Hold across journal claim, the UDS call and durable finish. A following
    // configuration write cannot outrun persistence of an uncertain result.
    let _configuration_guard = if command.operation == Operation::KuraConfigurationUpdate as i32
        || command.operation == Operation::KuraSnapshotSave as i32
        || command.operation == Operation::KuraSnapshotRollback as i32
    {
        Some(local.configuration_write_lock.clone().lock_owned().await)
    } else {
        None
    };
    if let Some(r) = sqlx::query(
        "SELECT operation,idempotency_key,result,request_hash FROM results WHERE command_id=?",
    )
    .bind(&command.command_id)
    .fetch_optional(db)
    .await?
    {
        ensure!(
            r.get::<i32, _>("operation") == command.operation
                && r.get::<String, _>("idempotency_key") == command.idempotency_key,
            "CONFLICT"
        );
        ensure!(
            r.get::<Option<String>, _>("request_hash")
                .as_ref()
                .is_some_and(|h| h == &request_hash)
                || (command.operation <= 3 && r.get::<Option<String>, _>("request_hash").is_none()),
            "CONFLICT"
        );
        use tonic::codegen::Bytes;
        use yofc_management_protocol::v1::TaskResult;
        // Protobuf remains the stored result format; no parallel JSON envelope.
        return Ok(<TaskResult as prost::Message>::decode(Bytes::from(
            r.get::<Vec<u8>, _>("result"),
        ))?);
    }
    if let Some(receipt) = journal::claim(db, &command, &request_hash).await? {
        return Ok(receipt);
    }
    // Configuration and snapshot writes share Kura state. An uncertain one blocks the others.
    let unresolved: bool = if matches!(command.operation, 12 | 13 | 14) {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM executions WHERE operation IN (12,13,14) AND command_id<>? AND state IN ('RUNNING','UNKNOWN'))")
            .bind(&command.command_id).fetch_one(db).await?
    } else {
        false
    };
    let result = match if unresolved {
        Ok(TaskResult {
            command_id: command.command_id.clone(),
            state: TaskState::Failed as i32,
            error: ErrorCode::Conflict as i32,
            result_json: b"{}".to_vec(),
        })
    } else {
        perform(local, &command, session).await
    } {
        Ok(result) => result,
        Err(_) if yofc_management_protocol::has_side_effect(command.operation) => {
            journal::unknown(&command.command_id, "EXECUTION_INTERRUPTED")
        }
        Err(_) => TaskResult {
            command_id: command.command_id.clone(),
            state: TaskState::Failed as i32,
            error: ErrorCode::Internal as i32,
            result_json: b"{}".to_vec(),
        },
    };
    journal::finish(db, &request_hash, result).await
}

fn accepted_snapshot_receipt(method: &str, value: &serde_json::Value) -> bool {
    value.get("networkRewound") == Some(&serde_json::json!(false))
        && value.get("snapshotId").and_then(|v| v.as_str()).is_some_and(|id| !id.is_empty())
        && ((method == "kura.snapshot.save" && value.get("saved") == Some(&serde_json::json!(true)))
            || (method == "kura.snapshot.rollback" && value.get("rolledBack") == Some(&serde_json::json!(true))))
}

async fn perform(local: &Local, command: &ReadCommand, session: &str) -> Result<TaskResult> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    let mut state = TaskState::Succeeded;
    let mut error = ErrorCode::Unspecified;
    let result = if now >= command.expires_at_unix_ms {
        state = TaskState::Expired;
        error = ErrorCode::Timeout;
        json!({})
    } else if !command.valid_payload() {
        state = TaskState::Failed;
        error = ErrorCode::InvalidArgument;
        json!({})
    } else {
        match Operation::try_from(command.operation) {
            Ok(Operation::KuraSnapshotSave) | Ok(Operation::KuraSnapshotRollback) => {
                let method = if command.operation == Operation::KuraSnapshotSave as i32 { "kura.snapshot.save" } else { "kura.snapshot.rollback" };
                let params = if command.operation == Operation::KuraSnapshotSave as i32 {
                    command.kura_snapshot_save.as_ref().unwrap().parameters(command.expires_at_unix_ms).unwrap()
                } else {
                    command.kura_snapshot_rollback.as_ref().unwrap().parameters(command.expires_at_unix_ms).unwrap()
                };
                match local.snapshot(method, params).await {
                    Ok(value) if accepted_snapshot_receipt(method, &value) => value,
                    Ok(_) | Err("OUTCOME_UNKNOWN") => {
                        state = TaskState::Unknown;
                        error = ErrorCode::OutcomeUnknown;
                        json!({})
                    }
                    Err(code) => {
                        state = TaskState::Failed;
                        error = match code {
                            "INVALID_ARGUMENT" => ErrorCode::InvalidArgument,
                            "CONFLICT" => ErrorCode::Conflict,
                            "FORBIDDEN" => ErrorCode::Forbidden,
                            "NOT_FOUND" => ErrorCode::NotFound,
                            "UNSUPPORTED" => ErrorCode::Unsupported,
                            "RESOURCE_EXHAUSTED" => ErrorCode::ResourceExhausted,
                            "TIMEOUT" => ErrorCode::Timeout,
                            _ => ErrorCode::KuraUnavailable,
                        };
                        json!({})
                    }
                }
            }
            Ok(Operation::KuraConfigurationUpdate) => {
                let input = command.kura_configuration_update.as_ref().unwrap();
                let mut params = input.parameters(command.expires_at_unix_ms).unwrap();
                params["commandId"] = json!(command.command_id);
                let response = if serde_json::to_vec(&params).map(|v| v.len()).unwrap_or(usize::MAX) > 16384 {
                    // Definite rejection before the bridge queue, while keeping the journal terminal.
                    Err("INVALID_ARGUMENT")
                } else {
                    local.update_configuration(params).await
                };
                match response {
                    Ok(value)
                        if value["pid"] == input.pid
                            && value["submitted"] == true
                            && value["previousRevision"] == input.expected_revision =>
                    {
                        // The bridge must not smuggle sensitive fields into task receipts.
                        json!({"pid":input.pid,"submitted":true,"previousRevision":input.expected_revision})
                    }
                    Ok(_) | Err("OUTCOME_UNKNOWN") => {
                        state = TaskState::Unknown;
                        error = ErrorCode::OutcomeUnknown;
                        json!({})
                    }
                    Err(code) => {
                        state = TaskState::Failed;
                        error = match code {
                            "INVALID_ARGUMENT" => ErrorCode::InvalidArgument,
                            "CONFLICT" => ErrorCode::Conflict,
                            "FORBIDDEN" => ErrorCode::Forbidden,
                            "NOT_FOUND" => ErrorCode::NotFound,
                            "UNSUPPORTED" => ErrorCode::Unsupported,
                            "RESOURCE_EXHAUSTED" => ErrorCode::ResourceExhausted,
                            "TIMEOUT" => ErrorCode::Timeout,
                            _ => ErrorCode::KuraUnavailable,
                        };
                        json!({})
                    }
                }
            }
            Ok(Operation::AgentStatus) => local.status().await,
            Ok(Operation::KuraConfigurationList)
            | Ok(Operation::KuraSnapshotList)
            | Ok(Operation::KuraConfigurationGet) => {
                let method = match command.operation {
                    2 => "kura.configuration.list",
                    3 => "kura.snapshot.list",
                    _ => "kura.configuration.get",
                };
                let response = if command.operation == 11 {
                    match command.kura_configuration.as_ref() {
                        Some(target) if target.valid() => {
                            local
                                .call_with_params(method, Some(serde_json::to_value(target)?))
                                .await
                        }
                        _ => Err("INVALID_ARGUMENT"),
                    }
                } else {
                    local.call(method).await
                };
                match response {
                    Ok(v) => v,
                    Err(e) => {
                        state = TaskState::Failed;
                        error = match e {
                            "TIMEOUT" => ErrorCode::Timeout,
                            "RESOURCE_EXHAUSTED" => ErrorCode::ResourceExhausted,
                            "INVALID_ARGUMENT" => ErrorCode::InvalidArgument,
                            "NOT_FOUND" => ErrorCode::NotFound,
                            "UNSUPPORTED" => ErrorCode::Unsupported,
                            _ => ErrorCode::KuraUnavailable,
                        };
                        json!({})
                    }
                }
            }
            Ok(
                op @ (Operation::NetworkInspect
                | Operation::NetworkPrepare
                | Operation::NetworkConfirm
                | Operation::NetworkRollback
                | Operation::NetworkTransaction
                | Operation::NetworkTakeoverPlan
                | Operation::NetworkTakeoverPrepare),
            ) => {
                let method = match op {
                    Operation::NetworkInspect => "network.inspect",
                    Operation::NetworkPrepare => "network.prepare",
                    Operation::NetworkConfirm => "network.confirm",
                    Operation::NetworkRollback => "network.rollback",
                    Operation::NetworkTakeoverPlan => "network.takeover.plan",
                    Operation::NetworkTakeoverPrepare => "network.takeover.prepare",
                    _ => "network.transaction",
                };
                let response = if let Some(network) = &local.network {
                    if matches!(
                        op,
                        Operation::NetworkTakeoverPlan | Operation::NetworkTakeoverPrepare
                    ) {
                        match command.network_takeover.clone() {
                            Some(input) => {
                                network
                                    .takeover(
                                        method.into(),
                                        input,
                                        command.command_id.clone(),
                                        session.into(),
                                    )
                                    .await
                            }
                            None => Err(anyhow::anyhow!("INVALID_ARGUMENT")),
                        }
                    } else {
                        network
                            .request(
                                method.into(),
                                command.network_change.clone(),
                                command.network_action.clone(),
                                command.command_id.clone(),
                                session.into(),
                            )
                            .await
                    }
                } else {
                    Err(anyhow::anyhow!("UNSUPPORTED"))
                };
                match response {
                    Ok(v) => v,
                    Err(e) => {
                        state = TaskState::Failed;
                        error = match crate::network::error_code(&e) {
                            "CONFLICT" => ErrorCode::Conflict,
                            "FORBIDDEN" => ErrorCode::Forbidden,
                            "INVALID_ARGUMENT" => ErrorCode::InvalidArgument,
                            "NOT_FOUND" => ErrorCode::NotFound,
                            "RESOURCE_EXHAUSTED" => ErrorCode::ResourceExhausted,
                            "UNSUPPORTED" => ErrorCode::Unsupported,
                            "TIMEOUT" => ErrorCode::Timeout,
                            _ => ErrorCode::Internal,
                        };
                        json!({"code":crate::network::error_code(&e),"diagnostic":crate::network::diagnostic(&e)})
                    }
                }
            }
            _ => {
                state = TaskState::Failed;
                error = ErrorCode::Unsupported;
                json!({})
            }
        }
    };
    let result = TaskResult {
        command_id: command.command_id.clone(),
        state: state as i32,
        error: error as i32,
        result_json: serde_json::to_vec(&result)?,
    };
    ensure!(
        result.result_json.len() <= MAX_FRAME / 4,
        "RESOURCE_EXHAUSTED"
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn configuration_uncertainty_survives_restart_and_blocks_new_writes_without_replay() {
        let dir = std::env::temp_dir().join(format!("config-journal-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("state.sqlite");
        let db = database(path.to_str().unwrap()).await.unwrap();
        let command = ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation: 12,
            idempotency_key: "config-test".into(),
            expires_at_unix_ms: i64::MAX,
            kura_configuration_update: Some(KuraConfigurationUpdate {
                pid: "fixture".into(),
                expected_revision: "a".repeat(64),
                properties: vec![KuraConfigurationProperty {
                    id: "password".into(),
                    value: Some(kura_configuration_property::Value::Text(
                        "new-test-secret".into(),
                    )),
                }],
            }),
            ..Default::default()
        };
        use prost::Message;
        let hash = format!("{:x}", Sha256::digest(command.encode_to_vec()));
        assert!(
            journal::claim(&db, &command, &hash)
                .await
                .unwrap()
                .is_none()
        );
        journal::finish(
            &db,
            &hash,
            journal::unknown(&command.command_id, "EXECUTION_INTERRUPTED"),
        )
        .await
        .unwrap();
        db.close().await;
        let db = database(path.to_str().unwrap()).await.unwrap();
        let mut local = Local::new(0, 0);
        local.enable_configuration_updates(true);
        assert_eq!(
            execute(&db, &local, command.clone()).await.unwrap().state,
            TaskState::Unknown as i32
        );
        let fresh = ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            idempotency_key: "next".into(),
            ..command
        };
        let result = execute(&db, &local, fresh.clone()).await.unwrap();
        assert_eq!(
            (result.state, result.error),
            (TaskState::Failed as i32, ErrorCode::Conflict as i32)
        );
        assert_eq!(
            execute(&db, &local, fresh).await.unwrap().error,
            ErrorCode::Conflict as i32
        );
        let snapshot = ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation: Operation::KuraSnapshotSave as i32,
            idempotency_key: "snapshot-after-unknown".into(),
            expires_at_unix_ms: i64::MAX,
            kura_snapshot_save: Some(KuraSnapshotSave { expected_latest_id: "1".into() }),
            ..Default::default()
        };
        assert_eq!(
            execute(&db, &local, snapshot).await.unwrap().error,
            ErrorCode::Conflict as i32
        );
        let plans: Vec<Vec<u8>> = sqlx::query_scalar("SELECT plan FROM executions")
            .fetch_all(&db)
            .await
            .unwrap();
        assert!(plans.iter().all(|b| {
            !b.windows(b"new-test-secret".len())
                .any(|w| w == b"new-test-secret")
        }));
        db.close().await;
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn snapshot_receipt_must_deny_network_rewind_and_name_the_action() {
        let good = json!({"saved":true,"snapshotId":"5","previousLatestId":"4","networkRewound":false});
        assert!(accepted_snapshot_receipt("kura.snapshot.save", &good));
        assert!(!accepted_snapshot_receipt("kura.snapshot.rollback", &good));
        assert!(!accepted_snapshot_receipt("kura.snapshot.save", &json!({"saved":true,"snapshotId":"5","networkRewound":true})));
        assert!(!accepted_snapshot_receipt("kura.snapshot.save", &json!({"saved":true,"snapshotId":"","networkRewound":false})));
        assert!(accepted_snapshot_receipt("kura.snapshot.rollback", &json!({"rolledBack":true,"snapshotId":"2","networkRewound":false})));
    }
    #[tokio::test]
    async fn snapshot_write_is_unsupported_until_explicitly_enabled() {
        let path = std::env::temp_dir().join(format!("snapshot-off-{}.sqlite", uuid::Uuid::new_v4()));
        let db = database(path.to_str().unwrap()).await.unwrap();
        let disabled = Local::new(0, 0);
        let off = ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation: Operation::KuraSnapshotSave as i32,
            expires_at_unix_ms: i64::MAX,
            idempotency_key: "save-off".into(),
            kura_snapshot_save: Some(KuraSnapshotSave { expected_latest_id: "0".into() }),
            ..Default::default()
        };
        assert_eq!(execute(&db, &disabled, off).await.unwrap().error, ErrorCode::Unsupported as i32);
        db.close().await;
        let plan_key = format!("{}.plan-key", path.display());
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(plan_key).ok();
    }
    #[tokio::test]
    async fn configuration_target_is_validated_before_call_and_receipt_survives_reopen() {
        use yofc_management_protocol::v1::KuraConfigurationTarget;
        let path =
            std::env::temp_dir().join(format!("yofc-config-{}.sqlite", uuid::Uuid::new_v4()));
        let db = database(path.to_str().unwrap()).await.unwrap();
        let uid = unsafe { libc::geteuid() };
        let local = Local::new(uid, uid);
        let command = ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation: 11,
            expires_at_unix_ms: i64::MAX,
            idempotency_key: "configuration".into(),
            ..Default::default()
        };
        assert_eq!(
            execute(&db, &local, command.clone()).await.unwrap().error,
            ErrorCode::InvalidArgument as i32
        );
        let good = ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            kura_configuration: Some(KuraConfigurationTarget {
                pid: "test.pid".into(),
                locale: "zh".into(),
            }),
            ..command
        };
        let result = execute(&db, &local, good.clone()).await.unwrap();
        assert_eq!(result.error, ErrorCode::KuraUnavailable as i32);
        db.close().await;
        let db = database(path.to_str().unwrap()).await.unwrap();
        assert_eq!(
            execute(&db, &local, good.clone())
                .await
                .unwrap()
                .result_json,
            result.result_json
        );
        let mut conflict = good;
        conflict.kura_configuration.as_mut().unwrap().locale = "en".into();
        assert!(execute(&db, &local, conflict).await.is_err());
        db.close().await;
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(format!("{}.plan-key", path.display())).unwrap();
    }
    use prost::Message;
    #[tokio::test]
    async fn result_survives_reopen_and_conflicting_replay_fails() {
        let path = std::env::temp_dir().join(format!("yofc-task-{}.sqlite", uuid::Uuid::new_v4()));
        let db = database(path.to_str().unwrap()).await.unwrap();
        let uid = unsafe { libc::geteuid() };
        let local = Local::new(uid, uid);
        let command = ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation: 1,
            expires_at_unix_ms: i64::MAX,
            idempotency_key: "once".into(),
            ..Default::default()
        };
        let first = execute(&db, &local, command.clone()).await.unwrap();
        let (a, b) = tokio::join!(
            execute(&db, &local, command.clone()),
            execute(&db, &local, command.clone())
        );
        assert_eq!(a.unwrap().encode_to_vec(), b.unwrap().encode_to_vec());
        let fresh = ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            ..command.clone()
        };
        let conflicting = ReadCommand {
            operation: 2,
            ..fresh.clone()
        };
        let (a, b) = tokio::join!(
            execute(&db, &local, fresh),
            execute(&db, &local, conflicting)
        );
        assert_ne!(
            a.is_ok(),
            b.is_ok(),
            "exactly one conflicting concurrent delivery may win"
        );
        db.close().await;
        let db = database(path.to_str().unwrap()).await.unwrap();
        let again = execute(&db, &local, command.clone()).await.unwrap();
        assert_eq!(first.result_json, again.result_json);
        let mut conflict = command.clone();
        conflict.operation = 2;
        assert!(execute(&db, &local, conflict).await.is_err());
        let expired = ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            expires_at_unix_ms: 1,
            ..command
        };
        assert_eq!(
            execute(&db, &local, expired).await.unwrap().state,
            TaskState::Expired as i32
        );
        db.close().await;
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(format!("{}.plan-key", path.display())).unwrap();
    }
}
