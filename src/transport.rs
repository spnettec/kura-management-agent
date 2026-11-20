use crate::{journal, local::Local};
mod capabilities;
mod imported;
use anyhow::{Context, Result, ensure};
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

#[derive(Clone)]
pub struct Config {
    pub endpoint: String,
    pub gateway: String,
    pub binding_generation: u64,
    pub ca: String,
    pub cert: String,
    pub key: String,
    pub boot_id: String,
}
pub(crate) fn validate_endpoint(value: &str) -> Result<()> {
    Endpoint::from_shared(value.to_owned())?;
    Ok(())
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
async fn tls_identity(cert: &str, key: &str) -> Result<Identity> {
    let (cert, key) = (cert.to_owned(), key.to_owned());
    // The bounded OpenSSL compatibility conversion runs on a blocking worker,
    // never in the control stream reader or local request executor.
    tokio::task::spawn_blocking(move || {
        crate::enrollment::tls_identity(fs::read(cert)?, fs::read(key)?)
    })
    .await?
}

/// One-shot mTLS control client for explicit pre-transfer checks. It never
/// starts the durable Connect stream and never leases tasks.
async fn control_client(
    endpoint: &str,
    ca: &str,
    cert: &str,
    key: &str,
) -> Result<ControlClient<tonic::transport::Channel>> {
    ensure!(
        endpoint.starts_with("https://"),
        "HTTPS gRPC endpoint required"
    );
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(fs::read(ca)?))
        .identity(tls_identity(cert, key).await?);
    let channel = Endpoint::from_shared(endpoint.to_string())?
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(5))
        .connect()
        .await?;
    Ok(ControlClient::new(channel)
        .max_decoding_message_size(MAX_FRAME)
        .max_encoding_message_size(MAX_FRAME))
}

/// Contract for packaging/setup.py: ACTIVE exits 0; revoked, unknown, and
/// unreachable all fail closed. Only status text is reported, never secrets.
pub async fn check_transfer_revocation(
    endpoint: &str,
    ca: &str,
    cert: &str,
    key: &str,
    transfer_id: &str,
) -> Result<()> {
    ensure!(
        uuid::Uuid::parse_str(transfer_id).is_ok(),
        "transfer id must be a UUID"
    );
    let mut client = tokio::time::timeout(
        Duration::from_secs(20),
        control_client(endpoint, ca, cert, key),
    )
    .await
    .map_err(|_| anyhow::anyhow!("revocation check timed out"))??;
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        client.check_transfer_revocation(TransferRevocationCheck {
            transfer_id: transfer_id.into(),
        }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("revocation check timed out"))??;
    let status = response.into_inner().status;
    ensure_transfer_active(&status)
}

/// Only a recorded, non-revoked issuance belonging to the caller is ACTIVE.
/// Revoked, unknown, and malformed answers all fail closed.
fn ensure_transfer_active(status: &str) -> Result<()> {
    ensure!(
        status == "ACTIVE",
        "transfer authorization is {status}; request a new approval"
    );
    Ok(())
}

pub async fn run(
    mut configs: tokio::sync::watch::Receiver<Option<Config>>,
    local: Local,
    remote: crate::remote::Remote,
    db: SqlitePool,
) -> Result<()> {
    let slots = std::sync::Arc::new(Semaphore::new(2));
    let mut changes = remote.subscribe();
    let mut delay = 1;
    loop {
        let config = configs.borrow_and_update().clone();
        let session = remote.session();
        let (Some(config), Some(revision)) = (&config, session) else {
            tokio::select! {changed=changes.changed()=>{changed?;}, changed=configs.changed()=>{changed?;}}
            continue;
        };
        remote.connection(&revision, "CONNECTING");
        let started = std::time::Instant::now();
        tokio::select! {
            biased;
            changed = configs.changed() => { changed?; delay=1; continue; }
            changed = changes.changed() => { changed?; delay=1; continue; }
            result = connect(config, &local, &db, &slots, &remote, &revision) => {
                remote.connection(&revision,"DISCONNECTED");
                if let Err(error) = result { tracing::warn!(%error,"control disconnected; reconnect scheduled"); }
            }
        }
        if started.elapsed() > Duration::from_secs(30) {
            delay = 1;
        }
        let jitter = OsRng.next_u32() as u64 % 500;
        tokio::select! {
            changed=configs.changed()=>{changed?; delay=1;}
            changed=changes.changed()=>{changed?; delay=1;}
            _=tokio::time::sleep(Duration::from_millis(delay*1000+jitter))=>{delay=(delay*2).min(30);}
        }
    }
}
async fn connect(
    config: &Config,
    local: &Local,
    db: &SqlitePool,
    slots: &std::sync::Arc<Semaphore>,
    remote: &crate::remote::Remote,
    revision: &str,
) -> Result<()> {
    ensure!(
        config.endpoint.starts_with("https://"),
        "HTTPS gRPC endpoint required"
    );
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(fs::read(&config.ca)?))
        .identity(tls_identity(&config.cert, &config.key).await?);
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
    let capabilities = capabilities::advertised(local).await;
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
    remote.connection(revision, "CONNECTED");
    // Locally minted only after the actual mTLS stream/welcome completes. The
    // center cannot rotate this witness by changing any command payload.
    let firewall_connection = format!(
        "{}:{}:{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
        uuid::Uuid::new_v4(),
        welcome.connection_epoch
    );
    // The joint NM coordinator uses the same connection witness semantics:
    // minted locally after the welcome, so confirm can require a connection
    // established after the apply.
    let nm_connection = firewall_connection.clone();
    *local.management_connection.lock().map_err(|_|anyhow::anyhow!("management connection state poisoned"))?=Some(firewall_connection.clone());
    tracing::info!(epoch=%welcome.connection_epoch,"control connected");
    let mut heartbeat =
        tokio::time::interval(Duration::from_secs(welcome.heartbeat_seconds as u64));
    let mut sequence = 0;
    let (control_tx, mut control_rx) = mpsc::channel::<anyhow::Error>(4);
    loop {
        tokio::select! {
            _=heartbeat.tick()=>{
                sequence+=1;
                let (kura_available, configuration_ready)=local.configuration_bridge_state().await;
                tx.try_send(AgentFrame{payload:Some(agent_frame::Payload::Heartbeat(Heartbeat{
                    sequence,kura_available,uptime_seconds:local.started.elapsed().as_secs(),
                    configuration_update_ready:local.configuration_updates_enabled().then_some(configuration_ready),
                }))})?;
            }
            incoming=stream.message()=>{
                let Some(frame)=incoming? else{break};
                match frame.payload {
                    Some(console_frame::Payload::TaskQuery(query))=>{
                        let _admission = remote.admit(revision)?;
                        ensure!(!query.command_ids.is_empty() && query.command_ids.len()<=16,"INVALID_ARGUMENT");
                        for id in query.command_ids {
                            let result=query_receipt(db,local,&id).await?;
                            tx.try_send(AgentFrame{payload:Some(agent_frame::Payload::Result(result))})?;
                        }
                    }
                    Some(console_frame::Payload::Command(command))=>{
                        let admission = remote.admit(revision)?;
                        let Ok(permit)=slots.clone().try_acquire_owned() else{anyhow::bail!("RESOURCE_EXHAUSTED")};
                        let db=db.clone();let local=local.clone();let tx=tx.clone();let session=match command.operation {30..=33|38..=48=>firewall_connection.clone(),34..=37=>nm_connection.clone(),_=>welcome.connection_epoch.clone()};
                        let control=control_tx.clone();
                        // This worker belongs to the process, not this connection.
                        // Losing gRPC must not cancel a system change after admission.
                        tokio::spawn(async move {
                            let _permit=permit;
                            let _admission=admission;
                            let action=async {
                                let prepare=matches!(Operation::try_from(command.operation), Ok(Operation::NetworkPrepare | Operation::NetworkTakeoverPrepare | Operation::FirewallPrepare | Operation::NmPrepare));
                                let imported_reconnect=matches!(command.operation,41|45);
                                let result=execute_in_session(&db,&local,command,&session).await?;
                                let reconnect=needs_reconnect(&result,prepare,imported_reconnect);
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

fn needs_reconnect(result:&TaskResult,legacy_prepare:bool,imported_action:bool)->bool {
    let Ok(value)=serde_json::from_slice::<serde_json::Value>(&result.result_json) else {return false;};
    legacy_prepare&&value["state"]=="WAIT_CONFIRM"
        || imported_action&&result.state==TaskState::Succeeded as i32&&value["receipt"]["state"]=="WAIT_CONFIRM"
            &&value["writeEnabled"]==true&&value["newManagementConnectionVerified"]==false
            &&value["receipt"]["deadlineExpired"]==false
            &&value["receipt"]["deadlineUnixMs"].as_i64().is_some_and(|d|d>journal::now())
}

pub(crate) async fn query_receipt(db: &SqlitePool, local: &Local, id: &str) -> Result<TaskResult> {
    // Do this before returning even a terminal encrypted receipt: a prepare
    // result contains a token and cannot cross a center/generation handoff.
    let operation:Option<i32>=sqlx::query_scalar("SELECT operation FROM executions WHERE command_id=? UNION ALL SELECT operation FROM results WHERE command_id=? LIMIT 1")
        .bind(id).bind(id).fetch_optional(db).await?;
    let imported=operation.is_some_and(|operation|matches!(operation,38..=48));
    let authority = if imported {imported::authority(local)} else {firewall_authority(local)}.ok();
    let matched=journal::firewall_authority_matches(db, id, authority.as_deref().unwrap_or("")).await?;
    if matched==Some(false) || imported&&matched!=Some(true)
    {
        return Ok(journal::unknown(id, "REMOTE_AUTHORITY_UNAVAILABLE"));
    }
    let current = journal::receipt(db, id).await?;
    if current.state != TaskState::Unknown as i32 {
        return Ok(current);
    }
    // Imported uncertainty requires an explicit owned original query. The
    // generic receipt path never invokes a private backend or fresh Core call.
    if imported {return Ok(current);}
    let Some((command, hash)) = journal::pending_plan(db, id).await? else {
        // Another read-only query can commit the terminal receipt between the
        // first read and this lookup. Return that receipt, never stale UNKNOWN.
        return journal::receipt(db, id).await;
    };
    if matches!(command.operation, 31..=33) {
        if let Some(firewall) = &local.firewall
            && let Ok(authority) = firewall_authority(local)
            && let Some(proof) = firewall.prove_remote(&command, &authority).await?
        {
            return journal::resolve(db, &hash, proof).await;
        }
        return Ok(current);
    }
    if matches!(command.operation, 34..=37) {
        if let Some(nm) = &local.nm {
            match nm_authority(local) {
                Ok(authority) => {
                    tracing::debug!(operation=command.operation, "NM receipt query");
                    match nm.prove_remote(&command, &authority).await {
                        Ok(Some(proof)) => {
                            tracing::debug!(command_id=%proof.command_id, state=%proof.state, payload=%String::from_utf8_lossy(&proof.result_json), "NM receipt proved");
                            match journal::resolve(db, &hash, proof).await {
                                Ok(r) => {
                                    tracing::debug!(state=%r.state, "NM receipt resolved");
                                    return Ok(r);
                                }
                                Err(e) => {
                                    tracing::debug!(error=%e, "NM resolve failed");
                                    return Ok(current);
                                }
                            }
                        }
                        Ok(None) => tracing::debug!("NM receipt not matched"),
                        Err(e) => tracing::debug!(error=%e, "NM prove failed"),
                    }
                }
                Err(e) => tracing::debug!(error=%e, "NM authority unavailable"),
            }
        }
        return Ok(current);
    }
    if matches!(command.operation, 24..=28) {
        if let Some(control) = &local.system_control
            && let Some(proof) = control.prove(&command).await?
        {
            return journal::resolve(db, &hash, proof).await;
        }
        return Ok(current);
    }
    if matches!(command.operation, 21 | 22 | 29) {
        if let Some(recovery) = &local.recovery
            && let Some(proof) = recovery.prove_ordinary_command(&command).await?
        {
            return journal::resolve(db, &hash, proof).await;
        }
        return Ok(current);
    }
    if matches!(command.operation, 16..=19) {
        if let Some(control) = &local.ordinary_boot
            && let Some(proof) = control.prove(&command).await?
        {
            return journal::resolve(db, &hash, proof).await;
        }
        return Ok(current);
    }
    let configuration_write = command.operation == Operation::KuraConfigurationUpdate as i32;
    if !configuration_write
        && let Some(network) = &local.network
        && let Some(proof) = network.prove_outcome(&command).await?
    {
        return journal::resolve(db, &hash, proof).await;
    }
    // A missing journal stays unknown. Current configuration is not evidence.
    if configuration_write
        && let Some(proof) = crate::configuration_outcome::prove(local, &command).await?
    {
        return journal::resolve(db, &hash, proof).await;
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
    if matches!(command.operation, 31..=33 | 38..=48) {
        let authority = match if matches!(command.operation, 38..=48) { imported::authority(local) } else { firewall_authority(local) } {
            Ok(v) => v,
            Err(e) => {
                return Ok(TaskResult {
                    command_id: command.command_id.clone(),
                    state: TaskState::Failed as i32,
                    error: ErrorCode::from_str_name(crate::boot_control::error_code(&e))
                        .unwrap_or(ErrorCode::Internal) as i32,
                    result_json: b"{}".to_vec(),
                });
            }
        };
        journal::bind_firewall_authority(db, &command.command_id, &authority, &request_hash)
            .await?;
    }
    // Hold across journal claim, the UDS call and durable finish. A following
    // configuration write cannot outrun persistence of an uncertain result.
    let _configuration_guard = if command.operation == Operation::KuraConfigurationUpdate as i32
        || command.operation == Operation::KuraSnapshotSave as i32
        || command.operation == Operation::KuraSnapshotRollback as i32
        || matches!(command.operation, 16..=19 | 21 | 22 | 24..=29)
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
    // Keep the OS-backed coordinator lease through durable completion. A local
    // recovery cannot stop Kura while this process has an accepted online write.
    let _system_guard = if matches!(command.operation, 12..=14) {
        if let Some(root) = local.system_state.clone() {
            match tokio::task::spawn_blocking(move || {
                crate::system_change::Guard::acquire(
                    &root,
                    crate::system_change::Subsystem::Configuration,
                )
            })
            .await?
            {
                Ok(guard) => Some(guard),
                Err(_) => {
                    return journal::finish(
                        db,
                        &request_hash,
                        TaskResult {
                            command_id: command.command_id.clone(),
                            state: TaskState::Failed as i32,
                            error: ErrorCode::Conflict as i32,
                            result_json: b"{}".to_vec(),
                        },
                    )
                    .await;
                }
            }
        } else {
            None
        }
    } else {
        None
    };
    // Configuration and snapshot writes share Kura state. An uncertain one blocks the others.
    let unresolved: bool = if matches!(command.operation, 12..=14) {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM executions WHERE operation IN (12,13,14,16,17,18,19,21,22,24,25,26,27,28) AND command_id<>? AND state IN ('RUNNING','UNKNOWN'))")
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
        if matches!(command.operation, 38..=48) {
            imported::perform(db, local, &command, &request_hash, session).await
        } else {
            perform(local, &command, session).await
        }
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
    #[cfg(test)]
    boot_process_loss_fixture(&command, &result)?;
    #[cfg(test)]
    firewall_process_loss_fixture(&command, &result)?;
    journal::finish(db, &request_hash, result).await
}

#[cfg(test)]
fn boot_process_loss_fixture(command: &ReadCommand, result: &TaskResult) -> Result<()> {
    let Some(path) = std::env::var_os("YOFC_BOOT_STREAM_EXIT_FIXTURE") else {
        return Ok(());
    };
    let (bytes, meta) = crate::durable::read(std::path::Path::new(&path), 16384)?;
    ensure!(
        meta.uid == unsafe { libc::geteuid() } && meta.mode == 0o600,
        "private explicit stream fixture required"
    );
    let spec: serde_json::Value = serde_json::from_slice(&bytes)?;
    if spec["exitAfterOperation"].as_i64() == Some(i64::from(command.operation))
        && matches!(command.operation, 16..=19 | 21 | 22 | 29)
        && result.state == TaskState::Succeeded as i32
    {
        use prost::Message;
        crate::durable::publish_new(
            std::path::Path::new(
                spec["exitSignal"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("exit signal required"))?,
            ),
            &serde_json::to_vec(
                &json!({"commandId":command.command_id,"operation":command.operation,"requestSha256":format!("{:x}",Sha256::digest(command.encode_to_vec())),"domainSucceededBeforeExecutionReceipt":true,"testOnlyProcessExit":true}),
            )?,
            crate::durable::FileMetadata::private(),
        )?;
        std::process::exit(92);
    }
    Ok(())
}

#[cfg(test)]
fn firewall_process_loss_fixture(command: &ReadCommand, result: &TaskResult) -> Result<()> {
    let Some(path) = std::env::var_os("YOFC_FIREWALL_STREAM_EXIT_FIXTURE") else {
        return Ok(());
    };
    let (bytes, meta) = crate::durable::read(std::path::Path::new(&path), 16384)?;
    ensure!(
        meta.uid == unsafe { libc::geteuid() } && meta.mode == 0o600,
        "private explicit stream fixture required"
    );
    let spec: serde_json::Value = serde_json::from_slice(&bytes)?;
    if spec["exitAfterOperation"].as_i64() == Some(i64::from(command.operation))
        && matches!(command.operation, 31..=33)
        && result.state == TaskState::Succeeded as i32
    {
        use prost::Message;
        crate::durable::publish_new(
            std::path::Path::new(
                spec["exitSignal"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("exit signal required"))?,
            ),
            &serde_json::to_vec(
                &json!({"commandId":command.command_id,"operation":command.operation,"requestSha256":format!("{:x}",Sha256::digest(command.encode_to_vec())),"domainSucceededBeforeExecutionReceipt":true,"testOnlyFirewallProcessExit":true}),
            )?,
            crate::durable::FileMetadata::private(),
        )?;
        std::process::exit(93);
    }
    Ok(())
}

fn accepted_snapshot_receipt(method: &str, value: &serde_json::Value) -> bool {
    value.get("networkRewound") == Some(&serde_json::json!(false))
        && value
            .get("snapshotId")
            .and_then(|v| v.as_str())
            .is_some_and(|id| !id.is_empty())
        && ((method == "kura.snapshot.save"
            && value.get("saved") == Some(&serde_json::json!(true)))
            || (method == "kura.snapshot.rollback"
                && value.get("rolledBack") == Some(&serde_json::json!(true))))
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
            Ok(
                Operation::NmView
                | Operation::NmPrepare
                | Operation::NmConfirm
                | Operation::NmRollback,
            ) => {
                let response = if let Some(nm) = &local.nm {
                    match nm_authority(local) {
                        Ok(authority) => {
                            nm.remote_request(command, &authority, session, local.nm_remote)
                                .await
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    Err(anyhow::anyhow!("UNSUPPORTED"))
                };
                if let Err(ref e) = response {
                    tracing::debug!(error=%e, operation=command.operation, "NM remote command rejected");
                }
                match response {
                    Ok(value) => value,
                    Err(e) => {
                        let code = crate::boot_control::error_code(&e);
                        state = if code == "OUTCOME_UNKNOWN" {
                            TaskState::Unknown
                        } else {
                            TaskState::Failed
                        };
                        error = ErrorCode::from_str_name(code).unwrap_or(ErrorCode::Internal);
                        if matches!(command.operation, 34..=37) && code == "INTERNAL" {
                            state = TaskState::Unknown;
                            error = ErrorCode::OutcomeUnknown;
                        }
                        json!({})
                    }
                }
            }
            Ok(
                Operation::FirewallView
                | Operation::FirewallPrepare
                | Operation::FirewallConfirm
                | Operation::FirewallRollback,
            ) => {
                let response = if let Some(firewall) = &local.firewall {
                    match firewall_authority(local) {
                        Ok(authority) => {
                            firewall
                                .remote_request(command, &authority, session, local.firewall_remote)
                                .await
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    Err(anyhow::anyhow!("UNSUPPORTED"))
                };
                match response {
                    Ok(value) => value,
                    Err(e) => {
                        let code = crate::boot_control::error_code(&e);
                        state = if code == "OUTCOME_UNKNOWN" {
                            TaskState::Unknown
                        } else {
                            TaskState::Failed
                        };
                        error = ErrorCode::from_str_name(code).unwrap_or(ErrorCode::Internal);
                        // Unexpected I/O/persistence errors cannot certify a
                        // remote write as rejected before dispatch.
                        if (matches!(command.operation, 31..=33) || matches!(command.operation, 34..=37))
                            && code == "INTERNAL"
                        {
                            state = TaskState::Unknown;
                            error = ErrorCode::OutcomeUnknown;
                        }
                        json!({"code":code})
                    }
                }
            }
            Ok(
                Operation::ServiceStatus
                | Operation::ServiceRestartPrepare
                | Operation::ServiceRestart
                | Operation::SystemRebootPrepare
                | Operation::SystemReboot
                | Operation::SystemControlCancel,
            ) => {
                let response = if local.system_control_remote {
                    if let Some(control) = &local.system_control {
                        control
                            .request(
                                command.operation,
                                command.system_control_action.clone(),
                                Some(command),
                                local.clone(),
                            )
                            .await
                    } else {
                        Err(anyhow::anyhow!("UNSUPPORTED"))
                    }
                } else {
                    Err(anyhow::anyhow!("UNSUPPORTED"))
                };
                return match response {
                    Ok(value) => {
                        local
                            .system_control
                            .as_ref()
                            .unwrap()
                            .command_result(command, value)
                            .await
                    }
                    Err(e) => {
                        let code = crate::boot_control::error_code(&e);
                        Ok(TaskResult {
                            command_id: command.command_id.clone(),
                            state: if code == "OUTCOME_UNKNOWN" {
                                TaskState::Unknown
                            } else {
                                TaskState::Failed
                            } as i32,
                            error: ErrorCode::from_str_name(code).unwrap_or(ErrorCode::Internal)
                                as i32,
                            result_json: serde_json::to_vec(&json!({"code":code}))?,
                        })
                    }
                };
            }
            Ok(
                Operation::OrdinaryHandoffStatus
                | Operation::OrdinaryHandoffPrepare
                | Operation::OrdinaryHandoffExecute
                | Operation::OrdinaryHandoffCancel,
            ) => {
                let response = if local.ordinary_handoff_remote {
                    if let Some(recovery) = &local.recovery {
                        recovery.remote_ordinary(command, local.clone()).await
                    } else {
                        Err(anyhow::anyhow!("UNSUPPORTED"))
                    }
                } else {
                    Err(anyhow::anyhow!("UNSUPPORTED"))
                };
                match response {
                    Ok(value) => {
                        if value["state"] == "RECOVERY_REQUIRED" {
                            state = TaskState::Failed;
                            error = ErrorCode::Conflict;
                        }
                        value
                    }
                    Err(e) => {
                        let code = crate::boot_control::error_code(&e);
                        if code == "OUTCOME_UNKNOWN" {
                            state = TaskState::Unknown;
                            error = ErrorCode::OutcomeUnknown;
                        } else {
                            state = TaskState::Failed;
                            error = match code {
                                "INVALID_ARGUMENT" => ErrorCode::InvalidArgument,
                                "FORBIDDEN" => ErrorCode::Forbidden,
                                "UNSUPPORTED" => ErrorCode::Unsupported,
                                "CONFLICT" => ErrorCode::Conflict,
                                "TIMEOUT" => ErrorCode::Timeout,
                                _ => ErrorCode::Internal,
                            };
                        }
                        json!({"code":code})
                    }
                }
            }
            Ok(Operation::KuraSnapshotSave) | Ok(Operation::KuraSnapshotRollback) => {
                let method = if command.operation == Operation::KuraSnapshotSave as i32 {
                    "kura.snapshot.save"
                } else {
                    "kura.snapshot.rollback"
                };
                let params = if command.operation == Operation::KuraSnapshotSave as i32 {
                    command
                        .kura_snapshot_save
                        .as_ref()
                        .unwrap()
                        .parameters(command.expires_at_unix_ms)
                        .unwrap()
                } else {
                    command
                        .kura_snapshot_rollback
                        .as_ref()
                        .unwrap()
                        .parameters(command.expires_at_unix_ms)
                        .unwrap()
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
                let response = if serde_json::to_vec(&params)
                    .map(|v| v.len())
                    .unwrap_or(usize::MAX)
                    > 16384
                {
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
            Ok(
                op @ (Operation::OrdinaryBootStatus
                | Operation::OrdinaryBootPrepare
                | Operation::OrdinaryBootExecute
                | Operation::OrdinaryBootCancel
                | Operation::OrdinaryBootReconcile),
            ) => {
                let method = match op {
                    Operation::OrdinaryBootStatus => "ordinary.boot.status",
                    Operation::OrdinaryBootPrepare => "ordinary.boot.prepare",
                    Operation::OrdinaryBootExecute => "ordinary.boot.execute",
                    Operation::OrdinaryBootCancel => "ordinary.boot.cancel",
                    _ => "ordinary.boot.reconcile",
                };
                let params = command
                    .ordinary_boot_action
                    .as_ref()
                    .map(|v| serde_json::to_value(v).unwrap())
                    .unwrap_or(serde_json::Value::Null);
                let response = if let Some(control) = &local.ordinary_boot {
                    control.request(method, params, Some(command)).await
                } else {
                    Err(anyhow::anyhow!("UNSUPPORTED"))
                };
                match response {
                    Ok(v) => {
                        if v["state"] == "RECOVERY_REQUIRED" {
                            state = TaskState::Failed;
                            error = ErrorCode::Conflict;
                        }
                        v
                    }
                    Err(e) => {
                        let code = crate::boot_control::error_code(&e);
                        if code == "OUTCOME_UNKNOWN" {
                            state = TaskState::Unknown;
                            error = ErrorCode::OutcomeUnknown;
                        } else {
                            state = TaskState::Failed;
                            error = match code {
                                "INVALID_ARGUMENT" => ErrorCode::InvalidArgument,
                                "FORBIDDEN" => ErrorCode::Forbidden,
                                "UNSUPPORTED" => ErrorCode::Unsupported,
                                "CONFLICT" => ErrorCode::Conflict,
                                "TIMEOUT" => ErrorCode::Timeout,
                                _ => ErrorCode::Internal,
                            };
                        }
                        json!({"code":code})
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
                            "OUTCOME_UNKNOWN" => {
                                state = TaskState::Unknown;
                                ErrorCode::OutcomeUnknown
                            }
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

fn nm_authority(local: &Local) -> Result<String> {
    ensure!(
        local.nm_remote,
        "UNSUPPORTED: remote NM writes disabled"
    );
    let view = local
        .remote
        .as_ref()
        .context("UNSUPPORTED: no remote binding")?
        .status();
    ensure!(
        view["bound"] == true && view["enabled"] == true && view["recoveryRequired"] == false,
        "FORBIDDEN: remote authority unavailable"
    );
    let endpoint = view["endpoint"]
        .as_str()
        .context("FORBIDDEN: remote endpoint")?;
    let gateway = view["gatewayId"]
        .as_str()
        .context("FORBIDDEN: remote gateway")?;
    let generation = view["bindingGeneration"]
        .as_str()
        .context("FORBIDDEN: remote generation")?;
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&json!([
            "nm.remote.v1",
            endpoint,
            gateway,
            generation
        ]))?)
    ))
}

fn firewall_authority(local: &Local) -> Result<String> {
    ensure!(
        local.firewall_remote,
        "UNSUPPORTED: remote firewall disabled"
    );
    let view = local
        .remote
        .as_ref()
        .context("UNSUPPORTED: no remote binding")?
        .status();
    ensure!(
        view["bound"] == true && view["enabled"] == true && view["recoveryRequired"] == false,
        "FORBIDDEN: remote authority unavailable"
    );
    let endpoint = view["endpoint"]
        .as_str()
        .context("FORBIDDEN: remote endpoint")?;
    let gateway = view["gatewayId"]
        .as_str()
        .context("FORBIDDEN: remote gateway")?;
    let generation = view["bindingGeneration"]
        .as_str()
        .context("FORBIDDEN: remote generation")?;
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&json!([
            "firewall.remote.v1",
            endpoint,
            gateway,
            generation
        ]))?)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transfer_revocation_fails_closed_except_recorded_active() {
        assert!(ensure_transfer_active("ACTIVE").is_ok());
        for status in ["REVOKED", "NOT_FOUND", "", "active", "UNKNOWN"] {
            let error = ensure_transfer_active(status).unwrap_err().to_string();
            assert!(error.contains("request a new approval"), "status={status}");
        }
    }
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
            kura_snapshot_save: Some(KuraSnapshotSave {
                expected_latest_id: "1".into(),
            }),
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
        let good =
            json!({"saved":true,"snapshotId":"5","previousLatestId":"4","networkRewound":false});
        assert!(accepted_snapshot_receipt("kura.snapshot.save", &good));
        assert!(!accepted_snapshot_receipt("kura.snapshot.rollback", &good));
        assert!(!accepted_snapshot_receipt(
            "kura.snapshot.save",
            &json!({"saved":true,"snapshotId":"5","networkRewound":true})
        ));
        assert!(!accepted_snapshot_receipt(
            "kura.snapshot.save",
            &json!({"saved":true,"snapshotId":"","networkRewound":false})
        ));
        assert!(accepted_snapshot_receipt(
            "kura.snapshot.rollback",
            &json!({"rolledBack":true,"snapshotId":"2","networkRewound":false})
        ));
    }
    #[tokio::test]
    async fn snapshot_write_is_unsupported_until_explicitly_enabled() {
        let path =
            std::env::temp_dir().join(format!("snapshot-off-{}.sqlite", uuid::Uuid::new_v4()));
        let db = database(path.to_str().unwrap()).await.unwrap();
        let disabled = Local::new(0, 0);
        let off = ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation: Operation::KuraSnapshotSave as i32,
            expires_at_unix_ms: i64::MAX,
            idempotency_key: "save-off".into(),
            kura_snapshot_save: Some(KuraSnapshotSave {
                expected_latest_id: "0".into(),
            }),
            ..Default::default()
        };
        assert_eq!(
            execute(&db, &disabled, off).await.unwrap().error,
            ErrorCode::Unsupported as i32
        );
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
    #[tokio::test]
    async fn boot_is_default_off_and_cross_payloads_never_gain_authority() {
        let root = std::env::temp_dir().join(format!("boot-off-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let db = database(root.join("state.db").to_str().unwrap())
            .await
            .unwrap();
        let local = Local::new(1001, unsafe { libc::geteuid() });
        for operation in 15..=19 {
            let command = ReadCommand {
                command_id: uuid::Uuid::new_v4().to_string(),
                operation,
                idempotency_key: uuid::Uuid::new_v4().to_string(),
                expires_at_unix_ms: i64::MAX,
                ordinary_boot_action: matches!(operation, 17 | 18).then_some(OrdinaryBootAction {
                    transaction_id: format!("boot-{}", uuid::Uuid::new_v4()),
                    confirmation_token: uuid::Uuid::new_v4().to_string(),
                }),
                ..Default::default()
            };
            let result = execute(&db, &local, command).await.unwrap();
            assert_eq!(result.state, TaskState::Failed as i32);
            assert_eq!(result.error, ErrorCode::Unsupported as i32);
        }
        db.close().await;
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    #[ignore = "explicit fresh firewall process-loss fixture; test binary only"]
    fn actual_firewall_outcome_main_with_explicit_fixture() {
        // Match the real main entry: harden before creating runtime workers.
        crate::secure::harden_process().unwrap();
        let path = std::env::var("YOFC_FIREWALL_STREAM_EXIT_FIXTURE")
            .expect("explicit new firewall fixture required");
        let (bytes, meta) = crate::durable::read(std::path::Path::new(&path), 16384).unwrap();
        assert_eq!(meta.mode, 0o600);
        assert_eq!(meta.uid, unsafe { libc::geteuid() });
        let spec: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(spec["exitAfterOperation"].as_u64(), Some(31..=33)));
        let root = std::path::PathBuf::from(spec["stateRoot"].as_str().unwrap());
        assert_eq!(
            std::env::var("AGENT_STATE_DB").unwrap(),
            root.join("results.sqlite").to_str().unwrap()
        );
        assert_eq!(std::env::var("AGENT_FIREWALL_REMOTE").unwrap(), "1");
        assert_eq!(std::env::var("AGENT_FIREWALL_WRITE").unwrap(), "1");
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(4)
            .enable_all()
            .build()
            .unwrap()
            .block_on(crate::run())
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "explicit fresh ordinary handoff process-loss fixture; test binary only"]
    async fn actual_handoff_outcome_main_with_explicit_fixture() {
        let path =
            std::env::var("YOFC_BOOT_STREAM_EXIT_FIXTURE").expect("explicit new fixture required");
        let (bytes, meta) = crate::durable::read(std::path::Path::new(&path), 16384).unwrap();
        assert_eq!(meta.mode, 0o600);
        assert_eq!(meta.uid, unsafe { libc::geteuid() });
        let spec: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(spec["exitAfterOperation"].as_u64(), Some(21 | 22)));
        let root = std::path::PathBuf::from(spec["stateRoot"].as_str().unwrap());
        assert_eq!(
            std::env::var("AGENT_STATE_DB").unwrap(),
            root.join("results.sqlite").to_str().unwrap()
        );
        assert_eq!(
            std::env::var("AGENT_RECOVERY_ORDINARY_REMOTE").unwrap(),
            "1"
        );
        crate::run().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "explicit fresh mTLS process-loss fixture; test binary only"]
    async fn actual_boot_outcome_mtls_agent_with_explicit_fixture() {
        let path =
            std::env::var("YOFC_BOOT_STREAM_EXIT_FIXTURE").expect("explicit new fixture required");
        let (bytes, meta) = crate::durable::read(std::path::Path::new(&path), 16384).unwrap();
        assert_eq!(meta.mode, 0o600);
        assert_eq!(meta.uid, unsafe { libc::geteuid() });
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let root = std::path::PathBuf::from(v["stateRoot"].as_str().unwrap());
        let db = database(root.join("results.sqlite").to_str().unwrap())
            .await
            .unwrap();
        let config = Config {
            endpoint: v["endpoint"].as_str().unwrap().into(),
            gateway: v["gateway"].as_str().unwrap().into(),
            binding_generation: 1,
            ca: v["ca"].as_str().unwrap().into(),
            cert: v["cert"].as_str().unwrap().into(),
            key: v["key"].as_str().unwrap().into(),
            boot_id: format!("explicit-test-process-{}", uuid::Uuid::new_v4()),
        };
        let remote = crate::remote::Remote::open(
            root.clone(),
            true,
            Some((config.endpoint.clone(), config.gateway.clone(), 1)),
        )
        .unwrap();
        let mut local = Local::new(unsafe { libc::geteuid() }, unsafe { libc::geteuid() });
        local.remote = Some(remote.clone());
        local.ordinary_boot = Some(
            crate::boot_control::Control::new(
                root,
                std::path::PathBuf::from(v["bootRequest"].as_str().unwrap()),
                db.clone(),
            )
            .unwrap(),
        );
        let listener = local
            .listen(std::path::Path::new(v["socket"].as_str().unwrap()))
            .await
            .unwrap();
        let (_sender, receiver) = tokio::sync::watch::channel(Some(config));
        tokio::select! {r=local.clone().serve(listener)=>r.unwrap(),r=run(receiver,local,remote,db)=>r.unwrap()};
    }
}

#[cfg(test)]
#[path = "transport/reconnect_tests.rs"]
mod reconnect_tests;
