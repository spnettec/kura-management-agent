//! Durable execution admission and receipt lookup. Plans are encrypted locally;
//! unfinished admissions become UNKNOWN on process restart and never auto-run.
use anyhow::{Result, ensure};
use prost::Message;
use rand_core::{OsRng, RngCore};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
};
use yofc_management_protocol::v1::{ErrorCode, ReadCommand, TaskResult, TaskState};
pub(crate) mod imported;

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

async fn key_path(db: &SqlitePool) -> Result<PathBuf> {
    let row = sqlx::query("PRAGMA database_list").fetch_one(db).await?;
    let path: String = row.get("file");
    ensure!(!path.is_empty(), "persistent execution database required");
    Ok(PathBuf::from(format!("{path}.plan-key")))
}

async fn plan_key(db: &SqlitePool) -> Result<LessSafeKey> {
    let path = key_path(db).await?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o777 == 0o600,
        "unsafe execution plan key"
    );
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(33).read_to_end(&mut bytes)?;
    ensure!(bytes.len() == 32, "invalid execution plan key");
    Ok(LessSafeKey::new(
        UnboundKey::new(&aead::AES_256_GCM, &bytes)
            .map_err(|_| anyhow::anyhow!("invalid execution plan key"))?,
    ))
}

async fn seal(db: &SqlitePool, aad: &str, mut data: Vec<u8>) -> Result<Vec<u8>> {
    let key = plan_key(db).await?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad.as_bytes()),
        &mut data,
    )
    .map_err(|_| anyhow::anyhow!("execution encryption failed"))?;
    let mut encrypted = vec![1u8];
    encrypted.extend_from_slice(&nonce);
    encrypted.extend_from_slice(&data);
    Ok(encrypted)
}
async fn unseal(db: &SqlitePool, aad: &str, encrypted: Vec<u8>) -> Result<Vec<u8>> {
    ensure!(
        encrypted.len() >= 29 && encrypted[0] == 1,
        "invalid execution ciphertext"
    );
    let nonce: [u8; 12] = encrypted[1..13].try_into()?;
    let mut data = encrypted[13..].to_vec();
    let key = plan_key(db).await?;
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad.as_bytes()),
            &mut data,
        )
        .map_err(|_| anyhow::anyhow!("execution decryption failed"))?;
    Ok(plain.to_vec())
}
async fn decode_receipt(db: &SqlitePool, hash: &str, encrypted: Vec<u8>) -> Result<TaskResult> {
    let data = unseal(db, &format!("result:{hash}"), encrypted).await?;
    Ok(TaskResult::decode(data.as_slice())?)
}

pub async fn initialize(db: &SqlitePool) -> Result<()> {
    imported::initialize(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS firewall_execution_authorities(command_id TEXT PRIMARY KEY,authority TEXT NOT NULL,request_hash TEXT NOT NULL)").execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS executions(command_id TEXT PRIMARY KEY,operation INTEGER NOT NULL,idempotency_key TEXT NOT NULL,request_hash TEXT NOT NULL,plan BLOB NOT NULL,state TEXT NOT NULL,result BLOB,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,expires_at INTEGER NOT NULL)").execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS execution_resolutions(command_id TEXT PRIMARY KEY,request_hash TEXT NOT NULL,source TEXT NOT NULL,journal_sha256 TEXT NOT NULL,resolved_at INTEGER NOT NULL)").execute(db).await?;
    let columns = sqlx::query("PRAGMA table_info(executions)")
        .fetch_all(db)
        .await?;
    if !columns
        .iter()
        .any(|r| r.get::<String, _>("name") == "expires_at")
    {
        // Older development admissions had no TTL column. Keep those receipts
        // indefinitely rather than risk evicting a still-valid command identity.
        sqlx::query("ALTER TABLE executions ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 9223372036854775807").execute(db).await?;
    }
    let path = key_path(db).await?;
    if !path.try_exists()? {
        let count: i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM executions)+(SELECT count(*) FROM imported_remote_originals)")
            .fetch_one(db)
            .await?;
        ensure!(count == 0, "execution plan key missing; recovery required");
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::File::open(path.parent().unwrap())?.sync_all()?;
    }
    plan_key(db).await?;
    let interrupted =
        sqlx::query("SELECT command_id,request_hash FROM executions WHERE state='RUNNING'")
            .fetch_all(db)
            .await?;
    let mut tx = db.begin().await?;
    for row in interrupted {
        let id: String = row.get("command_id");
        let result = unknown(&id, "AGENT_RESTARTED");
        let hash: String = row.get("request_hash");
        let encrypted = seal(db, &format!("result:{hash}"), result.encode_to_vec()).await?;
        sqlx::query("UPDATE executions SET state='UNKNOWN',result=?,updated_at=? WHERE command_id=? AND state='RUNNING'")
            .bind(encrypted).bind(now()).bind(id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Force a center-generation/plan binding before remote firewall admission.
/// This value-free identity is retained even when an old receipt is pruned.
pub(crate) async fn bind_firewall_authority(
    db: &SqlitePool,
    id: &str,
    authority: &str,
    hash: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO firewall_execution_authorities(command_id,authority,request_hash) VALUES(?,?,?) ON CONFLICT(command_id) DO NOTHING")
        .bind(id).bind(authority).bind(hash).execute(db).await?;
    let (saved, saved_hash): (String, String) = sqlx::query_as(
        "SELECT authority,request_hash FROM firewall_execution_authorities WHERE command_id=?",
    )
    .bind(id)
    .fetch_one(db)
    .await?;
    ensure!(
        saved == authority && saved_hash == hash,
        "FORBIDDEN: remote firewall command authority or plan"
    );
    Ok(())
}
pub(crate) async fn firewall_authority_matches(
    db: &SqlitePool,
    id: &str,
    authority: &str,
) -> Result<Option<bool>> {
    let saved: Option<String> = sqlx::query_scalar(
        "SELECT authority FROM firewall_execution_authorities WHERE command_id=?",
    )
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(saved.map(|v| v == authority))
}

pub fn unknown(id: &str, reason: &str) -> TaskResult {
    TaskResult {
        command_id: id.into(),
        state: TaskState::Unknown as i32,
        error: ErrorCode::OutcomeUnknown as i32,
        result_json: serde_json::to_vec(&serde_json::json!({"reason":reason})).unwrap(),
    }
}

fn running(id: &str) -> TaskResult {
    TaskResult {
        command_id: id.into(),
        state: TaskState::Running as i32,
        error: ErrorCode::Unspecified as i32,
        result_json: b"{}".to_vec(),
    }
}

/// None grants this worker execution. Some is a stored receipt or a running
/// admission, so concurrent duplicates never enter the underlying operation.
pub async fn claim(
    db: &SqlitePool,
    command: &ReadCommand,
    hash: &str,
) -> Result<Option<TaskResult>> {
    let encrypted = seal(db, &format!("plan:{hash}"), command.encode_to_vec()).await?;
    let inserted = sqlx::query("INSERT INTO executions(command_id,operation,idempotency_key,request_hash,plan,state,created_at,updated_at,expires_at) VALUES(?,?,?,?,?,'RUNNING',?,?,?) ON CONFLICT(command_id) DO NOTHING")
        .bind(&command.command_id).bind(command.operation).bind(&command.idempotency_key).bind(hash).bind(encrypted).bind(now()).bind(now()).bind(command.expires_at_unix_ms)
        .execute(db).await?.rows_affected();
    if inserted == 1 {
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT operation,idempotency_key,request_hash,result FROM executions WHERE command_id=?",
    )
    .bind(&command.command_id)
    .fetch_one(db)
    .await?;
    ensure!(
        row.get::<i32, _>("operation") == command.operation
            && row.get::<String, _>("idempotency_key") == command.idempotency_key
            && row.get::<String, _>("request_hash") == hash,
        "CONFLICT"
    );
    Ok(Some(match row.get::<Option<Vec<u8>>, _>("result") {
        Some(bytes) => decode_receipt(db, hash, bytes).await?,
        None => running(&command.command_id),
    }))
}

pub async fn finish(db: &SqlitePool, hash: &str, result: TaskResult) -> Result<TaskResult> {
    let encrypted = seal(db, &format!("result:{hash}"), result.encode_to_vec()).await?;
    let changed = sqlx::query("UPDATE executions SET state=?,result=?,updated_at=? WHERE command_id=? AND request_hash=? AND state='RUNNING'")
        .bind(TaskState::try_from(result.state)?.as_str_name()).bind(encrypted).bind(now())
        .bind(&result.command_id).bind(hash).execute(db).await?.rows_affected();
    ensure!(changed == 1, "execution admission lost; recovery required");
    // Unresolved admissions are never evicted. Expired commands cannot execute
    // again after terminal retention ends, even if a receipt has been pruned.
    sqlx::query("DELETE FROM executions WHERE state NOT IN ('RUNNING','UNKNOWN') AND updated_at<? AND expires_at<?")
        .bind(now()-7*86400000).bind(now()).execute(db).await?;
    Ok(result)
}

/// This path never dispatches an operation or creates an execution record.
pub async fn receipt(db: &SqlitePool, id: &str) -> Result<TaskResult> {
    ensure!(uuid::Uuid::parse_str(id).is_ok(), "INVALID_ARGUMENT");
    if let Some(row) = sqlx::query("SELECT result,request_hash FROM executions WHERE command_id=?")
        .bind(id)
        .fetch_optional(db)
        .await?
    {
        return match row.get::<Option<Vec<u8>>, _>("result") {
            Some(bytes) => decode_receipt(db, &row.get::<String, _>("request_hash"), bytes).await,
            None => Ok(running(id)),
        };
    }
    if let Some(bytes) =
        sqlx::query_scalar::<_, Vec<u8>>("SELECT result FROM results WHERE command_id=?")
            .bind(id)
            .fetch_optional(db)
            .await?
    {
        return Ok(TaskResult::decode(bytes.as_slice())?);
    }
    Ok(unknown(id, "RECEIPT_NOT_FOUND"))
}

/// Authenticate an existing UNKNOWN plan. This cannot create or admit work.
pub async fn pending_plan(db: &SqlitePool, id: &str) -> Result<Option<(ReadCommand, String)>> {
    ensure!(uuid::Uuid::parse_str(id).is_ok(), "INVALID_ARGUMENT");
    let Some(row) = sqlx::query("SELECT operation,idempotency_key,request_hash,plan FROM executions WHERE command_id=? AND state='UNKNOWN'")
        .bind(id).fetch_optional(db).await? else { return Ok(None) };
    let hash: String = row.get("request_hash");
    let bytes = unseal(db, &format!("plan:{hash}"), row.get("plan")).await?;
    let plan = ReadCommand::decode(bytes.as_slice())?;
    ensure!(
        plan.command_id == id
            && plan.operation == row.get::<i32, _>("operation")
            && plan.idempotency_key == row.get::<String, _>("idempotency_key")
            && format!("{:x}", Sha256::digest(plan.encode_to_vec())) == hash,
        "execution plan identity mismatch"
    );
    Ok(Some((plan, hash)))
}

/// Store proof and terminal receipt atomically. Concurrent queries preserve the
/// first resolution; no query calls claim() or any system operation.
pub async fn resolve(db: &SqlitePool, hash: &str, result: TaskResult) -> Result<TaskResult> {
    ensure!(
        matches!(
            TaskState::try_from(result.state)?,
            TaskState::Succeeded | TaskState::Failed
        ),
        "terminal proof required"
    );
    let value: serde_json::Value = serde_json::from_slice(&result.result_json)?;
    let evidence = &value["reconciliation"];
    let source = evidence["source"].as_str().unwrap_or("");
    ensure!(
        matches!(
            source,
            "network.journal.v1"
                | "configuration.journal.v1"
                | "ordinary.boot.journal.v1"
                | "ordinary.handoff.journal.v1"
                | "system.control.journal.v1"
                | "firewall.remote.journal.v1"
                | "nm.coordinator.journal.v1"
        ) && evidence["commandId"] == result.command_id,
        "invalid reconciliation proof"
    );
    let digest = evidence["journalSha256"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("proof digest required"))?;
    ensure!(
        digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid proof digest"
    );
    let encrypted = seal(db, &format!("result:{hash}"), result.encode_to_vec()).await?;
    let mut tx = db.begin().await?;
    let changed = sqlx::query("UPDATE executions SET state=?,result=?,updated_at=? WHERE command_id=? AND request_hash=? AND state='UNKNOWN'")
        .bind(TaskState::try_from(result.state)?.as_str_name()).bind(encrypted).bind(now()).bind(&result.command_id).bind(hash)
        .execute(&mut *tx).await?.rows_affected();
    if changed == 1 {
        sqlx::query("INSERT INTO execution_resolutions(command_id,request_hash,source,journal_sha256,resolved_at) VALUES(?,?,?,?,?)")
            .bind(&result.command_id).bind(hash).bind(source).bind(digest).bind(now()).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    receipt(db, &result.command_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    fn command() -> ReadCommand {
        ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation: 6,
            idempotency_key: "once".into(),
            expires_at_unix_ms: i64::MAX,
            network_action: Some(yofc_management_protocol::v1::NetworkAction {
                transaction_id: uuid::Uuid::new_v4().to_string(),
                confirmation_token: "private-test-confirmation-token".into(),
            }),
            ..Default::default()
        }
    }
    fn hash(c: &ReadCommand) -> String {
        format!("{:x}", Sha256::digest(c.encode_to_vec()))
    }
    async fn open() -> (PathBuf, SqlitePool) {
        let path =
            std::env::temp_dir().join(format!("yofc-execution-{}.sqlite", uuid::Uuid::new_v4()));
        let db = crate::transport::database(path.to_str().unwrap())
            .await
            .unwrap();
        (path, db)
    }
    async fn close(path: PathBuf, db: SqlitePool) {
        db.close().await;
        fs::remove_file(&path).unwrap();
        fs::remove_file(format!("{}.plan-key", path.display())).unwrap();
    }
    #[tokio::test]
    async fn concurrent_duplicates_admit_once_and_encrypt_the_execution_plan() {
        let (path, db) = open().await;
        let c = command();
        let h = hash(&c);
        let (a, b) = tokio::join!(claim(&db, &c, &h), claim(&db, &c, &h));
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_ne!(a.is_none(), b.is_none());
        let row = sqlx::query("SELECT plan FROM executions WHERE command_id=?")
            .bind(&c.command_id)
            .fetch_one(&db)
            .await
            .unwrap();
        let sealed: Vec<u8> = row.get("plan");
        assert!(
            !sealed
                .windows(31)
                .any(|v| v == b"private-test-confirmation-token")
        );
        let nonce: [u8; 12] = sealed[1..13].try_into().unwrap();
        let mut encrypted = sealed[13..].to_vec();
        let key = plan_key(&db).await.unwrap();
        let plaintext = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(format!("plan:{h}").as_bytes()),
                &mut encrypted,
            )
            .unwrap();
        assert_eq!(ReadCommand::decode(&*plaintext).unwrap(), c);
        let mut changed = c.clone();
        changed.expires_at_unix_ms -= 1;
        assert!(claim(&db, &changed, &hash(&changed)).await.is_err());
        close(path, db).await;
    }
    #[tokio::test]
    async fn restart_preserves_uncertainty_and_never_grants_a_second_execution() {
        let (path, db) = open().await;
        let c = command();
        let h = hash(&c);
        assert!(claim(&db, &c, &h).await.unwrap().is_none());
        db.close().await;
        let db = crate::transport::database(path.to_str().unwrap())
            .await
            .unwrap();
        let result = claim(&db, &c, &h).await.unwrap().unwrap();
        assert_eq!(result.state, TaskState::Unknown as i32);
        assert_eq!(result.error, ErrorCode::OutcomeUnknown as i32);
        assert_eq!(receipt(&db, &c.command_id).await.unwrap(), result);
        close(path, db).await;
    }
    #[tokio::test]
    async fn completed_receipt_survives_restart_and_query_cannot_admit_missing_work() {
        let (path, db) = open().await;
        let c = command();
        let h = hash(&c);
        claim(&db, &c, &h).await.unwrap();
        let completed = TaskResult {
            command_id: c.command_id.clone(),
            state: TaskState::Succeeded as i32,
            error: 0,
            result_json: b"{}".to_vec(),
        };
        finish(&db, &h, completed.clone()).await.unwrap();
        db.close().await;
        let db = crate::transport::database(path.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(receipt(&db, &c.command_id).await.unwrap(), completed);
        let absent = receipt(&db, &uuid::Uuid::new_v4().to_string())
            .await
            .unwrap();
        assert_eq!(absent.state, TaskState::Unknown as i32);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM executions")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 1);
        close(path, db).await;
    }
    #[tokio::test]
    async fn missing_or_unsafe_key_fails_closed_for_retained_admissions() {
        let (path, db) = open().await;
        let c = command();
        claim(&db, &c, &hash(&c)).await.unwrap();
        let key = key_path(&db).await.unwrap();
        db.close().await;
        let backup = key.with_extension("saved");
        fs::rename(&key, &backup).unwrap();
        assert!(
            crate::transport::database(path.to_str().unwrap())
                .await
                .is_err()
        );
        fs::rename(backup, &key).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            crate::transport::database(path.to_str().unwrap())
                .await
                .is_err()
        );
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let db = crate::transport::database(path.to_str().unwrap())
            .await
            .unwrap();
        close(path, db).await;
    }
    #[tokio::test]
    async fn encrypted_results_reject_tampering_and_cannot_grant_execution_again() {
        let (path, db) = open().await;
        let c = command();
        let h = hash(&c);
        claim(&db, &c, &h).await.unwrap();
        let result = TaskResult {
            command_id: c.command_id.clone(),
            state: TaskState::Succeeded as i32,
            error: 0,
            result_json: b"{\"token\":\"private-test-confirmation-token\"}".to_vec(),
        };
        finish(&db, &h, result.clone()).await.unwrap();
        let mut encrypted: Vec<u8> =
            sqlx::query_scalar("SELECT result FROM executions WHERE command_id=?")
                .bind(&c.command_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            !encrypted
                .windows(31)
                .any(|v| v == b"private-test-confirmation-token")
        );
        assert_eq!(receipt(&db, &c.command_id).await.unwrap(), result);
        let index = encrypted.len() - 1;
        encrypted[index] ^= 1;
        sqlx::query("UPDATE executions SET result=? WHERE command_id=?")
            .bind(encrypted)
            .bind(&c.command_id)
            .execute(&db)
            .await
            .unwrap();
        assert!(receipt(&db, &c.command_id).await.is_err());
        assert!(claim(&db, &c, &h).await.is_err());
        close(path, db).await;
    }
    #[tokio::test]
    async fn retention_never_evicts_unresolved_or_still_valid_command_identity() {
        let (path, db) = open().await;
        let valid = command();
        let pending = command();
        for c in [&valid, &pending] {
            claim(&db, c, &hash(c)).await.unwrap();
        }
        finish(
            &db,
            &hash(&valid),
            TaskResult {
                command_id: valid.command_id.clone(),
                state: TaskState::Succeeded as i32,
                error: 0,
                result_json: b"{}".to_vec(),
            },
        )
        .await
        .unwrap();
        sqlx::query("UPDATE executions SET updated_at=?")
            .bind(now() - 8 * 86400000)
            .execute(&db)
            .await
            .unwrap();
        let trigger = command();
        claim(&db, &trigger, &hash(&trigger)).await.unwrap();
        finish(
            &db,
            &hash(&trigger),
            TaskResult {
                command_id: trigger.command_id,
                state: TaskState::Expired as i32,
                error: ErrorCode::Timeout as i32,
                result_json: b"{}".to_vec(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            receipt(&db, &valid.command_id).await.unwrap().state,
            TaskState::Succeeded as i32
        );
        assert!(
            claim(&db, &pending, &hash(&pending))
                .await
                .unwrap()
                .is_some()
        );
        close(path, db).await;
    }
    #[tokio::test]
    async fn authenticated_pending_plan_and_concurrent_proof_are_durable_and_atomic() {
        let (path, db) = open().await;
        let c = command();
        let h = hash(&c);
        claim(&db, &c, &h).await.unwrap();
        assert!(pending_plan(&db, &c.command_id).await.unwrap().is_none());
        db.close().await;
        let db = crate::transport::database(path.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(
            pending_plan(&db, &c.command_id).await.unwrap().unwrap(),
            (c.clone(), h.clone())
        );
        let result = TaskResult { command_id:c.command_id.clone(), state:TaskState::Succeeded as i32,error:0,
            result_json:serde_json::to_vec(&serde_json::json!({"state":"COMMITTED","reconciliation":{
                "source":"network.journal.v1","commandId":c.command_id,"journalSha256":"ab".repeat(32)
            }})).unwrap() };
        let (a, b) = tokio::join!(
            resolve(&db, &h, result.clone()),
            resolve(&db, &h, result.clone())
        );
        assert_eq!(a.unwrap(), result);
        assert_eq!(b.unwrap(), result);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM execution_resolutions")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 1);
        let source: String =
            sqlx::query_scalar("SELECT source FROM execution_resolutions WHERE command_id=?")
                .bind(&c.command_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(source, "network.journal.v1");
        assert!(pending_plan(&db, &c.command_id).await.unwrap().is_none());
        db.close().await;
        let db = crate::transport::database(path.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(receipt(&db, &c.command_id).await.unwrap(), result);
        assert!(claim(&db, &c, &h).await.unwrap().is_some());
        let unknown = uuid::Uuid::new_v4().to_string();
        assert!(pending_plan(&db, &unknown).await.unwrap().is_none());
        close(path, db).await;
    }
    #[tokio::test]
    async fn configuration_resolution_preserves_its_own_journal_source() {
        let (path, db) = open().await;
        let c = command();
        let h = hash(&c);
        claim(&db, &c, &h).await.unwrap();
        finish(&db, &h, unknown(&c.command_id, "INTERRUPTED"))
            .await
            .unwrap();
        let result = TaskResult { command_id:c.command_id.clone(), state:TaskState::Succeeded as i32,error:0,
            result_json:serde_json::to_vec(&serde_json::json!({"submitted":true,"reconciliation":{
                "source":"configuration.journal.v1","commandId":c.command_id,"journalSha256":"cd".repeat(32)
            }})).unwrap() };
        resolve(&db, &h, result.clone()).await.unwrap();
        let source: String =
            sqlx::query_scalar("SELECT source FROM execution_resolutions WHERE command_id=?")
                .bind(&c.command_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(source, "configuration.journal.v1");
        assert_eq!(receipt(&db, &c.command_id).await.unwrap(), result);
        close(path, db).await;
    }
    #[tokio::test]
    async fn corrupt_or_relabelled_pending_plan_cannot_be_used_as_business_proof() {
        let (path, db) = open().await;
        let c = command();
        let h = hash(&c);
        claim(&db, &c, &h).await.unwrap();
        initialize(&db).await.unwrap();
        sqlx::query("UPDATE executions SET operation=7 WHERE command_id=?")
            .bind(&c.command_id)
            .execute(&db)
            .await
            .unwrap();
        assert!(pending_plan(&db, &c.command_id).await.is_err());
        sqlx::query("UPDATE executions SET operation=6,plan=x'00' WHERE command_id=?")
            .bind(&c.command_id)
            .execute(&db)
            .await
            .unwrap();
        assert!(pending_plan(&db, &c.command_id).await.is_err());
        assert_eq!(
            receipt(&db, &c.command_id).await.unwrap().state,
            TaskState::Unknown as i32
        );
        close(path, db).await;
    }
}
