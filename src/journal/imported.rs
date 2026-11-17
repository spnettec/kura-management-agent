//! Durable remote principal -> original admission binding. This is an encrypted
//! capability index, not an execution queue. Reads never create or claim work.
pub(crate) mod connection;
use super::*;
use anyhow::Context;
use yofc_management_protocol::imported::Envelope;

pub(super) async fn initialize(db: &SqlitePool) -> Result<()> {
    sqlx::query("CREATE TABLE IF NOT EXISTS imported_remote_originals(command_id TEXT PRIMARY KEY,operation_id TEXT UNIQUE,authority TEXT NOT NULL,request_hash TEXT NOT NULL,plan BLOB NOT NULL)")
        .execute(db).await?;
    connection::initialize(db).await?;
    Ok(())
}
fn envelope(command: &ReadCommand) -> Result<Envelope> {
    ensure!(
        matches!(command.operation, 40..=44 | 47) && command.valid_payload(),
        "INVALID_ARGUMENT: imported original"
    );
    Envelope::from_wire(
        command
            .imported_firewall
            .as_ref()
            .context("INVALID_ARGUMENT")?,
        command.operation,
    )
}
fn identity(command: &ReadCommand, authority: &str, hash: &str) -> Result<String> {
    ensure!(
        uuid::Uuid::parse_str(&command.command_id).is_ok()
            && authority.len() == 64
            && hash == format!("{:x}", Sha256::digest(command.encode_to_vec())),
        "CONFLICT: imported original identity"
    );
    Ok(format!(
        "remote-{:x}",
        Sha256::digest(serde_json::to_vec(&[
            "firewall.imported.original.v1",
            authority,
            &command.command_id,
            hash
        ])?)
    ))
}
pub(crate) async fn bind(
    db: &SqlitePool,
    command: &ReadCommand,
    authority: &str,
    hash: &str,
) -> Result<String> {
    let input = envelope(command)?;
    let request_id = identity(command, authority, hash)?;
    let claimed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM executions WHERE command_id=? AND request_hash=? AND operation=? AND state='RUNNING')")
        .bind(&command.command_id).bind(hash).bind(command.operation).fetch_one(db).await?;
    ensure!(claimed, "FORBIDDEN: original admission required");
    let encrypted = seal(
        db,
        &format!("imported-original:{authority}:{hash}"),
        command.encode_to_vec(),
    )
    .await?;
    sqlx::query("INSERT INTO imported_remote_originals(command_id,operation_id,authority,request_hash,plan) SELECT ?,?,?,?,? WHERE (SELECT count(*) FROM imported_remote_originals)<1024 ON CONFLICT(command_id) DO NOTHING")
        .bind(&command.command_id).bind(input.request.original_operation().map(|id|id.to_string()))
        .bind(authority).bind(hash).bind(encrypted).execute(db).await?;
    let saved = load(db, &command.command_id, authority).await?;
    ensure!(
        saved.command == *command && saved.request_id == request_id,
        "CONFLICT: imported original changed"
    );
    Ok(request_id)
}
pub(crate) struct Original {
    pub command: ReadCommand,
    pub request_id: String,
    authority: String,
    request_hash: String,
}
impl Original {
    pub(crate) fn checked_binding(&self) -> Result<(&str, &str)> {
        ensure!(
            identity(&self.command, &self.authority, &self.request_hash)? == self.request_id,
            "CONFLICT: authenticated original changed after lookup"
        );
        Ok((&self.authority, &self.request_hash))
    }
}
pub(crate) async fn load(db: &SqlitePool, id: &str, authority: &str) -> Result<Original> {
    ensure!(
        uuid::Uuid::parse_str(id).is_ok(),
        "INVALID_ARGUMENT: original task ID"
    );
    let row = sqlx::query("SELECT operation_id,authority,request_hash,plan FROM imported_remote_originals WHERE command_id=?")
        .bind(id).fetch_optional(db).await?.context("OUTCOME_UNKNOWN: original imported admission unavailable;never replace or resend")?;
    ensure!(
        row.get::<String, _>("authority") == authority,
        "FORBIDDEN: original center binding generation"
    );
    let hash: String = row.get("request_hash");
    let bytes = unseal(
        db,
        &format!("imported-original:{authority}:{hash}"),
        row.get("plan"),
    )
    .await?;
    decoded_original(&bytes, id, authority, &hash, row.get("operation_id"))
}

fn decoded_original(
    bytes: &[u8],
    id: &str,
    authority: &str,
    hash: &str,
    operation_id: Option<String>,
) -> Result<Original> {
    let command = ReadCommand::decode(bytes)?;
    let input = envelope(&command)?;
    ensure!(
        command.command_id == id
            && input.request.original_operation().map(|id| id.to_string()) == operation_id,
        "CONFLICT: imported original plan identity"
    );
    let request_id = identity(&command, authority, hash)?;
    Ok(Original {
        command,
        request_id,
        authority: authority.into(),
        request_hash: hash.into(),
    })
}

pub(super) fn inspect_existing(
    key: &ring::aead::LessSafeKey,
    id: &str,
    operation_id: Option<String>,
    authority: &str,
    hash: &str,
    encrypted: &[u8],
) -> Result<Original> {
    let bytes = super::unseal_with_key(
        key,
        &format!("imported-original:{authority}:{hash}"),
        encrypted,
    )?;
    decoded_original(&bytes, id, authority, hash, operation_id)
}

pub(super) async fn load_inspected(
    db: &SqlitePool,
    key: &ring::aead::LessSafeKey,
    id: &str,
) -> Result<Original> {
    let row = sqlx::query("SELECT operation_id,authority,request_hash,plan FROM imported_remote_originals WHERE command_id=?")
        .bind(id).fetch_optional(db).await?
        .context("retained imported original missing")?;
    let authority: String = row.try_get("authority")?;
    let hash: String = row.try_get("request_hash")?;
    let encrypted: Vec<u8> = row.try_get("plan")?;
    inspect_existing(
        key,
        id,
        row.try_get("operation_id")?,
        &authority,
        &hash,
        &encrypted,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use yofc_management_protocol::imported::{Proposal, Request};
    fn command() -> ReadCommand {
        let envelope = Envelope {
            request: Request::Prepare {
                proposal: Proposal {
                    operation_id: uuid::Uuid::new_v4(),
                    expected_revision: 7,
                    source_digest: "a".repeat(64),
                    cohort_digest: "b".repeat(64),
                    confirm_seconds: 90,
                    candidate: serde_json::json!({"schemaVersion":4}),
                    destination_prefixes: BTreeMap::new(),
                },
            },
            owner_key: Some("c".repeat(64)),
        };
        ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation: 40,
            idempotency_key: "original".into(),
            expires_at_unix_ms: i64::MAX,
            imported_firewall: Some(envelope.to_wire().unwrap()),
            ..Default::default()
        }
    }
    #[tokio::test]
    async fn original_capability_is_encrypted_generation_bound_and_survives_receipt_pruning() {
        let path = std::env::temp_dir().join(format!(
            "yofc-imported-original-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let db = crate::transport::database(path.to_str().unwrap())
            .await
            .unwrap();
        let c = command();
        let hash = format!("{:x}", Sha256::digest(c.encode_to_vec()));
        let authority = "d".repeat(64);
        assert!(load(&db, &c.command_id, &authority).await.is_err());
        assert!(bind(&db, &c, &authority, &hash).await.is_err());
        assert!(super::super::claim(&db, &c, &hash).await.unwrap().is_none());
        let request = bind(&db, &c, &authority, &hash).await.unwrap();
        assert!(load(&db, &c.command_id, &"e".repeat(64)).await.is_err());
        let encrypted: Vec<u8> =
            sqlx::query_scalar("SELECT plan FROM imported_remote_originals WHERE command_id=?")
                .bind(&c.command_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            !encrypted
                .windows(64)
                .any(|v| v == "c".repeat(64).as_bytes())
        );
        sqlx::query("DELETE FROM executions")
            .execute(&db)
            .await
            .unwrap();
        assert_eq!(
            load(&db, &c.command_id, &authority)
                .await
                .unwrap()
                .request_id,
            request
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM executions")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 0);
        let mut replacement = c.clone();
        replacement.command_id = uuid::Uuid::new_v4().to_string();
        let replacement_hash = format!("{:x}", Sha256::digest(replacement.encode_to_vec()));
        super::super::claim(&db, &replacement, &replacement_hash)
            .await
            .unwrap();
        assert!(
            bind(&db, &replacement, &authority, &replacement_hash)
                .await
                .is_err()
        );
        db.close().await;
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(format!("{}.plan-key", path.display())).unwrap();
    }
    #[tokio::test]
    async fn changed_original_or_relabelled_ciphertext_never_becomes_query_authority() {
        let path = std::env::temp_dir().join(format!(
            "yofc-imported-tamper-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let db = crate::transport::database(path.to_str().unwrap())
            .await
            .unwrap();
        let c = command();
        let hash = format!("{:x}", Sha256::digest(c.encode_to_vec()));
        let authority = "d".repeat(64);
        super::super::claim(&db, &c, &hash).await.unwrap();
        bind(&db, &c, &authority, &hash).await.unwrap();
        let mut changed = c.clone();
        changed.expires_at_unix_ms -= 1;
        assert!(bind(&db, &changed, &authority, &hash).await.is_err());
        sqlx::query("UPDATE imported_remote_originals SET authority=?")
            .bind("e".repeat(64))
            .execute(&db)
            .await
            .unwrap();
        assert!(load(&db, &c.command_id, &"e".repeat(64)).await.is_err());
        assert!(load(&db, &c.command_id, &authority).await.is_err());
        db.close().await;
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(format!("{}.plan-key", path.display())).unwrap();
    }
}
