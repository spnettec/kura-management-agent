//! Post-ACK management connectivity audit. Never native/Core write authority.
use super::*;
use serde::{Deserialize, Serialize};
use yofc_management_protocol::imported::{DecisionEvidence, Request};

pub(super) async fn initialize(db: &SqlitePool) -> Result<()> {
    sqlx::query("CREATE TABLE IF NOT EXISTS imported_remote_connection_barriers(command_id TEXT PRIMARY KEY,record BLOB NOT NULL)").execute(db).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS imported_remote_connection_confirmations(command_id TEXT PRIMARY KEY,record BLOB NOT NULL)").execute(db).await?;
    Ok(())
}
#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Barrier {
    schema: u8,
    authority: String,
    original_id: String,
    original_hash: String,
    forward_hash: String,
    after_ms: i64,
    blocked: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Confirmation {
    schema: u8,
    barrier_sha256: String,
    command_hash: String,
    connected: String,
    verified_at: i64,
}
struct Witness<'a> {
    connected_at: i64,
    nonce: &'a str,
    epoch: &'a str,
}
fn witness(value: &str) -> Result<Witness<'_>> {
    let fields: Vec<_> = value.split(':').collect();
    ensure!(
        fields.len() == 3 && value.len() <= 128,
        "CONFLICT: management connection witness"
    );
    let connected_at: i64 = fields[0].parse()?;
    ensure!(
        connected_at > 0
            && connected_at.to_string() == fields[0]
            && fields[1..]
                .iter()
                .all(|v| uuid::Uuid::parse_str(v)
                    .is_ok_and(|id| !id.is_nil() && id.to_string() == *v)),
        "CONFLICT: locally minted connection identity"
    );
    Ok(Witness {
        connected_at,
        nonce: fields[1],
        epoch: fields[2],
    })
}
fn original_binding(original: &Original) -> Result<(&str, &str)> {
    ensure!(
        original.command.operation == 40,
        "CONFLICT: connection requires original preparation"
    );
    original.checked_binding()
}
fn barrier_aad(original: &Original) -> Result<String> {
    let (authority, hash) = original_binding(original)?;
    Ok(format!("imported-connection-barrier:{authority}:{hash}"))
}
impl Barrier {
    fn require(&self, original: &Original) -> Result<()> {
        let (authority, hash) = original_binding(original)?;
        let blocked = witness(&self.blocked)?;
        ensure!(
            self.schema == 1
                && self.authority == authority
                && self.original_id == original.command.command_id
                && self.original_hash == hash
                && self.forward_hash.len() == 64
                && self
                    .forward_hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && self.after_ms > 0
                && blocked.connected_at <= self.after_ms,
            "CONFLICT: original ACK connection barrier"
        );
        Ok(())
    }
    fn permits(&self, session: &str, current: Option<&str>, now: i64) -> bool {
        let Ok(candidate) = witness(session) else {
            return false;
        };
        let Ok(blocked) = witness(&self.blocked) else {
            return false;
        };
        current == Some(session)
            && candidate.nonce != blocked.nonce
            && candidate.epoch != blocked.epoch
            && now >= self.after_ms
            && candidate.connected_at > self.after_ms
            && candidate.connected_at <= now
    }
    fn digest(&self) -> Result<String> {
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }
}
async fn barrier(db: &SqlitePool, original: &Original) -> Result<Option<Barrier>> {
    let encrypted: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT record FROM imported_remote_connection_barriers WHERE command_id=?",
    )
    .bind(&original.command.command_id)
    .fetch_optional(db)
    .await?;
    let Some(encrypted) = encrypted else {
        return Ok(None);
    };
    let saved: Barrier =
        serde_json::from_slice(&unseal(db, &barrier_aad(original)?, encrypted).await?)?;
    saved.require(original)?;
    Ok(Some(saved))
}
/// Called only after the SAME checked original metadata proves the forward ACK.
/// Missing barriers are conservatively repaired at the current observation time.
pub(crate) async fn note_ack(
    db: &SqlitePool,
    original: &Original,
    evidence: &DecisionEvidence,
    blocked: &str,
    now: i64,
) -> Result<()> {
    let (authority, hash) = original_binding(original)?;
    ensure!(
        evidence.valid() && !evidence.source_observation && evidence.forward_acknowledged,
        "CONFLICT: connection barrier requires original forward ACK"
    );
    let commands = evidence
        .commands
        .as_ref()
        .context("CONFLICT: original command phase audit")?;
    ensure!(
        commands.original_sha256 == hash,
        "CONFLICT: connection original command"
    );
    let forward_hash = commands
        .forward_sha256
        .as_ref()
        .context("CONFLICT: forward command audit")?;
    if let Some(saved) = barrier(db, original).await? {
        ensure!(
            saved.forward_hash == *forward_hash,
            "CONFLICT: original forward command changed"
        );
        return Ok(());
    }
    let proposed = Barrier {
        schema: 1,
        authority: authority.into(),
        original_id: original.command.command_id.clone(),
        original_hash: hash.into(),
        forward_hash: forward_hash.clone(),
        after_ms: now,
        blocked: blocked.into(),
    };
    proposed.require(original)?;
    let encrypted = seal(db, &barrier_aad(original)?, serde_json::to_vec(&proposed)?).await?;
    sqlx::query("INSERT INTO imported_remote_connection_barriers(command_id,record) SELECT ?,? WHERE (SELECT count(*) FROM imported_remote_connection_barriers)<1024 ON CONFLICT(command_id) DO NOTHING")
        .bind(&original.command.command_id).bind(encrypted).execute(db).await?;
    let saved = barrier(db, original)
        .await?
        .context("RESOURCE_EXHAUSTED: connection barrier inventory")?;
    ensure!(
        saved.forward_hash == *forward_hash,
        "CONFLICT: original forward command changed"
    );
    Ok(())
}
pub(crate) async fn ready(
    db: &SqlitePool,
    original: &Original,
    session: &str,
    current: Option<&str>,
    now: i64,
) -> Result<bool> {
    Ok(barrier(db, original)
        .await?
        .is_some_and(|b| b.permits(session, current, now)))
}
fn confirmation_aad(original: &Original, command: &Original) -> Result<String> {
    let (authority, hash) = original_binding(original)?;
    let (current_authority, command_hash) = command.checked_binding()?;
    ensure!(
        current_authority == authority
            && command.command.operation == 42
            && envelope(&command.command)?.request
                == Request::Confirm {
                    original_task_id: uuid::Uuid::parse_str(&original.command.command_id)?
                },
        "FORBIDDEN: original confirmation command binding"
    );
    Ok(format!(
        "imported-connection-confirmation:{authority}:{hash}:{command_hash}"
    ))
}
pub(crate) async fn record_confirmation(
    db: &SqlitePool,
    original: &Original,
    command: &Original,
    session: &str,
    current: Option<&str>,
    now: i64,
) -> Result<()> {
    let aad = confirmation_aad(original, command)?;
    let barrier = barrier(db, original)
        .await?
        .context("CONFLICT: original post-ACK connection barrier missing")?;
    ensure!(
        barrier.permits(session, current, now),
        "CONFLICT: reconnect after apply before confirmation"
    );
    let saved = Confirmation {
        schema: 1,
        barrier_sha256: barrier.digest()?,
        command_hash: command.checked_binding()?.1.into(),
        connected: session.into(),
        verified_at: now,
    };
    let encrypted = seal(db, &aad, serde_json::to_vec(&saved)?).await?;
    sqlx::query("INSERT INTO imported_remote_connection_confirmations(command_id,record) SELECT ?,? WHERE (SELECT count(*) FROM imported_remote_connection_confirmations)<1024 ON CONFLICT(command_id) DO NOTHING")
        .bind(&command.command.command_id).bind(encrypted).execute(db).await?;
    ensure!(
        confirmed(db, original, command).await?,
        "OUTCOME_UNKNOWN: original connection confirmation publication unavailable;query only"
    );
    Ok(())
}
/// Read existing proof only. No current grant/clock/connection can reconstruct it.
pub(crate) async fn confirmed(
    db: &SqlitePool,
    original: &Original,
    command: &Original,
) -> Result<bool> {
    let aad = confirmation_aad(original, command)?;
    let encrypted: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT record FROM imported_remote_connection_confirmations WHERE command_id=?",
    )
    .bind(&command.command.command_id)
    .fetch_optional(db)
    .await?;
    let Some(encrypted) = encrypted else {
        return Ok(false);
    };
    let Some(barrier) = barrier(db, original).await? else {
        return Ok(false);
    };
    let saved: Confirmation = serde_json::from_slice(&unseal(db, &aad, encrypted).await?)?;
    ensure!(
        saved.schema == 1
            && saved.command_hash == command.checked_binding()?.1
            && saved.barrier_sha256 == barrier.digest()?
            && barrier.permits(&saved.connected, Some(&saved.connected), saved.verified_at),
        "CONFLICT: original persisted connection confirmation"
    );
    Ok(true)
}
#[cfg(test)]
mod tests;
