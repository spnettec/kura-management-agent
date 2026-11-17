//! Read-only authentication of retained execution data. This module does not
//! initialize a database, recover RUNNING work, prune receipts, or dispatch it.
use super::*;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use sqlx::{Column, TypeInfo, ValueRef, sqlite::SqliteRow};
use std::collections::{BTreeMap, BTreeSet};

const SCHEMAS: &[(&str, &[(&str, &str)])] = &[
    (
        "execution_resolutions",
        &[
            ("command_id", "TEXT"),
            ("request_hash", "TEXT"),
            ("source", "TEXT"),
            ("journal_sha256", "TEXT"),
            ("resolved_at", "INTEGER"),
        ],
    ),
    (
        "executions",
        &[
            ("command_id", "TEXT"),
            ("operation", "INTEGER"),
            ("idempotency_key", "TEXT"),
            ("request_hash", "TEXT"),
            ("plan", "BLOB"),
            ("state", "TEXT"),
            ("result", "BLOB"),
            ("created_at", "INTEGER"),
            ("updated_at", "INTEGER"),
            ("expires_at", "INTEGER"),
        ],
    ),
    (
        "firewall_execution_authorities",
        &[
            ("command_id", "TEXT"),
            ("authority", "TEXT"),
            ("request_hash", "TEXT"),
        ],
    ),
    (
        "imported_remote_connection_barriers",
        &[("command_id", "TEXT"), ("record", "BLOB")],
    ),
    (
        "imported_remote_connection_confirmations",
        &[("command_id", "TEXT"), ("record", "BLOB")],
    ),
    (
        "imported_remote_originals",
        &[
            ("command_id", "TEXT"),
            ("operation_id", "TEXT"),
            ("authority", "TEXT"),
            ("request_hash", "TEXT"),
            ("plan", "BLOB"),
        ],
    ),
    (
        "native_profile_generation",
        &[("singleton", "INTEGER"), ("operation_id", "TEXT")],
    ),
    (
        "results",
        &[
            ("command_id", "TEXT"),
            ("operation", "INTEGER"),
            ("idempotency_key", "TEXT"),
            ("result", "BLOB"),
            ("created_at", "INTEGER"),
            ("request_hash", "TEXT"),
        ],
    ),
];
const MAX_ROWS: i64 = 1_000_000;
const PAGE_ROWS: i64 = 8;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Inventory {
    pub schema_version: u32,
    pub profile: String,
    pub initialization_id: String,
    pub table_counts: BTreeMap<String, u64>,
    pub execution_states: BTreeMap<String, u64>,
    pub unresolved_executions: u64,
    pub schema_sha256: String,
    pub logical_sha256: String,
    pub records_changed: bool,
    pub replay_performed: bool,
}

fn hash_field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

fn hash_row(digest: &mut Sha256, row: &SqliteRow) -> Result<()> {
    for (index, column) in row.columns().iter().enumerate() {
        hash_field(digest, column.name().as_bytes());
        let value = row.try_get_raw(index)?;
        if value.is_null() {
            hash_field(digest, b"NULL");
            continue;
        }
        let kind = value.type_info().name().to_owned();
        hash_field(digest, kind.as_bytes());
        match kind.as_str() {
            "INTEGER" => hash_field(digest, &row.try_get::<i64, _>(index)?.to_be_bytes()),
            "TEXT" => hash_field(digest, row.try_get::<String, _>(index)?.as_bytes()),
            "BLOB" => {
                let bytes: Vec<u8> = row.try_get(index)?;
                hash_field(digest, &(bytes.len() as u64).to_be_bytes());
                hash_field(digest, &Sha256::digest(bytes));
            }
            _ => anyhow::bail!("unreviewed retained SQLite value type"),
        }
    }
    Ok(())
}

fn sha(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid retained digest"
    );
    Ok(())
}

fn command_identity(id: &str, idempotency_key: &str) -> Result<()> {
    ensure!(
        uuid::Uuid::parse_str(id).is_ok()
            && !idempotency_key.is_empty()
            && idempotency_key.len() <= 64,
        "invalid retained command identity"
    );
    Ok(())
}

async fn schema(db: &SqlitePool) -> Result<String> {
    let mut seen = BTreeSet::new();
    let mut digest = Sha256::new();
    for row in sqlx::query("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")
        .fetch_all(db)
        .await?
    {
        let kind: String = row.try_get("type")?;
        let name: String = row.try_get("name")?;
        let table: String = row.try_get("tbl_name")?;
        let definition: Option<String> = row.try_get("sql")?;
        match kind.as_str() {
            "table" => {
                ensure!(
                    SCHEMAS.iter().any(|(n, _)| *n == name) && table == name,
                    "unreviewed retained table"
                );
                seen.insert(name);
            }
            "index" => ensure!(
                definition.is_none()
                    && name.starts_with(&format!("sqlite_autoindex_{table}_"))
                    && SCHEMAS.iter().any(|(n, _)| *n == table),
                "unreviewed retained index"
            ),
            _ => anyhow::bail!(
                "retained views, triggers and virtual schema are not source maintenance"
            ),
        }
        hash_row(&mut digest, &row)?;
    }
    ensure!(
        seen == SCHEMAS.iter().map(|(n, _)| n.to_string()).collect(),
        "retained schema is incomplete"
    );
    for (name, columns) in SCHEMAS {
        let query = format!("PRAGMA table_xinfo({name})");
        let rows = sqlx::query(&query).fetch_all(db).await?;
        ensure!(rows.len() == columns.len(), "retained columns changed");
        for (index, (row, (column, kind))) in rows.iter().zip(columns.iter()).enumerate() {
            ensure!(
                row.try_get::<i64, _>("cid")? == index as i64
                    && row.try_get::<String, _>("name")? == *column
                    && row.try_get::<String, _>("type")? == *kind
                    && row.try_get::<i64, _>("hidden")? == 0
                    && row.try_get::<i64, _>("pk")? == i64::from(index == 0),
                "retained column definition differs"
            );
        }
    }
    let checked: String = sqlx::query_scalar("PRAGMA quick_check(1)")
        .fetch_one(db)
        .await?;
    ensure!(
        checked == "ok",
        "retained SQLite integrity requires original recovery"
    );
    Ok(format!("{:x}", digest.finalize()))
}

async fn validate_execution(db: &SqlitePool, key: &LessSafeKey, row: &SqliteRow) -> Result<String> {
    let id: String = row.try_get("command_id")?;
    let idempotency: String = row.try_get("idempotency_key")?;
    command_identity(&id, &idempotency)?;
    let hash: String = row.try_get("request_hash")?;
    sha(&hash)?;
    let encrypted: Vec<u8> = row.try_get("plan")?;
    let bytes = super::unseal_with_key(key, &format!("plan:{hash}"), &encrypted)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == hash,
        "retained plan digest differs"
    );
    let command = ReadCommand::decode(bytes.as_slice())?;
    let expires: i64 = row.try_get("expires_at")?;
    ensure!(
        command.command_id == id
            && command.idempotency_key == idempotency
            && command.operation == row.try_get::<i32, _>("operation")?
            && (command.expires_at_unix_ms == expires || expires == i64::MAX),
        "retained plan binding differs"
    );
    // Refused/expired input can be a legitimate persisted admission. Inspection
    // authenticates that exact request; it never turns it into valid new work.
    let state: String = row.try_get("state")?;
    let parsed = TaskState::from_str_name(&state).context("unreviewed retained execution state")?;
    let encrypted: Option<Vec<u8>> = row.try_get("result")?;
    if let Some(encrypted) = encrypted {
        let bytes = super::unseal_with_key(key, &format!("result:{hash}"), &encrypted)?;
        let result = TaskResult::decode(bytes.as_slice())?;
        ensure!(
            result.command_id == id && result.state == parsed as i32,
            "retained receipt binding differs"
        );
    } else {
        ensure!(
            matches!(state.as_str(), "RUNNING" | "UNKNOWN"),
            "retained original receipt missing"
        );
    }
    // These lookups remain inside the already generation-bound copy.
    if let Some(resolution) = sqlx::query_scalar::<_, String>(
        "SELECT request_hash FROM execution_resolutions WHERE command_id=?",
    )
    .bind(&id)
    .fetch_optional(db)
    .await?
    {
        ensure!(resolution == hash, "retained resolution binding differs");
    }
    Ok(state)
}

async fn validate_row(
    db: &SqlitePool,
    key: &LessSafeKey,
    name: &str,
    row: &SqliteRow,
) -> Result<Option<String>> {
    match name {
        "executions" => return Ok(Some(validate_execution(db, key, row).await?)),
        "results" => {
            let id: String = row.try_get("command_id")?;
            command_identity(&id, &row.try_get::<String, _>("idempotency_key")?)?;
            let operation: i32 = row.try_get("operation")?;
            let hash: Option<String> = row.try_get("request_hash")?;
            if let Some(hash) = hash {
                sha(&hash)?;
            } else {
                ensure!(
                    operation <= 3,
                    "legacy cached write lacks its original request binding"
                );
            }
            let bytes: Vec<u8> = row.try_get("result")?;
            let result = TaskResult::decode(bytes.as_slice())?;
            ensure!(
                result.command_id == id && TaskState::try_from(result.state).is_ok(),
                "legacy cached receipt differs"
            );
        }
        "execution_resolutions" => {
            uuid::Uuid::parse_str(&row.try_get::<String, _>("command_id")?)?;
            sha(&row.try_get::<String, _>("request_hash")?)?;
            sha(&row.try_get::<String, _>("journal_sha256")?)?;
            let source: String = row.try_get("source")?;
            ensure!(
                !source.is_empty() && source.len() <= 256,
                "retained resolution source differs"
            );
        }
        "firewall_execution_authorities" => {
            let id: String = row.try_get("command_id")?;
            uuid::Uuid::parse_str(&id)?;
            let hash: String = row.try_get("request_hash")?;
            sha(&hash)?;
            sha(&row.try_get::<String, _>("authority")?)?;
            if let Some((operation, saved)) = sqlx::query_as::<_, (i32, String)>(
                "SELECT operation,request_hash FROM executions WHERE command_id=?",
            )
            .bind(id)
            .fetch_optional(db)
            .await?
            {
                ensure!(
                    matches!(operation, 31..=33 | 38..=48) && saved == hash,
                    "retained firewall authority differs"
                );
            }
        }
        "imported_remote_originals" => {
            let id: String = row.try_get("command_id")?;
            let authority: String = row.try_get("authority")?;
            sha(&authority)?;
            let hash: String = row.try_get("request_hash")?;
            sha(&hash)?;
            let encrypted: Vec<u8> = row.try_get("plan")?;
            super::imported::inspect_existing(
                key,
                &id,
                row.try_get("operation_id")?,
                &authority,
                &hash,
                &encrypted,
            )?;
        }
        "imported_remote_connection_barriers" | "imported_remote_connection_confirmations" => {
            uuid::Uuid::parse_str(&row.try_get::<String, _>("command_id")?)?;
        }
        "native_profile_generation" => {}
        _ => anyhow::bail!("unreviewed retained table"),
    }
    Ok(None)
}

pub(crate) async fn inspect(
    db: &SqlitePool,
    key: &LessSafeKey,
    initialization: &str,
) -> Result<Inventory> {
    let original = uuid::Uuid::parse_str(initialization)?;
    ensure!(
        !original.is_nil() && original.to_string() == initialization,
        "invalid original native initialization"
    );
    let schema_sha256 = schema(db).await?;
    let generations: Vec<(i64, String)> =
        sqlx::query_as("SELECT singleton,operation_id FROM native_profile_generation LIMIT 2")
            .fetch_all(db)
            .await?;
    ensure!(
        generations == [(1, initialization.into())],
        "different native installation; do not inspect saved work here"
    );
    let mut counts = BTreeMap::new();
    let mut states = BTreeMap::new();
    let mut digest = Sha256::new();
    hash_field(&mut digest, schema_sha256.as_bytes());
    for (name, columns) in SCHEMAS {
        let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {name}"))
            .fetch_one(db)
            .await?;
        ensure!(
            count <= MAX_ROWS && (!name.starts_with("imported_remote_") || count <= 1024),
            "retained record inventory limit"
        );
        counts.insert(name.to_string(), count as u64);
        hash_field(&mut digest, name.as_bytes());
        for (column, kind) in *columns {
            if matches!(*kind, "TEXT" | "BLOB") {
                let maximum: i64 = sqlx::query_scalar(&format!(
                    "SELECT coalesce(max(length(CAST({column} AS BLOB))),0) FROM {name}"
                ))
                .fetch_one(db)
                .await?;
                ensure!(
                    maximum <= (yofc_management_protocol::MAX_FRAME + 29) as i64,
                    "oversized retained value"
                );
            }
        }
        let order = columns[0].0;
        let query = format!("SELECT * FROM {name} ORDER BY {order} LIMIT ? OFFSET ?");
        let mut offset = 0;
        while offset < count {
            let rows = sqlx::query(&query)
                .bind(PAGE_ROWS)
                .bind(offset)
                .fetch_all(db)
                .await?;
            ensure!(
                !rows.is_empty(),
                "retained inventory changed during inspection"
            );
            for row in &rows {
                hash_row(&mut digest, row)?;
                if let Some(state) = validate_row(db, key, name, row).await? {
                    *states.entry(state).or_insert(0u64) += 1;
                }
            }
            offset += rows.len() as i64;
        }
        ensure!(
            offset == count,
            "retained inventory changed during inspection"
        );
    }
    let (barriers, confirmations) = super::imported::connection::inspect_existing(db, key).await?;
    ensure!(
        counts["imported_remote_connection_barriers"] == barriers
            && counts["imported_remote_connection_confirmations"] == confirmations,
        "retained connection inventory changed"
    );
    Ok(Inventory {
        schema_version: 1,
        profile: "native-execution-inventory-v1".into(),
        initialization_id: initialization.into(),
        table_counts: counts,
        unresolved_executions: states.get("RUNNING").copied().unwrap_or(0)
            + states.get("UNKNOWN").copied().unwrap_or(0),
        execution_states: states,
        schema_sha256,
        logical_sha256: format!("{:x}", digest.finalize()),
        records_changed: false,
        replay_performed: false,
    })
}

#[cfg(test)]
mod tests;
