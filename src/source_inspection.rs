//! Short-lived source-maintenance inspection, separate from the daemon. Root
//! authenticates the candidate executable and creates the private encrypted
//! copy; this process can only read data as the original native UID/cap0/NNP1.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::Duration,
};

const DATABASE: &str = "results.sqlite";
const WAL: &str = "results.sqlite-wal";
const SHM: &str = "results.sqlite-shm";
#[cfg(target_os = "linux")]
const NO_ATIME: i32 = libc::O_NOATIME;
#[cfg(not(target_os = "linux"))]
const NO_ATIME: i32 = 0;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct FileProof {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Report {
    pub schema_version: u32,
    pub profile: String,
    pub native_uid: u32,
    pub native_gid: u32,
    pub no_new_privileges: bool,
    pub input_files: BTreeMap<String, FileProof>,
    pub inventory: crate::journal::inspection::Inventory,
}

fn private_copy(directory: &Path) -> Result<()> {
    let parent = directory
        .parent()
        .context("private inspection copy required")?;
    let name = parent
        .file_name()
        .and_then(|name| name.to_str())
        .context("private inspection copy name")?;
    ensure!(
        directory.file_name().is_some_and(|name| name == "copy")
            && parent.parent() == Some(Path::new("/run"))
            && name.starts_with("kura-source-inspection-")
            && name.len() > 23
            && name.len() <= 96
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
        "FORBIDDEN: fixed Root-created inspection directory required"
    );
    let outer = fs::symlink_metadata(parent)?;
    let inner = fs::symlink_metadata(directory)?;
    ensure!(
        outer.is_dir()
            && outer.uid() == 0
            && outer.gid() == 0
            && outer.mode() & 0o7777 == 0o711
            && inner.is_dir()
            && inner.uid() == unsafe { libc::geteuid() }
            && inner.gid() == unsafe { libc::getegid() }
            && inner.mode() & 0o7777 == 0o700,
        "FORBIDDEN: private inspection directory ownership differs"
    );
    Ok(())
}

fn inputs(directory: &Path) -> Result<BTreeMap<String, FileProof>> {
    let mut proofs = BTreeMap::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("inspection copy name"))?;
        ensure!(
            matches!(name.as_str(), DATABASE | WAL | SHM),
            "unreviewed inspection copy member"
        );
        let path = directory.join(&name);
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | NO_ATIME)
            .open(&path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.gid() == unsafe { libc::getegid() }
                && metadata.mode() & 0o7777 == 0o600
                && metadata.nlink() == 1
                && metadata.len()
                    <= if name == SHM {
                        16 * 1024 * 1024
                    } else {
                        8 * 1024 * 1024 * 1024
                    },
            "unsafe inspection copy ownership, type or size"
        );
        if name == SHM {
            continue;
        }
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        let after = file.metadata()?;
        let stable = |m: &fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.mode(),
                m.uid(),
                m.gid(),
                m.nlink(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        };
        ensure!(
            stable(&metadata) == stable(&after)
                && stable(&metadata) == stable(&fs::symlink_metadata(&path)?),
            "inspection copy changed during hashing"
        );
        proofs.insert(
            name,
            FileProof {
                bytes: metadata.len(),
                sha256: format!("{:x}", digest.finalize()),
            },
        );
    }
    ensure!(
        proofs
            .get(DATABASE)
            .is_some_and(|proof| proof.bytes >= 4096),
        "inspection database missing"
    );
    Ok(proofs)
}

pub(crate) async fn run(directory: &Path, initialization: &str) -> Result<Report> {
    // This also checks the original marker, fixed native state/key inode and
    // Root-sealed key digest before any records in a copy are inspected.
    let key = crate::native_state::inspection_key(initialization).await?;
    private_copy(directory)?;
    let before = inputs(directory)?;
    let db = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(directory.join(DATABASE))
                .read_only(true)
                .create_if_missing(false)
                .busy_timeout(Duration::ZERO)
                .statement_cache_capacity(0)
                .pragma("trusted_schema", "OFF")
                .pragma("query_only", "ON")
                .pragma("cell_size_check", "ON"),
        )
        .await?;
    sqlx::query("BEGIN").execute(&db).await?;
    let inspected = tokio::time::timeout(
        Duration::from_secs(30),
        crate::journal::inspection::inspect(&db, &key, initialization),
    )
    .await;
    let rollback = sqlx::query("ROLLBACK").execute(&db).await;
    db.close().await;
    rollback?;
    let inventory =
        inspected.context("retained inspection timed out without changing source state")??;
    let after = inputs(directory)?;
    ensure!(
        before[DATABASE] == after[DATABASE],
        "read-only inspection changed its database copy"
    );
    if let Some(wal) = before.get(WAL) {
        ensure!(
            after.get(WAL) == Some(wal) || (wal.bytes == 0 && !after.contains_key(WAL)),
            "read-only inspection changed its copied WAL"
        );
    } else {
        ensure!(
            after.get(WAL).is_none_or(|wal| wal.bytes == 0),
            "inspection created nonempty WAL"
        );
    }
    Ok(Report {
        schema_version: 1,
        profile: "native-retained-state-inspection-v1".into(),
        native_uid: unsafe { libc::geteuid() },
        native_gid: unsafe { libc::getegid() },
        no_new_privileges: true,
        input_files: before,
        inventory,
    })
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn root_inspection_is_refused_before_accessing_native_metadata_or_keys() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let error = super::run(
            std::path::Path::new("/run/not-an-inspection-copy"),
            &uuid::Uuid::new_v4().to_string(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("dedicated non-Root identity"));
    }

    #[tokio::test]
    #[ignore = "explicit disposable source-inspection filesystem fixture only; never installed"]
    async fn populate_and_hold_explicit_disposable_fixture() {
        use prost::Message;
        use sha2::{Digest, Sha256};
        use yofc_management_protocol::v1::{ReadCommand, TaskResult, TaskState};
        assert_eq!(
            std::env::var("YOFC_SOURCE_INSPECTION_FIXTURE").as_deref(),
            Ok("1")
        );
        let initialization = std::env::var("YOFC_SOURCE_INSPECTION_INITIALIZATION").unwrap();
        let raw = crate::runtime_identity::protected(
            std::path::Path::new("/run/kura-source-inspection-fixture-v1.json"),
            4096,
        )
        .unwrap();
        let marker: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            marker,
            serde_json::json!({"schemaVersion":1,"profile":"explicit-disposable-source-inspection-v1","initializationId":initialization})
        );
        crate::native_state::inspection_key(&initialization)
            .await
            .unwrap();
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(
                        std::path::Path::new(crate::runtime_identity::STATE).join("results.sqlite"),
                    )
                    .create_if_missing(false),
            )
            .await
            .unwrap();
        let existing: i64 = sqlx::query_scalar("SELECT count(*) FROM executions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            existing, 0,
            "fresh explicit fixture only; never append to retained real work"
        );
        for state in ["SUCCEEDED", "UNKNOWN", "RUNNING"] {
            let command = ReadCommand {
                command_id: uuid::Uuid::new_v4().to_string(),
                operation: 1,
                idempotency_key: uuid::Uuid::new_v4().to_string(),
                expires_at_unix_ms: i64::MAX,
                ..Default::default()
            };
            let hash = format!("{:x}", Sha256::digest(command.encode_to_vec()));
            assert!(
                crate::journal::claim(&pool, &command, &hash)
                    .await
                    .unwrap()
                    .is_none()
            );
            if state != "RUNNING" {
                let result = if state == "UNKNOWN" {
                    crate::journal::unknown(&command.command_id, "EXPLICIT_FIXTURE_ACK_LOST")
                } else {
                    TaskResult {
                        command_id: command.command_id,
                        state: TaskState::Succeeded as i32,
                        error: 0,
                        result_json: b"{\"explicitFixture\":true}".to_vec(),
                    }
                };
                crate::journal::finish(&pool, &hash, result).await.unwrap();
            }
        }
        println!("SOURCE_INSPECTION_FIXTURE_READY");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        // Holding the connection keeps a real, committed nonempty WAL. The
        // parent copies it while this isolated fixture performs no more writes.
        let mut release = [0u8; 1];
        std::io::Read::read_exact(&mut std::io::stdin(), &mut release).unwrap();
        assert_eq!(release, [b'X']);
        pool.close().await;
    }
}
