//! A native startup must retain its provisioned database and encryption key.
//! This is structural continuity, not proof against rollback of selected rows.
use anyhow::{Result, ensure};
use serde::Deserialize;
use sqlx::{Connection, SqliteConnection, sqlite::SqliteConnectOptions};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub(crate) const CONTINUITY: &str = "/etc/kura-management-runtime/continuity.json";
const MARKER: &str = ".native-profile-v1";
#[cfg(target_os = "linux")]
const NO_ATIME: i32 = libc::O_NOATIME;
#[cfg(not(target_os = "linux"))]
const NO_ATIME: i32 = 0;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Marker {
    schema_version: u32,
    operation_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct KeyIdentity {
    device: u64,
    inode: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RootOverlay {
    device: u64,
    overlay_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Continuity {
    schema_version: u32,
    operation_id: String,
    state_directory: String,
    database: FileIdentity,
    plan_key: KeyIdentity,
    root_overlay: Option<RootOverlay>,
}

fn original(value: &str) -> Result<()> {
    ensure!(
        uuid::Uuid::parse_str(value)?.to_string() == value,
        "INVALID_ARGUMENT: original native initialization UUID required"
    );
    Ok(())
}

fn owned(path: &Path, maximum: u64) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | NO_ATIME)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.gid() == unsafe { libc::getegid() }
            && m.mode() & 0o7777 == 0o600
            && m.nlink() == 1
            && m.len() <= maximum,
        "CONFLICT: native state file requires original recovery"
    );
    Ok(file)
}

fn marker(root: &Path, operation: &str) -> Result<()> {
    let mut file = owned(&root.join(MARKER), 4096)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let value: Marker = serde_json::from_slice(&bytes)?;
    ensure!(
        value.schema_version == 1 && value.operation_id == operation,
        "CONFLICT: native state marker differs from original initialization"
    );
    Ok(())
}

async fn check_generation(file: &File, operation: &str) -> Result<()> {
    use std::os::fd::AsRawFd;
    let options = SqliteConnectOptions::new()
        .filename(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .read_only(true)
        .immutable(true)
        .create_if_missing(false);
    let mut connection = SqliteConnection::connect_with(&options).await?;
    sqlx::query("PRAGMA trusted_schema=OFF")
        .execute(&mut connection)
        .await?;
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT singleton,operation_id FROM native_profile_generation LIMIT 2")
            .fetch_all(&mut connection)
            .await?;
    connection.close().await?;
    ensure!(
        rows == vec![(1, operation.to_owned())],
        "CONFLICT: native database generation requires original recovery"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn verified_overlay_device(proof: &RootOverlay) -> Result<u64> {
    let mut input = String::new();
    let limit = 2 * 1024 * 1024;
    File::open("/proc/self/mountinfo")?
        .take(limit + 1)
        .read_to_string(&mut input)?;
    ensure!(
        input.len() as u64 <= limit,
        "CONFLICT: native root mount record is too large"
    );
    let device = fs::metadata("/")?.dev();
    let expected_device = format!(
        "{}:{}",
        libc::major(device as libc::dev_t),
        libc::minor(device as libc::dev_t)
    );
    let mut root = None;
    for line in input.lines() {
        let (mnt, filesystem) = line
            .split_once(" - ")
            .ok_or_else(|| anyhow::anyhow!("CONFLICT: invalid kernel mount record"))?;
        let fields: Vec<&str> = mnt.split_ascii_whitespace().collect();
        ensure!(fields.len() >= 6, "CONFLICT: invalid kernel mount fields");
        if fields[4] == "/" {
            ensure!(
                root.is_none() && fields[2] == expected_device && fields[3] == "/",
                "CONFLICT: native root mount identity differs"
            );
            root = Some(filesystem);
        }
    }
    let fields: Vec<&str> = root.unwrap_or_default().split_ascii_whitespace().collect();
    ensure!(
        fields.len() == 3
            && fields[..2] == ["overlay", "overlay"]
            && crate::durable::hash(fields.join("\0").as_bytes()) == proof.overlay_sha256,
        "CONFLICT: native state overlay backing differs"
    );
    Ok(device)
}

#[cfg(not(target_os = "linux"))]
fn verified_overlay_device(_: &RootOverlay) -> Result<u64> {
    anyhow::bail!("CONFLICT: native root overlay proof requires the Linux kernel")
}

fn continuity_devices(proof: &Continuity) -> Result<(u64, u64)> {
    let Some(overlay) = &proof.root_overlay else {
        return Ok((proof.database.device, proof.plan_key.device));
    };
    ensure!(
        proof.database.device == overlay.device && proof.plan_key.device == overlay.device,
        "CONFLICT: native state original overlay device differs"
    );
    let device = verified_overlay_device(overlay)?;
    Ok((device, device))
}

async fn verify_at(root: &Path, proof: &Continuity) -> Result<()> {
    original(&proof.operation_id)?;
    ensure!(
        proof.schema_version == 1
            && proof.state_directory == root.to_str().unwrap_or("")
            && proof.plan_key.sha256.len() == 64
            && proof
                .plan_key
                .sha256
                .bytes()
                .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase()),
        "CONFLICT: native state continuity descriptor refused"
    );
    let m = fs::symlink_metadata(root)?;
    ensure!(
        m.is_dir()
            && m.uid() == unsafe { libc::geteuid() }
            && m.gid() == unsafe { libc::getegid() }
            && m.mode() & 0o7777 == 0o700,
        "CONFLICT: native state directory requires original recovery"
    );
    marker(root, &proof.operation_id)?;
    let (database_device, key_device) = continuity_devices(proof)?;
    let db = owned(&root.join("results.sqlite"), 8 * 1024 * 1024 * 1024)?;
    let db_m = db.metadata()?;
    ensure!(
        db_m.dev() == database_device
            && db_m.ino() == proof.database.inode
            && db_m.len() >= 4096,
        "CONFLICT: native database was lost or replaced"
    );
    let mut key = owned(&root.join("results.sqlite.plan-key"), 32)?;
    let key_m = key.metadata()?;
    ensure!(
        key_m.dev() == key_device
            && key_m.ino() == proof.plan_key.inode
            && key_m.len() == 32,
        "CONFLICT: native plan key was lost or replaced"
    );
    let mut bytes = [0u8; 32];
    key.read_exact(&mut bytes)?;
    let digest = crate::durable::hash(&bytes);
    bytes.fill(0);
    ensure!(
        digest == proof.plan_key.sha256,
        "CONFLICT: native plan key changed"
    );
    check_generation(&db, &proof.operation_id).await?;
    let current_db = fs::symlink_metadata(root.join("results.sqlite"))?;
    let current_key = fs::symlink_metadata(root.join("results.sqlite.plan-key"))?;
    ensure!(
        current_db.ino() == db_m.ino()
            && current_db.dev() == db_m.dev()
            && current_key.ino() == key_m.ino()
            && current_key.dev() == key_m.dev(),
        "CONFLICT: native state changed during verification"
    );
    Ok(())
}

pub(crate) async fn verified_initialization() -> Result<String> {
    let raw = crate::runtime_identity::protected(Path::new(CONTINUITY), 4096)?;
    let proof: Continuity = serde_json::from_slice(&raw)?;
    verify_at(Path::new(crate::runtime_identity::STATE), &proof).await?;
    Ok(proof.operation_id)
}

/// Read the original native plan key into the short-lived inspector only. No
/// alternate key path, copy, creation, or recovery is available through this API.
pub(crate) async fn inspection_key(operation: &str) -> Result<ring::aead::LessSafeKey> {
    crate::runtime_identity::inspection_role()?;
    original(operation)?;
    let proof: Continuity = serde_json::from_slice(&crate::runtime_identity::protected(
        Path::new(CONTINUITY),
        4096,
    )?)?;
    ensure!(
        proof.operation_id == operation,
        "CONFLICT: different native installation; do not inspect saved work here"
    );
    let root = Path::new(crate::runtime_identity::STATE);
    ensure!(
        proof.schema_version == 1
            && proof.state_directory == root.to_str().unwrap()
            && proof.plan_key.sha256.len() == 64
            && proof
                .plan_key
                .sha256
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)),
        "CONFLICT: original native inspection continuity differs"
    );
    let directory = fs::symlink_metadata(root)?;
    ensure!(
        directory.is_dir()
            && directory.uid() == unsafe { libc::geteuid() }
            && directory.gid() == unsafe { libc::getegid() }
            && directory.mode() & 0o7777 == 0o700,
        "CONFLICT: original native inspection directory differs"
    );
    marker(root, operation)?;
    let (database_device, key_device) = continuity_devices(&proof)?;
    // Never reopen the original DB through SQLite here: even an immutable
    // SQLite open can update its atime. Root binds the byte-for-byte copy, whose
    // generation is checked before any retained command is decrypted.
    let database_path = root.join("results.sqlite");
    let database = owned(&database_path, 8 * 1024 * 1024 * 1024)?;
    let database_before = database.metadata()?;
    ensure!(
        database_before.dev() == database_device
            && database_before.ino() == proof.database.inode
            && database_before.len() >= 4096,
        "CONFLICT: original native inspection database changed"
    );
    let path = root.join("results.sqlite.plan-key");
    let mut file = owned(&path, 32)?;
    let before = file.metadata()?;
    ensure!(
        before.dev() == key_device
            && before.ino() == proof.plan_key.inode
            && before.len() == 32,
        "CONFLICT: original native inspection key changed"
    );
    let mut bytes = [0u8; 32];
    file.read_exact(&mut bytes)?;
    let digest = crate::durable::hash(&bytes);
    let key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &bytes)
        .map_err(|_| anyhow::anyhow!("native inspection key refused"));
    bytes.fill(0);
    let after = file.metadata()?;
    let stable = |m: &std::fs::Metadata| {
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
        digest == proof.plan_key.sha256
            && stable(&before) == stable(&after)
            && stable(&before) == stable(&fs::symlink_metadata(&path)?)
            && stable(&database_before) == stable(&database.metadata()?)
            && stable(&database_before) == stable(&fs::symlink_metadata(&database_path)?),
        "CONFLICT: original native inspection key differs"
    );
    Ok(ring::aead::LessSafeKey::new(key?))
}

pub(crate) async fn initialize(operation: &str) -> Result<()> {
    original(operation)?;
    let root = Path::new(crate::runtime_identity::STATE);
    let db_path = root.join("results.sqlite");
    crate::runtime_identity::enforce(
        std::env::var_os("AGENT_RUNTIME_IDENTITY").map(PathBuf::from),
        &db_path,
        Path::new(crate::runtime_identity::SOCKET),
        u32::MAX,
        0,
    )?
    .ok_or_else(|| anyhow::anyhow!("FORBIDDEN: exact non-Root native profile required"))?;
    ensure!(
        !Path::new(CONTINUITY).try_exists()?,
        "CONFLICT: native continuity already exists; never initialize again"
    );
    let m = fs::symlink_metadata(root)?;
    ensure!(
        m.is_dir()
            && m.uid() == unsafe { libc::geteuid() }
            && m.gid() == unsafe { libc::getegid() }
            && m.mode() & 0o7777 == 0o700,
        "CONFLICT: native initialization directory"
    );
    marker(root, operation)?;
    let entries = fs::read_dir(root)?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        entries.len() == 1 && entries[0].file_name() == MARKER,
        "CONFLICT: retained native state must never be initialized again"
    );
    let pool = crate::transport::database(db_path.to_str().unwrap()).await?;
    sqlx::query("CREATE TABLE native_profile_generation(singleton INTEGER PRIMARY KEY CHECK(singleton=1),operation_id TEXT NOT NULL)")
        .execute(&pool).await?;
    sqlx::query("INSERT INTO native_profile_generation(singleton,operation_id) VALUES(1,?)")
        .bind(operation)
        .execute(&pool)
        .await?;
    let checkpoint: (i64, i64, i64) = sqlx::query_as("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_one(&pool)
        .await?;
    ensure!(
        checkpoint.0 == 0,
        "UNKNOWN: native initial checkpoint is busy; preserve original intent"
    );
    pool.close().await;
    owned(&db_path, 8 * 1024 * 1024 * 1024)?.sync_all()?;
    owned(&root.join("results.sqlite.plan-key"), 32)?.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn retained_native_database_and_key_are_required_without_recreation() -> Result<()> {
        let root = std::env::temp_dir().join(format!("native-continuity-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let operation = uuid::Uuid::new_v4().to_string();
        fs::write(
            root.join(MARKER),
            serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"operationId":operation}))?,
        )?;
        fs::set_permissions(root.join(MARKER), fs::Permissions::from_mode(0o600))?;
        let db_path = root.join("results.sqlite");
        let pool = crate::transport::database(db_path.to_str().unwrap()).await?;
        sqlx::query("CREATE TABLE native_profile_generation(singleton INTEGER,operation_id TEXT)")
            .execute(&pool)
            .await?;
        sqlx::query("INSERT INTO native_profile_generation VALUES(1,?)")
            .bind(&operation)
            .execute(&pool)
            .await?;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&pool)
            .await?;
        pool.close().await;
        fs::set_permissions(&db_path, fs::Permissions::from_mode(0o600))?;
        let key_path = root.join("results.sqlite.plan-key");
        let dm = fs::metadata(&db_path)?;
        let km = fs::metadata(&key_path)?;
        let proof = Continuity {
            schema_version: 1,
            operation_id: operation,
            state_directory: root.to_str().unwrap().into(),
            database: FileIdentity {
                device: dm.dev(),
                inode: dm.ino(),
            },
            plan_key: KeyIdentity {
                device: km.dev(),
                inode: km.ino(),
                sha256: crate::durable::hash(&fs::read(&key_path)?),
            },
            root_overlay: None,
        };
        verify_at(&root, &proof).await?;
        let original_key = fs::read(&key_path)?;
        fs::write(&key_path, [0u8; 32])?;
        assert!(verify_at(&root, &proof).await.is_err());
        fs::write(&key_path, &original_key)?;
        verify_at(&root, &proof).await?;
        fs::rename(&key_path, root.join("retained-plan-key"))?;
        assert!(verify_at(&root, &proof).await.is_err());
        assert!(!key_path.exists());
        fs::rename(root.join("retained-plan-key"), &key_path)?;
        let pool =
            SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&db_path)).await?;
        let mut pool = pool;
        sqlx::query("DELETE FROM native_profile_generation")
            .execute(&mut pool)
            .await?;
        pool.close().await?;
        assert!(verify_at(&root, &proof).await.is_err());
        fs::rename(&db_path, root.join("retained-results.sqlite"))?;
        assert!(verify_at(&root, &proof).await.is_err());
        assert!(!db_path.exists());
        fs::write(&db_path, b"not the retained SQLite database")?;
        fs::set_permissions(&db_path, fs::Permissions::from_mode(0o600))?;
        assert!(verify_at(&root, &proof).await.is_err());
        fs::remove_dir_all(&root)?;
        Ok(())
    }
}
