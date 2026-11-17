use super::*;
use ring::aead::{self, UnboundKey};
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

struct Fixture {
    root: PathBuf,
    pool: SqlitePool,
    key: LessSafeKey,
    initialization: String,
}

impl Fixture {
    async fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("kura-source-inspection-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let pool = crate::transport::database(root.join("results.sqlite").to_str().unwrap())
            .await
            .unwrap();
        let initialization = uuid::Uuid::new_v4().to_string();
        sqlx::query("CREATE TABLE native_profile_generation(singleton INTEGER PRIMARY KEY CHECK(singleton=1),operation_id TEXT NOT NULL)")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO native_profile_generation VALUES(1,?)")
            .bind(&initialization)
            .execute(&pool)
            .await
            .unwrap();
        let key = super::super::plan_key(&pool).await.unwrap();
        Self {
            root,
            pool,
            key,
            initialization,
        }
    }

    fn command(&self) -> ReadCommand {
        ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation: 1,
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            expires_at_unix_ms: i64::MAX,
            ..Default::default()
        }
    }

    async fn claim(&self, command: &ReadCommand) -> String {
        let hash = format!("{:x}", Sha256::digest(command.encode_to_vec()));
        assert!(
            super::super::claim(&self.pool, command, &hash)
                .await
                .unwrap()
                .is_none()
        );
        hash
    }

    async fn terminal(&self, command: &ReadCommand) {
        let hash = self.claim(command).await;
        super::super::finish(
            &self.pool,
            &hash,
            TaskResult {
                command_id: command.command_id.clone(),
                state: TaskState::Succeeded as i32,
                error: 0,
                result_json: b"{\"agentAvailable\":true}".to_vec(),
            },
        )
        .await
        .unwrap();
    }

    async fn inspect(&self) -> Result<Inventory> {
        inspect(&self.pool, &self.key, &self.initialization).await
    }
}

#[tokio::test]
async fn terminal_running_and_unknown_records_are_authenticated_without_recovery_or_replay() {
    let fixture = Fixture::new().await;
    let completed = fixture.command();
    fixture.terminal(&completed).await;
    let running = fixture.command();
    fixture.claim(&running).await;
    let unknown = fixture.command();
    let hash = fixture.claim(&unknown).await;
    super::super::finish(
        &fixture.pool,
        &hash,
        super::super::unknown(&unknown.command_id, "ACK_LOST"),
    )
    .await
    .unwrap();
    let before: Vec<(String, String, Vec<u8>, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT command_id,state,plan,result FROM executions ORDER BY command_id")
            .fetch_all(&fixture.pool)
            .await
            .unwrap();
    let inventory = fixture.inspect().await.unwrap();
    assert_eq!(inventory.table_counts["executions"], 3);
    assert_eq!(inventory.execution_states["RUNNING"], 1);
    assert_eq!(inventory.execution_states["UNKNOWN"], 1);
    assert_eq!(inventory.execution_states["SUCCEEDED"], 1);
    assert_eq!(inventory.unresolved_executions, 2);
    assert!(!inventory.records_changed && !inventory.replay_performed);
    let after: Vec<(String, String, Vec<u8>, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT command_id,state,plan,result FROM executions ORDER BY command_id")
            .fetch_all(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(before, after);
    let public = serde_json::to_string(&inventory).unwrap();
    for value in [
        &completed.command_id,
        &running.command_id,
        &unknown.idempotency_key,
    ] {
        assert!(!public.contains(value));
    }
}

#[tokio::test]
async fn wrong_installation_is_refused_before_any_retained_plan_is_decrypted() {
    let fixture = Fixture::new().await;
    let command = fixture.command();
    fixture.claim(&command).await;
    sqlx::query("UPDATE executions SET plan=x'00'")
        .execute(&fixture.pool)
        .await
        .unwrap();
    let error = inspect(
        &fixture.pool,
        &fixture.key,
        &uuid::Uuid::new_v4().to_string(),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("different native installation"));
    assert!(
        fixture
            .inspect()
            .await
            .unwrap_err()
            .to_string()
            .contains("ciphertext")
    );
}

#[tokio::test]
async fn wrong_key_and_relabelled_ciphertext_cannot_authenticate_a_retained_admission() {
    let fixture = Fixture::new().await;
    let a = fixture.command();
    fixture.terminal(&a).await;
    let b = fixture.command();
    fixture.terminal(&b).await;
    let wrong = LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &[9u8; 32]).unwrap());
    assert!(
        inspect(&fixture.pool, &wrong, &fixture.initialization)
            .await
            .is_err()
    );
    let plan: Vec<u8> = sqlx::query_scalar("SELECT plan FROM executions WHERE command_id=?")
        .bind(&a.command_id)
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE executions SET plan=? WHERE command_id=?")
        .bind(plan)
        .bind(&b.command_id)
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert!(fixture.inspect().await.is_err());
}

#[tokio::test]
async fn changed_hash_identity_or_receipt_fate_is_refused_without_a_repair() {
    for sql in [
        "UPDATE executions SET request_hash='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
        "UPDATE executions SET idempotency_key='different-original'",
        "UPDATE executions SET state='FAILED'",
        "UPDATE executions SET result=x'0102'",
        "UPDATE executions SET result=NULL",
    ] {
        let fixture = Fixture::new().await;
        let command = fixture.command();
        fixture.terminal(&command).await;
        sqlx::query(sql).execute(&fixture.pool).await.unwrap();
        assert!(fixture.inspect().await.is_err(), "{sql}");
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM executions")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);
    }
}

#[tokio::test]
async fn unreviewed_tables_views_triggers_columns_and_null_terminal_receipts_are_not_adopted() {
    for sql in [
        "CREATE TABLE surprise(value TEXT)",
        "CREATE VIEW surprise AS SELECT command_id FROM executions",
        "CREATE TRIGGER surprise AFTER INSERT ON executions BEGIN SELECT 1; END",
        "ALTER TABLE executions ADD COLUMN surprise TEXT",
    ] {
        let fixture = Fixture::new().await;
        sqlx::query(sql).execute(&fixture.pool).await.unwrap();
        assert!(fixture.inspect().await.is_err(), "{sql}");
    }
}

#[tokio::test]
async fn original_legacy_read_cache_and_pruned_auxiliary_history_are_retained() {
    let fixture = Fixture::new().await;
    let command = fixture.command();
    let result = TaskResult {
        command_id: command.command_id.clone(),
        state: TaskState::Succeeded as i32,
        error: 0,
        result_json: b"{}".to_vec(),
    };
    sqlx::query("INSERT INTO results(command_id,operation,idempotency_key,result,created_at) VALUES(?,?,?,?,?)")
        .bind(&command.command_id).bind(1).bind(&command.idempotency_key).bind(result.encode_to_vec()).bind(1i64)
        .execute(&fixture.pool).await.unwrap();
    let pruned = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO execution_resolutions VALUES(?,?,?,?,?)")
        .bind(&pruned)
        .bind("a".repeat(64))
        .bind("kura.configuration")
        .bind("b".repeat(64))
        .bind(1i64)
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO firewall_execution_authorities VALUES(?,?,?)")
        .bind(pruned)
        .bind("c".repeat(64))
        .bind("a".repeat(64))
        .execute(&fixture.pool)
        .await
        .unwrap();
    let before = fixture.inspect().await.unwrap();
    assert_eq!(before.table_counts["results"], 1);
    assert_eq!(before.table_counts["executions"], 0);
    assert_eq!(before.table_counts["execution_resolutions"], 1);
    assert_eq!(before.table_counts["firewall_execution_authorities"], 1);
    assert_eq!(fixture.inspect().await.unwrap(), before);
}

#[tokio::test]
async fn authenticated_imported_originals_are_preserved_with_their_original_authority() {
    use yofc_management_protocol::imported::{Envelope, Proposal, Request};
    let fixture = Fixture::new().await;
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
    let mut command = fixture.command();
    command.operation = 40;
    command.imported_firewall = Some(envelope.to_wire().unwrap());
    let hash = fixture.claim(&command).await;
    super::super::imported::bind(&fixture.pool, &command, &"d".repeat(64), &hash)
        .await
        .unwrap();
    let before = fixture.inspect().await.unwrap();
    assert_eq!(before.table_counts["imported_remote_originals"], 1);
    assert_eq!(before.unresolved_executions, 1);
    assert_eq!(fixture.inspect().await.unwrap(), before);
    sqlx::query("UPDATE imported_remote_originals SET authority=?")
        .bind("e".repeat(64))
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert!(fixture.inspect().await.is_err());
}

fn retained_bytes(path: &Path) -> Vec<u8> {
    #[cfg(target_os = "linux")]
    let no_atime = libc::O_NOATIME;
    #[cfg(not(target_os = "linux"))]
    let no_atime = 0;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | no_atime)
        .open(path)
        .unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    bytes
}

fn original_files(root: &Path) -> BTreeMap<String, (Vec<u64>, Vec<u8>)> {
    [
        "results.sqlite",
        "results.sqlite-wal",
        "results.sqlite-shm",
        "results.sqlite.plan-key",
    ]
    .into_iter()
    .filter_map(|name| {
        let path = root.join(name);
        if !path.exists() {
            return None;
        }
        let metadata = fs::symlink_metadata(&path).unwrap();
        let identity = vec![
            metadata.dev(),
            metadata.ino(),
            metadata.mode() as u64,
            metadata.uid() as u64,
            metadata.gid() as u64,
            metadata.nlink(),
            metadata.size(),
            metadata.atime() as u64,
            metadata.atime_nsec() as u64,
            metadata.mtime() as u64,
            metadata.mtime_nsec() as u64,
            metadata.ctime() as u64,
            metadata.ctime_nsec() as u64,
        ];
        Some((name.into(), (identity, retained_bytes(&path))))
    })
    .collect()
}

#[tokio::test]
async fn a_private_readonly_wal_copy_is_inspected_without_opening_or_changing_original_state() {
    let fixture = Fixture::new().await;
    let command = fixture.command();
    fixture.terminal(&command).await;
    let expected = fixture.inspect().await.unwrap();
    let before = original_files(&fixture.root);
    assert!(!before["results.sqlite-wal"].1.is_empty());
    let copy = fixture.root.with_extension("readonly-copy");
    fs::create_dir(&copy).unwrap();
    for name in ["results.sqlite", "results.sqlite-wal"] {
        fs::write(copy.join(name), &before[name].1).unwrap();
    }
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(copy.join("results.sqlite"))
                .read_only(true)
                .create_if_missing(false)
                .pragma("trusted_schema", "OFF")
                .pragma("query_only", "ON"),
        )
        .await
        .unwrap();
    let inspected = inspect(&pool, &fixture.key, &fixture.initialization)
        .await
        .unwrap();
    assert_eq!(inspected, expected);
    pool.close().await;
    assert_eq!(original_files(&fixture.root), before);
    assert_eq!(fixture.inspect().await.unwrap(), expected);
}

#[tokio::test]
async fn expired_terminal_admissions_are_not_pruned_or_reclassified_by_inspection() {
    let fixture = Fixture::new().await;
    let mut command = fixture.command();
    command.expires_at_unix_ms = 1;
    fixture.terminal(&command).await;
    sqlx::query("UPDATE executions SET updated_at=0")
        .execute(&fixture.pool)
        .await
        .unwrap();
    let before = fixture.inspect().await.unwrap();
    assert_eq!(before.execution_states["SUCCEEDED"], 1);
    assert_eq!(before, fixture.inspect().await.unwrap());
}
