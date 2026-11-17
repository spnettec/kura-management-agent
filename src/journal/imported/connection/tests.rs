use super::*;
use yofc_management_protocol::imported::{OriginalCommands, Proposal};
fn session(at: i64) -> String {
    format!("{at}:{}:{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4())
}
async fn admitted(db: &SqlitePool, request: Request, authority: &str) -> Original {
    let input = Envelope {
        owner_key: request.needs_owner_key().then(|| "c".repeat(64)),
        request,
    };
    let command = ReadCommand {
        command_id: uuid::Uuid::new_v4().to_string(),
        operation: input.request.operation(),
        idempotency_key: "connection-guard-fixture".into(),
        expires_at_unix_ms: i64::MAX,
        imported_firewall: Some(input.to_wire().unwrap()),
        ..Default::default()
    };
    let hash = format!("{:x}", Sha256::digest(command.encode_to_vec()));
    super::super::super::claim(db, &command, &hash)
        .await
        .unwrap();
    bind(db, &command, authority, &hash).await.unwrap();
    load(db, &command.command_id, authority).await.unwrap()
}
fn evidence(original: &Original) -> DecisionEvidence {
    DecisionEvidence {
        record_sha256: "e".repeat(64),
        historical: false,
        source_observation: false,
        forward_intent: true,
        forward_acknowledged: true,
        inverse_intent: false,
        inverse_acknowledged: false,
        negative_acknowledged: false,
        confirmed_decision: false,
        commands: Some(OriginalCommands {
            original_sha256: original.checked_binding().unwrap().1.into(),
            forward_sha256: Some("f".repeat(64)),
            inverse_sha256: None,
            confirmation_sha256: None,
            cancellation_sha256: None,
            expiry_decision: false,
        }),
    }
}
async fn fixture() -> (std::path::PathBuf, SqlitePool, Original, Original) {
    let root = std::env::temp_dir().join(format!("imported-connection-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let db = crate::transport::database(root.join("state.db").to_str().unwrap())
        .await
        .unwrap();
    let original = admitted(
        &db,
        Request::Prepare {
            proposal: Proposal {
                operation_id: uuid::Uuid::new_v4(),
                expected_revision: 0,
                source_digest: "a".repeat(64),
                cohort_digest: "b".repeat(64),
                confirm_seconds: 120,
                candidate: serde_json::json!({}),
                destination_prefixes: Default::default(),
            },
        },
        &"d".repeat(64),
    )
    .await;
    let confirm = admitted(
        &db,
        Request::Confirm {
            original_task_id: uuid::Uuid::parse_str(&original.command.command_id).unwrap(),
        },
        &"d".repeat(64),
    )
    .await;
    (root, db, original, confirm)
}
#[tokio::test]
async fn post_ack_connection_refuses_same_pre_effect_reused_future_clock_rollback_and_stale_worker()
{
    let (root, db, original, confirm) = fixture().await;
    let old = session(900);
    let current = session(1100);
    let ack = evidence(&original);
    assert!(
        !ready(&db, &original, &current, Some(&current), 1200)
            .await
            .unwrap()
    );
    assert!(
        record_confirmation(&db, &original, &confirm, &current, Some(&current), 1200)
            .await
            .is_err()
    );
    let mut no_ack = ack.clone();
    no_ack.forward_acknowledged = false;
    assert!(note_ack(&db, &original, &no_ack, &old, 1000).await.is_err());
    note_ack(&db, &original, &ack, &old, 1000).await.unwrap();
    let pre = session(999);
    let exact = session(1000);
    let future = session(1300);
    for (candidate, live, now) in [
        (&old, &old, 1200),
        (&pre, &pre, 1200),
        (&exact, &exact, 1200),
        (&future, &future, 1200),
        (&current, &current, 999),
        (&current, &old, 1200),
    ] {
        assert!(
            !ready(&db, &original, candidate, Some(live), now)
                .await
                .unwrap()
        );
        assert!(
            record_confirmation(&db, &original, &confirm, candidate, Some(live), now)
                .await
                .is_err()
        );
    }
    let old_parts: Vec<_> = old.split(':').collect();
    let new_parts: Vec<_> = current.split(':').collect();
    for reused in [
        format!("1100:{}:{}", old_parts[1], new_parts[2]),
        format!("1100:{}:{}", new_parts[1], old_parts[2]),
    ] {
        assert!(
            !ready(&db, &original, &reused, Some(&reused), 1200)
                .await
                .unwrap()
        );
    }
    assert!(
        ready(&db, &original, &current, Some(&current), 1200)
            .await
            .unwrap()
    );
    // A later observer cannot move the first barrier or make its own old stream fresh.
    note_ack(&db, &original, &ack, &current, 1200)
        .await
        .unwrap();
    assert!(
        ready(&db, &original, &current, Some(&current), 1200)
            .await
            .unwrap()
    );
    assert_eq!(
        barrier(&db, &original).await.unwrap().unwrap().after_ms,
        1000
    );
    db.close().await;
    std::fs::remove_dir_all(root).unwrap();
}
#[tokio::test]
async fn encrypted_connection_confirmation_survives_restart_but_is_never_recreated_or_relabelled() {
    let (root, db, original, confirm) = fixture().await;
    let inspection_key = crate::journal::plan_key(&db).await.unwrap();
    assert_eq!(inspect_existing(&db, &inspection_key).await.unwrap(), (0, 0));
    let old = session(900);
    let current = session(1100);
    let ack = evidence(&original);
    note_ack(&db, &original, &ack, &old, 1000).await.unwrap();
    assert!(!confirmed(&db, &original, &confirm).await.unwrap());
    assert_eq!(inspect_existing(&db, &inspection_key).await.unwrap(), (1, 0));
    record_confirmation(&db, &original, &confirm, &current, Some(&current), 1200)
        .await
        .unwrap();
    assert_eq!(inspect_existing(&db, &inspection_key).await.unwrap(), (1, 1));
    let bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT record FROM imported_remote_connection_confirmations WHERE command_id=?",
    )
    .bind(&confirm.command.command_id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert!(
        !bytes
            .windows(current.len())
            .any(|v| v == current.as_bytes())
    );
    assert!(!bytes.windows(16).any(|v| v == b"barrier_sha256\":\""));
    db.close().await;
    let db = crate::transport::database(root.join("state.db").to_str().unwrap())
        .await
        .unwrap();
    assert!(confirmed(&db, &original, &confirm).await.unwrap());
    let next = admitted(
        &db,
        Request::Confirm {
            original_task_id: uuid::Uuid::parse_str(&original.command.command_id).unwrap(),
        },
        &"d".repeat(64),
    )
    .await;
    assert!(!confirmed(&db, &original, &next).await.unwrap());
    sqlx::query(
        "INSERT INTO imported_remote_connection_confirmations(command_id,record) VALUES(?,?)",
    )
    .bind(&next.command.command_id)
    .bind(bytes)
    .execute(&db)
    .await
    .unwrap();
    assert!(confirmed(&db, &original, &next).await.is_err());
    assert!(inspect_existing(&db, &inspection_key).await.is_err());
    let wrong = admitted(
        &db,
        Request::Confirm {
            original_task_id: uuid::Uuid::parse_str(&original.command.command_id).unwrap(),
        },
        &"e".repeat(64),
    )
    .await;
    assert!(
        record_confirmation(&db, &original, &wrong, &current, Some(&current), 1200)
            .await
            .is_err()
    );
    let mut changed = evidence(&original);
    changed.commands.as_mut().unwrap().original_sha256 = "0".repeat(64);
    assert!(
        note_ack(&db, &original, &changed, &old, 1000)
            .await
            .is_err()
    );
    let mut changed = evidence(&original);
    changed.commands.as_mut().unwrap().forward_sha256 = Some("0".repeat(64));
    assert!(
        note_ack(&db, &original, &changed, &old, 1000)
            .await
            .is_err()
    );
    sqlx::query("DELETE FROM imported_remote_connection_confirmations")
        .execute(&db)
        .await
        .unwrap();
    assert!(!confirmed(&db, &original, &confirm).await.unwrap());
    assert!(
        ready(&db, &original, &current, Some(&current), 1200)
            .await
            .unwrap()
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM imported_remote_connection_confirmations")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(count, 0);
    assert_eq!(inspect_existing(&db, &inspection_key).await.unwrap(), (1, 0));
    db.close().await;
    std::fs::remove_dir_all(root).unwrap();
}
