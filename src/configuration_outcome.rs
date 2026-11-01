use anyhow::Result;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use yofc_management_protocol::v1::{ErrorCode, KuraConfigurationUpdate, ReadCommand, TaskResult, TaskState};

use crate::local::Local;

pub fn params_sha256(update: &KuraConfigurationUpdate) -> Option<String> {
    let params = update.parameters(1)?;
    Some(hash(&canonical(
        params["pid"].as_str()?,
        params["expectedRevision"].as_str()?,
        params["properties"].as_object()?,
    )))
}

pub fn canonical(pid: &str, revision: &str, properties: &serde_json::Map<String, Value>) -> Vec<u8> {
    let mut out = Vec::new();
    cstring(&mut out, "kura.configuration.journal.v1");
    cstring(&mut out, pid);
    cstring(&mut out, revision);
    let mut keys: Vec<_> = properties.keys().cloned().collect();
    keys.sort();
    for key in keys {
        cstring(&mut out, &key);
        match &properties[&key] {
            Value::Bool(value) => {
                out.push(b'b');
                out.push(u8::from(*value));
            }
            Value::String(value) => {
                out.push(b's');
                cstring(&mut out, value);
            }
            Value::Array(values) if values.first().is_some_and(Value::is_boolean) => {
                out.push(b'B');
                out.extend_from_slice(&(values.len() as u32).to_be_bytes());
                for value in values {
                    out.push(u8::from(value.as_bool().unwrap_or(false)));
                }
            }
            Value::Array(values) => {
                out.push(b'S');
                out.extend_from_slice(&(values.len() as u32).to_be_bytes());
                for value in values {
                    cstring(&mut out, value.as_str().unwrap_or(""));
                }
            }
            _ => {}
        }
    }
    out
}

pub async fn prove(local: &Local, command: &ReadCommand) -> Result<Option<TaskResult>> {
    let Some(update) = &command.kura_configuration_update else {
        return Ok(None);
    };
    let Some(expected) = params_sha256(update) else {
        return Ok(None);
    };
    let found = match local
        .call_with_params(
            "kura.configuration.outcome",
            Some(json!({"commandId": command.command_id})),
        )
        .await
    {
        Ok(value) => value,
        Err("NOT_FOUND" | "UNSUPPORTED" | "KURA_UNAVAILABLE" | "TIMEOUT") => return Ok(None),
        Err(code) => anyhow::bail!(code),
    };
    if found.get("properties").is_some()
        || found["source"] != "configuration.journal.v1"
        || found["commandId"] != command.command_id
        || found["operation"] != 12
        || found["submitted"] != true
        || found["pid"] != update.pid
        || found["previousRevision"] != update.expected_revision
        || found["paramsSha256"] != expected
    {
        return Ok(None);
    }
    let digest = found["journalSha256"].as_str().unwrap_or("");
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(None);
    }
    let value = json!({
        "pid": update.pid,
        "submitted": true,
        "previousRevision": update.expected_revision,
        "reconciliation": {
            "source": "configuration.journal.v1",
            "commandId": command.command_id,
            "operation": 12,
            "pid": update.pid,
            "previousRevision": update.expected_revision,
            "paramsSha256": expected,
            "journalSha256": digest,
        }
    });
    Ok(Some(TaskResult {
        command_id: command.command_id.clone(),
        state: TaskState::Succeeded as i32,
        error: ErrorCode::Unspecified as i32,
        result_json: serde_json::to_vec(&value)?,
    }))
}

fn cstring(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(value.as_bytes());
    out.push(0);
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_vector_matches_java_and_live_values_are_not_required() {
        let update = KuraConfigurationUpdate {
            pid: "fixture.pid".into(),
            expected_revision: "a".repeat(64),
            properties: vec![
                yofc_management_protocol::v1::KuraConfigurationProperty {
                    id: "enabled".into(),
                    value: Some(yofc_management_protocol::v1::kura_configuration_property::Value::Boolean(false)),
                },
                yofc_management_protocol::v1::KuraConfigurationProperty {
                    id: "count".into(),
                    value: Some(yofc_management_protocol::v1::kura_configuration_property::Value::Text(
                        "9223372036854775807".into(),
                    )),
                },
            ],
        };
        assert_eq!(
            params_sha256(&update).unwrap(),
            "b3d96d6934d94dfce358f529132126896914f22c7322da955882791986a768c0"
        );
    }
}

#[cfg(test)]
mod prove_tests {
    use super::*;
    use crate::transport::{database, query_receipt};
    use sha2::{Digest, Sha256};
    use yofc_management_protocol::v1::KuraConfigurationProperty;

    async fn unknown(db: &sqlx::SqlitePool, command: &ReadCommand) -> String {
        let hash = format!("{:x}", Sha256::digest(prost::Message::encode_to_vec(command)));
        assert!(crate::journal::claim(db, command, &hash).await.unwrap().is_none());
        crate::journal::finish(db, &hash, crate::journal::unknown(&command.command_id, "INTERRUPTED"))
            .await
            .unwrap();
        hash
    }

    #[tokio::test]
    async fn recorded_submission_resolves_unknown_without_repeating_the_write() {
        let path = std::env::temp_dir().join(format!("config-outcome-{}.sqlite", uuid::Uuid::new_v4()));
        let db = database(path.to_str().unwrap()).await.unwrap();
        let mut local = Local::new(0, 0);
        local.enable_configuration_updates(true);
        let command = ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation: 12,
            expires_at_unix_ms: i64::MAX,
            idempotency_key: "outcome".into(),
            kura_configuration_update: Some(KuraConfigurationUpdate {
                pid: "fixture.pid".into(),
                expected_revision: "a".repeat(64),
                properties: vec![KuraConfigurationProperty {
                    id: "secret".into(),
                    value: Some(yofc_management_protocol::v1::kura_configuration_property::Value::Text(
                        "outcome-secret".into(),
                    )),
                }],
            }),
            ..Default::default()
        };
        unknown(&db, &command).await;
        let mut rx = local.install_test_bridge(&["kura.configuration.outcome"]).await;
        let worker = local.clone();
        let database = db.clone();
        let id = command.command_id.clone();
        let task = tokio::spawn(async move { query_receipt(&database, &worker, &id).await });
        let request = rx.recv().await.unwrap();
        assert_eq!(request.method, "kura.configuration.outcome");
        assert_eq!(request.params, Some(json!({"commandId":command.command_id})));
        let update = command.kura_configuration_update.as_ref().unwrap();
        local.complete_pending(&request.request_id, Some(json!({
            "source":"configuration.journal.v1","commandId":command.command_id,"operation":12,
            "pid":update.pid,"previousRevision":update.expected_revision,"submitted":true,
            "paramsSha256":params_sha256(update).unwrap(),
            "journalSha256":"a".repeat(64)
        })), None);
        let result = task.await.unwrap().unwrap();
        assert_eq!(result.state, TaskState::Succeeded as i32);
        assert!(result.result_json.windows(b"outcome-secret".len()).all(|w| w != b"outcome-secret"));
        assert_eq!(query_receipt(&db, &local, &command.command_id).await.unwrap(), result);
        db.close().await;
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(format!("{}.plan-key", path.display())).ok();
    }

    #[tokio::test]
    async fn mismatched_or_missing_submission_stays_unknown() {
        let path = std::env::temp_dir().join(format!("config-outcome-miss-{}.sqlite", uuid::Uuid::new_v4()));
        let db = database(path.to_str().unwrap()).await.unwrap();
        let mut local = Local::new(0, 0);
        local.enable_configuration_updates(true);
        let command = ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation: 12,
            expires_at_unix_ms: i64::MAX,
            idempotency_key: "outcome-miss".into(),
            kura_configuration_update: Some(KuraConfigurationUpdate {
                pid: "fixture.pid".into(),
                expected_revision: "b".repeat(64),
                properties: vec![KuraConfigurationProperty {
                    id: "enabled".into(),
                    value: Some(yofc_management_protocol::v1::kura_configuration_property::Value::Boolean(true)),
                }],
            }),
            ..Default::default()
        };
        unknown(&db, &command).await;
        let mut rx = local.install_test_bridge(&["kura.configuration.outcome"]).await;
        let worker = local.clone();
        let database = db.clone();
        let id = command.command_id.clone();
        let task = tokio::spawn(async move { query_receipt(&database, &worker, &id).await });
        let request = rx.recv().await.unwrap();
        let update = command.kura_configuration_update.as_ref().unwrap();
        local.complete_pending(&request.request_id, Some(json!({
            "source":"configuration.journal.v1","commandId":command.command_id,"operation":12,
            "pid":"other.pid","previousRevision":update.expected_revision,"submitted":true,
            "paramsSha256":params_sha256(update).unwrap(),"journalSha256":"b".repeat(64)
        })), None);
        let result = task.await.unwrap().unwrap();
        assert_eq!(result.state, TaskState::Unknown as i32);
        db.close().await;
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(format!("{}.plan-key", path.display())).ok();
    }
}
