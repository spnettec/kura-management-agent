//! One-shot local Root upload for native Core snapshot verification.
//! The request carries neither an installation path nor recovery authority.
use crate::{
    durable,
    snapshot_validation::{Mode, PasswordPolicy, Report, Validator},
};
use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    sync::Semaphore,
};
use uuid::Uuid;

pub(crate) const METHOD: &str = "recovery.snapshot.validate";
const MAX_SNAPSHOT: usize = 32 << 20;

#[derive(Clone)]
pub(crate) struct Service {
    runtime: PathBuf,
    slot: Arc<Semaphore>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Request {
    size: usize,
    expected_sha256: String,
    mode: Mode,
    password_policy: PasswordPolicy,
}

impl Service {
    pub(crate) fn new(runtime: PathBuf) -> Self {
        Self {
            runtime,
            slot: Arc::new(Semaphore::new(1)),
        }
    }

    pub(crate) async fn handle(
        &self,
        params: Option<&Value>,
        input: &mut (impl AsyncRead + Unpin),
    ) -> std::result::Result<Value, &'static str> {
        let request: Request = serde::Deserialize::deserialize(params.ok_or("INVALID_ARGUMENT")?)
            .map_err(|_| "INVALID_ARGUMENT")?;
        if !(1..=MAX_SNAPSHOT).contains(&request.size)
            || request.expected_sha256.len() != 64
            || !request
                .expected_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("INVALID_ARGUMENT");
        }
        let permit = self
            .slot
            .clone()
            .try_acquire_owned()
            .map_err(|_| "RESOURCE_EXHAUSTED")?;
        let mut bytes = Vec::with_capacity(request.size);
        // A half-close ends the one-shot request. The bounded read also detects
        // trailing input, without waiting for EOF if the declared size is exceeded.
        tokio::time::timeout(
            Duration::from_secs(15),
            input.take(request.size as u64 + 1).read_to_end(&mut bytes),
        )
        .await
        .map_err(|_| "TIMEOUT")?
        .map_err(|_| "INVALID_ARGUMENT")?;
        if bytes.len() != request.size || durable::hash(&bytes) != request.expected_sha256 {
            return Err("CONFLICT");
        }

        let runtime = self.runtime.clone();
        let task = tokio::task::spawn_blocking(move || {
            // Hold the slot through worker completion even if the local peer
            // times out. This request never issues a stop, placement or restore.
            let _permit = permit;
            validate_temporary(&runtime, request, bytes)
        });
        let report = tokio::time::timeout(Duration::from_secs(150), task)
            .await
            .map_err(|_| "TIMEOUT")?
            .map_err(|_| "INTERNAL")?
            .map_err(|_| "CONFLICT")?;
        Ok(json!({"snapshotValidation":report,"kuraRecoveryVerified":false}))
    }
}

fn validate_temporary(runtime: &Path, request: Request, bytes: Vec<u8>) -> Result<Report> {
    let directory = runtime.join(format!("snapshot-validation-{}", Uuid::new_v4()));
    DirBuilder::new().mode(0o700).create(&directory)?;
    let path = directory.join("snapshot");
    let validated: Result<Report> = (|| {
        {
            let mut snapshot = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            snapshot.write_all(&bytes)?;
        }
        drop(bytes);
        let proof = Validator::native_core(request.mode, request.password_policy).validate(
            &path,
            &request.expected_sha256,
            None,
        )?;
        Ok(proof.report)
    })();
    // This directory is created atomically for this request inside the
    // systemd-owned runtime directory, so shutdown also discards a crash remnant.
    let cleanup = fs::remove_dir_all(&directory);
    let report = validated?;
    cleanup?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(bytes: &[u8]) -> Value {
        json!({
            "size":bytes.len(),"expectedSha256":durable::hash(bytes),
            "mode":"plain","passwordPolicy":"authenticated"
        })
    }

    #[tokio::test]
    async fn malformed_policy_sizes_and_trailing_or_changed_payload_are_rejected_before_core() {
        let service = Service::new(PathBuf::from("/no-validation-test-runtime"));
        let input = b"<fixture/>";
        let mut request = params(input);
        request["path"] = json!("/tmp/injected");
        assert_eq!(
            service
                .handle(Some(&request), &mut &input[..])
                .await
                .unwrap_err(),
            "INVALID_ARGUMENT"
        );
        let mut request = params(input);
        request["size"] = json!(MAX_SNAPSHOT + 1);
        assert_eq!(
            service
                .handle(Some(&request), &mut &input[..])
                .await
                .unwrap_err(),
            "INVALID_ARGUMENT"
        );
        let mut request = params(input);
        request["passwordPolicy"] = json!("unknown");
        assert_eq!(
            service
                .handle(Some(&request), &mut &input[..])
                .await
                .unwrap_err(),
            "INVALID_ARGUMENT"
        );
        for data in [&input[1..], b"<fixture/>X", b"<fixtureX>"] {
            assert_eq!(
                service
                    .handle(Some(&params(input)), &mut &data[..])
                    .await
                    .unwrap_err(),
                "CONFLICT"
            );
        }
    }

    #[tokio::test]
    async fn a_single_validation_slot_bounds_the_raw_body() {
        let service = Service::new(PathBuf::from("/no-validation-test-runtime"));
        let _permit = service.slot.try_acquire().unwrap();
        let bytes = b"<fixture/>";
        assert_eq!(
            service
                .handle(Some(&params(bytes)), &mut &bytes[..])
                .await
                .unwrap_err(),
            "RESOURCE_EXHAUSTED"
        );
    }
}
