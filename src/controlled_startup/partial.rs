use super::*;

/// A durable pre-mutation checkpoint and a failed Java receipt, never CM_APPLIED.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PartialApplication {
    pub receipt_sha256: String,
    pub backup_sha256: String,
    pub intended_sha256: String,
    pub plan_sha256: String,
    pub bundle_levels_sha256: String,
}

fn fields(bytes: &[u8]) -> Result<BTreeMap<&str, &str>> {
    let mut result = BTreeMap::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        let (key, value) = line.split_once('=').context("checkpoint line")?;
        ensure!(
            safe_value(value) && result.insert(key, value).is_none(),
            "checkpoint ambiguity"
        );
    }
    Ok(result)
}

impl Startup {
    pub fn allows_partial_source(&self) -> Result<bool> {
        Ok(self.inputs()?.0.allow_partial_source)
    }

    /// Immediate observation only: missing or incomplete evidence cannot be inferred or retried.
    pub fn partial_application(
        &self,
        p: &Prepared,
        id: &str,
        sha: &str,
        owner: FileMetadata,
    ) -> Result<PartialApplication> {
        let (_, digest) = self.inputs()?;
        ensure!(digest == p.profile_digest, "partial source profile changed");
        let read = |path: &Path, limit| -> Result<Vec<u8>> {
            let (bytes, metadata) = durable::read(path, limit)?;
            ensure!(
                metadata.mode & 0o077 == 0 && metadata.uid == owner.uid,
                "partial source owner"
            );
            Ok(bytes)
        };
        ensure!(
            durable::hash(&read(&p.request_path, 16 << 10)?) == p.request_sha256,
            "partial source request changed"
        );
        let receipt = read(&p.receipt_path, 1 << 20)?;
        let decision = fields(&receipt)?;
        ensure!(
            decision.len() == 5
                && decision.get("schema") == Some(&"1")
                && decision.get("status") == Some(&"RECOVERY_REQUIRED")
                && decision.get("restore.id") == Some(&id)
                && decision.get("fullRecoveryVerified") == Some(&"false")
                && decision.get("businessHealth") == Some(&"BLOCKED"),
            "partial source failure receipt"
        );
        let plan = read(
            &PathBuf::from(format!("{}.cm-plan.properties", p.receipt_path.display())),
            4096,
        )?;
        let checkpoint = fields(&plan)?;
        ensure!(
            checkpoint.len() == 5
                && checkpoint.get("schema") == Some(&"1")
                && checkpoint.get("restore.id") == Some(&id)
                && checkpoint.get("snapshot.sha256") == Some(&sha),
            "partial source checkpoint identity"
        );
        let backup_sha = *checkpoint
            .get("backup.sha256")
            .context("partial source backup hash")?;
        let intended_sha = *checkpoint
            .get("intended.sha256")
            .context("partial source intent hash")?;
        ensure!(
            super::digest(backup_sha) && super::digest(intended_sha),
            "partial source digest encoding"
        );
        for (suffix, expected) in [
            (".cm-backup.aes", backup_sha),
            (".cm-intended.aes", intended_sha),
        ] {
            let bytes = read(
                &PathBuf::from(format!("{}{suffix}", p.receipt_path.display())),
                64 << 20,
            )?;
            ensure!(
                !bytes.is_empty() && durable::hash(&bytes) == expected,
                "partial source checkpoint drift"
            );
        }
        let levels = read(
            &PathBuf::from(format!("{}.bundle-levels", p.receipt_path.display())),
            64 << 10,
        )?;
        ensure!(
            levels.starts_with(b"schema=1\n"),
            "partial source bundle ledger"
        );
        Ok(PartialApplication {
            receipt_sha256: durable::hash(&receipt),
            backup_sha256: backup_sha.into(),
            intended_sha256: intended_sha.into(),
            plan_sha256: durable::hash(&plan),
            bundle_levels_sha256: durable::hash(&levels),
        })
    }
}
