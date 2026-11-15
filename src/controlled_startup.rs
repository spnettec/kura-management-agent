//! Fixed, administrator-granted startup profile and exact Java CM application evidence.
//! CM_APPLIED is deliberately nonterminal: no implicit business success or write release.
use crate::durable::{self, FileMetadata};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

mod partial;
pub use partial::PartialApplication;

#[cfg(test)]
mod core_credential_tests {
    use super::*;

    #[test]
    fn managed_startup_uses_fingerprints_only_and_rejects_ambiguous_sources() {
        let mut parameters = vec![
            ("snapshot.mode".into(), "aes-gcm".into()),
            ("password.policy".into(), "authenticated".into()),
            ("crypto.systemd.credentials".into(), "true".into()),
            ("crypto.key.sha256".into(), "1".repeat(64)),
            ("crypto.ring.sha256".into(), "2".repeat(64)),
        ];
        let request = |values: &[(String, String)]| {
            Startup::request(
                "rec-11111111-1111-1111-1111-111111111111",
                Path::new("/private/snapshot"),
                &"3".repeat(64),
                Path::new("/private/receipt"),
                values,
            )
        };
        let output = String::from_utf8(request(&parameters).unwrap()).unwrap();
        assert!(output.contains("crypto.systemd.credentials=true\n"));
        assert!(!output.contains("crypto.key.file="));
        parameters[4].1 = "none".into();
        assert!(request(&parameters).is_ok());
        for extra in [
            ("crypto.default", "true"),
            ("crypto.key.file", "/private/key"),
        ] {
            let mut values = parameters.clone();
            values.push((extra.0.into(), extra.1.into()));
            assert!(request(&values).is_err());
        }
        for missing in 2..5 {
            let mut values = parameters.clone();
            values.remove(missing);
            assert!(request(&values).is_err());
        }
        parameters[2].1 = "false".into();
        assert!(request(&parameters).is_err());
    }
}

#[derive(Clone)]
pub struct Startup {
    config: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Config {
    schema: u32,
    unit: String,
    request_path: PathBuf,
    receipt_directory: PathBuf,
    timeout_seconds: u64,
    profile_files: Vec<ProfileFile>,
    #[serde(default)]
    allow_partial_source: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    path: PathBuf,
    sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Prepared {
    pub profile_digest: String,
    pub request_path: PathBuf,
    pub receipt_path: PathBuf,
    pub request_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Application {
    pub receipt_sha256: String,
    pub backup_sha256: String,
    pub bundle_levels_sha256: String,
    pub replaced: u32,
    pub created: u32,
    pub deleted: u32,
    #[serde(default)]
    pub compensation: Option<CompensationEvidence>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompensationEvidence {
    pub applied_sha256: String,
    pub intended_sha256: String,
    pub plan_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalAdmission {
    pub receipt_sha256: String,
    pub observed_sha256: String,
    pub bundle_levels_sha256: String,
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn private_directory(path: &Path, owner: u32) -> Result<()> {
    ensure!(path.is_absolute(), "startup path must be absolute");
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.mode() & 0o077 == 0 && m.uid() == owner,
        "unsafe startup directory"
    );
    Ok(())
}
pub(crate) fn trusted_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure!(path.is_absolute(), "startup profile path");
    let (bytes, m) = durable::read(path, limit)?;
    ensure!(
        m.mode & 0o022 == 0 && (m.uid == 0 || m.uid == unsafe { libc::geteuid() }),
        "unsafe startup profile"
    );
    let parent = fs::symlink_metadata(
        path.parent()
            .ok_or_else(|| anyhow::anyhow!("profile parent"))?,
    )?;
    ensure!(
        parent.is_dir() && parent.mode() & 0o022 == 0,
        "unsafe profile directory"
    );
    Ok(bytes)
}
fn safe_value(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}
impl Startup {
    pub fn new(config: PathBuf) -> Result<Self> {
        let s = Self { config };
        s.inputs()?;
        Ok(s)
    }
    fn inputs(&self) -> Result<(Config, String)> {
        let raw = trusted_file(&self.config, 256 << 10)?;
        ensure!(
            fs::symlink_metadata(&self.config)?.mode() & 0o077 == 0,
            "private startup grant required"
        );
        let c: Config = serde_json::from_slice(&raw)?;
        ensure!(
            c.schema == 1
                && (1..=120).contains(&c.timeout_seconds)
                && !c.profile_files.is_empty()
                && c.profile_files.len() <= 512,
            "startup grant bounds"
        );
        let mut hashes = vec![durable::hash(&raw)];
        let mut paths = BTreeSet::new();
        let mut total = 0;
        for f in &c.profile_files {
            ensure!(
                digest(&f.sha256) && paths.insert(f.path.clone()),
                "startup profile inventory"
            );
            let bytes = trusted_file(&f.path, 256 << 20)?;
            total += bytes.len();
            ensure!(total <= 2048usize << 20, "startup profile quota");
            ensure!(durable::hash(&bytes) == f.sha256, "startup profile changed");
            hashes.push(f.sha256.clone());
        }
        Ok((c, durable::hash(hashes.join("\n").as_bytes())))
    }
    pub(crate) fn authority_sha256(&self) -> Result<String> {
        Ok(self.inputs()?.1)
    }
    pub fn unit(&self) -> Result<String> {
        Ok(self.inputs()?.0.unit)
    }
    pub fn request_path(&self) -> Result<PathBuf> {
        Ok(self.inputs()?.0.request_path)
    }
    pub fn prepare(
        &self,
        unit: &str,
        id: &str,
        target: &Path,
        sha: &str,
        parameters: &[(String, String)],
        owner: FileMetadata,
    ) -> Result<Prepared> {
        let (c, profile_digest) = self.inputs()?;
        ensure!(
            c.unit == unit
                && id
                    .strip_prefix("rec-")
                    .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
                && digest(sha),
            "startup identity"
        );
        private_directory(
            c.request_path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("request parent"))?,
            owner.uid,
        )?;
        private_directory(&c.receipt_directory, owner.uid)?;
        ensure!(
            fs::symlink_metadata(&c.request_path)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "retained startup request; do not replay"
        );
        let receipt_path = c.receipt_directory.join(format!("{id}.properties"));
        for suffix in [
            "",
            ".bundle-levels",
            ".cm-backup.aes",
            ".cm-applied.aes",
            ".cm-intended.aes",
            ".cm-plan.properties",
            ".cm-observed.aes",
        ] {
            ensure!(
                fs::symlink_metadata(format!("{}{suffix}", receipt_path.display()))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "retained application evidence"
            );
        }
        let bytes = Self::request(id, target, sha, &receipt_path, parameters)?;
        Ok(Prepared {
            profile_digest,
            request_path: c.request_path,
            receipt_path,
            request_sha256: durable::hash(&bytes),
        })
    }
    fn request(
        id: &str,
        target: &Path,
        sha: &str,
        receipt: &Path,
        parameters: &[(String, String)],
    ) -> Result<Vec<u8>> {
        let mut values = BTreeMap::from([
            ("schema".to_owned(), "1".to_owned()),
            ("restore.id".into(), id.into()),
            (
                "snapshot.path".into(),
                target
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("snapshot encoding"))?
                    .into(),
            ),
            ("snapshot.sha256".into(), sha.into()),
            (
                "receipt.path".into(),
                receipt
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("receipt encoding"))?
                    .into(),
            ),
        ]);
        for (k, v) in parameters {
            ensure!(
                matches!(
                    k.as_str(),
                    "snapshot.mode"
                        | "password.policy"
                        | "crypto.key.file"
                        | "crypto.default"
                        | "crypto.systemd.credentials"
                        | "crypto.key.sha256"
                        | "crypto.ring.sha256"
                        | "compensation.source.receipt"
                        | "compensation.source.receipt.sha256"
                        | "compensation.source.plan.sha256"
                        | "verification.mode"
                        | "verification.source.receipt"
                        | "verification.source.receipt.sha256"
                        | "verification.source.applied.sha256"
                ) && values.insert(k.clone(), v.clone()).is_none(),
                "startup parameter"
            );
        }
        ensure!(
            values.contains_key("snapshot.mode")
                && values.contains_key("password.policy")
                && [
                    "crypto.key.file",
                    "crypto.default",
                    "crypto.systemd.credentials"
                ]
                .iter()
                .filter(|k| values.contains_key(**k))
                .count()
                    == 1,
            "startup parameters missing"
        );
        let managed = values.contains_key("crypto.systemd.credentials");
        ensure!(
            managed == values.contains_key("crypto.key.sha256")
                && managed == values.contains_key("crypto.ring.sha256"),
            "incomplete Core credential binding"
        );
        if managed {
            ensure!(
                values["crypto.systemd.credentials"] == "true"
                    && digest(&values["crypto.key.sha256"])
                    && (values["crypto.ring.sha256"] == "none"
                        || digest(&values["crypto.ring.sha256"])),
                "invalid Core credential binding"
            );
        }
        let source_keys = [
            "compensation.source.receipt",
            "compensation.source.receipt.sha256",
            "compensation.source.plan.sha256",
        ];
        let count = source_keys
            .iter()
            .filter(|key| values.contains_key(**key))
            .count();
        ensure!(
            count == 0
                || (count == source_keys.len()
                    && values.get("snapshot.mode").map(String::as_str) == Some("aes-gcm")
                    && Path::new(&values[source_keys[0]]).is_absolute()
                    && Path::new(&values[source_keys[0]]) != receipt
                    && digest(&values[source_keys[1]])
                    && digest(&values[source_keys[2]])),
            "incomplete or ambiguous compensation source"
        );
        let normal_keys = [
            "verification.mode",
            "verification.source.receipt",
            "verification.source.receipt.sha256",
            "verification.source.applied.sha256",
        ];
        let normal_count = normal_keys
            .iter()
            .filter(|k| values.contains_key(**k))
            .count();
        ensure!(
            normal_count == 0
                || (normal_count == normal_keys.len()
                    && count == 0
                    && values[normal_keys[0]] == "normal-read-only"
                    && Path::new(&values[normal_keys[1]]).is_absolute()
                    && Path::new(&values[normal_keys[1]]) != receipt
                    && digest(&values[normal_keys[2]])
                    && digest(&values[normal_keys[3]])),
            "incomplete or mixed normal startup authority"
        );
        let mut bytes = String::new();
        for (k, v) in values {
            ensure!(safe_value(&v), "ambiguous manifest value");
            bytes.push_str(&format!("{k}={v}\n"));
        }
        ensure!(bytes.len() <= 16 << 10, "startup request size");
        Ok(bytes.into_bytes())
    }
    pub fn verify_prepared(
        &self,
        p: &Prepared,
        unit: &str,
        id: &str,
        target: &Path,
        sha: &str,
        parameters: &[(String, String)],
    ) -> Result<()> {
        let (c, digest) = self.inputs()?;
        ensure!(
            c.unit == unit
                && c.request_path == p.request_path
                && c.receipt_directory.join(format!("{id}.properties")) == p.receipt_path
                && digest == p.profile_digest
                && durable::hash(&Self::request(
                    id,
                    target,
                    sha,
                    &p.receipt_path,
                    parameters
                )?) == p.request_sha256,
            "startup grant drifted"
        );
        Ok(())
    }
    pub fn publish(
        &self,
        p: &Prepared,
        id: &str,
        target: &Path,
        sha: &str,
        parameters: &[(String, String)],
        owner: FileMetadata,
    ) -> Result<()> {
        let bytes = Self::request(id, target, sha, &p.receipt_path, parameters)?;
        ensure!(
            durable::hash(&bytes) == p.request_sha256,
            "startup request drift"
        );
        private_directory(p.request_path.parent().unwrap(), owner.uid)?;
        private_directory(p.receipt_path.parent().unwrap(), owner.uid)?;
        durable::publish_new(
            &p.request_path,
            &bytes,
            FileMetadata {
                mode: 0o600,
                ..owner
            },
        )
    }
    /// Admission only: Java has authenticated CM while SCR is held. Business health remains unproven.
    pub fn normal_admission(
        &self,
        p: &Prepared,
        id: &str,
        sha: &str,
        source_receipt_sha: &str,
        source_applied_sha: &str,
        owner: FileMetadata,
    ) -> Result<NormalAdmission> {
        let (config, profile) = self.inputs()?;
        ensure!(
            profile == p.profile_digest,
            "normal startup profile changed"
        );
        let deadline = Instant::now() + Duration::from_secs(config.timeout_seconds);
        loop {
            match fs::symlink_metadata(&p.receipt_path) {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100))
                }
                _ => anyhow::bail!("normal admission timeout; query without resending"),
            }
        }
        let read = |path: &Path, limit| -> Result<Vec<u8>> {
            let (b, m) = durable::read(path, limit)?;
            ensure!(
                m.uid == owner.uid && m.mode & 0o077 == 0,
                "normal admission owner"
            );
            Ok(b)
        };
        ensure!(
            durable::hash(&read(&p.request_path, 16 << 10)?) == p.request_sha256,
            "normal request changed"
        );
        let receipt = read(&p.receipt_path, 1 << 20)?;
        let mut fields = BTreeMap::new();
        for line in std::str::from_utf8(&receipt)?.lines() {
            let (key, value) = line.split_once('=').context("normal receipt line")?;
            ensure!(
                safe_value(value) && fields.insert(key, value).is_none(),
                "normal receipt ambiguity"
            );
        }
        let mut expected = BTreeMap::from([
            ("schema", "1"),
            ("status", "NORMAL_BOOT_ADMITTED"),
            ("restore.id", id),
            ("snapshot.sha256", sha),
            ("source.receipt.sha256", source_receipt_sha),
            ("source.applied.sha256", source_applied_sha),
            ("fullRecoveryVerified", "false"),
            ("normalBootVerified", "false"),
            ("businessHealth", "UNVERIFIED"),
        ]);
        let observed = fields
            .get("observed.sha256")
            .context("normal observation missing")?;
        ensure!(digest(observed), "normal observation encoding");
        expected.insert("observed.sha256", observed);
        ensure!(fields == expected, "normal receipt identity/status");
        let observed_path = PathBuf::from(format!("{}.cm-observed.aes", p.receipt_path.display()));
        ensure!(
            durable::hash(&read(&observed_path, 32 << 20)?) == *observed,
            "normal observation changed"
        );
        let ledger = read(
            &PathBuf::from(format!("{}.bundle-levels", p.receipt_path.display())),
            64 << 10,
        )?;
        ensure!(!ledger.is_empty(), "normal bundle ledger missing");
        Ok(NormalAdmission {
            receipt_sha256: durable::hash(&receipt),
            observed_sha256: (*observed).into(),
            bundle_levels_sha256: durable::hash(&ledger),
        })
    }
    pub fn application(
        &self,
        p: &Prepared,
        id: &str,
        sha: &str,
        owner: FileMetadata,
    ) -> Result<Application> {
        self.application_inner(p, id, sha, owner).map_err(|_| {
            anyhow::anyhow!(
                "CONFLICT: controlled Kura CM receipt not proven; preserve recovery state"
            )
        })
    }
    fn application_inner(
        &self,
        p: &Prepared,
        id: &str,
        sha: &str,
        owner: FileMetadata,
    ) -> Result<Application> {
        let (c, d) = self.inputs()?;
        ensure!(d == p.profile_digest, "profile changed during startup");
        let deadline = Instant::now() + Duration::from_secs(c.timeout_seconds);
        loop {
            match fs::symlink_metadata(&p.receipt_path) {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100))
                }
                _ => anyhow::bail!("application receipt timeout"),
            }
        }
        let read = |path: &Path, limit| -> Result<Vec<u8>> {
            let (b, m) = durable::read(path, limit)?;
            ensure!(
                m.mode & 0o077 == 0 && m.uid == owner.uid,
                "application owner"
            );
            Ok(b)
        };
        let request = read(&p.request_path, 16 << 10)?;
        ensure!(
            durable::hash(&request) == p.request_sha256,
            "request changed"
        );
        let receipt = read(&p.receipt_path, 1 << 20)?;
        let text = std::str::from_utf8(&receipt)?;
        let mut fields = BTreeMap::new();
        for line in text.lines() {
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("receipt line"))?;
            ensure!(
                safe_value(v) && fields.insert(k, v).is_none(),
                "receipt ambiguity"
            );
        }
        ensure!(
            fields.get("schema") == Some(&"1")
                && fields.get("status") == Some(&"CM_APPLIED")
                && fields.get("restore.id") == Some(&id)
                && fields.get("snapshot.sha256") == Some(&sha)
                && fields.get("fullRecoveryVerified") == Some(&"false")
                && fields.get("businessHealth") == Some(&"UNVERIFIED"),
            "receipt identity/status"
        );
        let backup_sha = *fields
            .get("backup.sha256")
            .ok_or_else(|| anyhow::anyhow!("missing backup hash"))?;
        ensure!(digest(backup_sha), "backup hash encoding");
        let mut allowed = BTreeSet::from([
            "schema".to_owned(),
            "status".into(),
            "restore.id".into(),
            "snapshot.sha256".into(),
            "fullRecoveryVerified".into(),
            "businessHealth".into(),
            "backup.sha256".into(),
        ]);
        let compensation = if let Some(applied_sha) = fields.get("applied.sha256") {
            ensure!(digest(applied_sha), "applied hash encoding");
            allowed.insert("applied.sha256".into());
            let applied = read(
                &PathBuf::from(format!("{}.cm-applied.aes", p.receipt_path.display())),
                64 << 20,
            )?;
            ensure!(
                !applied.is_empty() && durable::hash(&applied) == *applied_sha,
                "applied CM drift"
            );
            let plan = read(
                &PathBuf::from(format!("{}.cm-plan.properties", p.receipt_path.display())),
                4096,
            )?;
            let mut values = BTreeMap::new();
            let text = std::str::from_utf8(&plan)?;
            for line in text.lines() {
                let (key, value) = line
                    .split_once('=')
                    .ok_or_else(|| anyhow::anyhow!("CM plan line"))?;
                ensure!(
                    safe_value(value) && values.insert(key, value).is_none(),
                    "ambiguous CM plan"
                );
            }
            ensure!(
                values.len() == 5
                    && values.get("schema") == Some(&"1")
                    && values.get("restore.id") == Some(&id)
                    && values.get("snapshot.sha256") == Some(&sha)
                    && values.get("backup.sha256") == Some(&backup_sha),
                "CM plan identity"
            );
            let intended_sha = *values
                .get("intended.sha256")
                .ok_or_else(|| anyhow::anyhow!("missing CM intent"))?;
            ensure!(digest(intended_sha), "CM intent hash encoding");
            let intended = read(
                &PathBuf::from(format!("{}.cm-intended.aes", p.receipt_path.display())),
                64 << 20,
            )?;
            ensure!(
                !intended.is_empty() && durable::hash(&intended) == intended_sha,
                "CM intent drift"
            );
            Some(CompensationEvidence {
                applied_sha256: (*applied_sha).into(),
                intended_sha256: intended_sha.into(),
                plan_sha256: durable::hash(&plan),
            })
        } else {
            None
        }; // Historical receipts remain readable; they do not gain compensation evidence.
        let mut counts = Vec::new();
        for kind in ["replaced", "created", "deleted"] {
            let key = format!("{kind}.count");
            let count = fields
                .get(key.as_str())
                .ok_or_else(|| anyhow::anyhow!("action count"))?
                .parse::<u32>()?;
            ensure!(count <= 4096, "action quota");
            allowed.insert(key);
            let mut names = BTreeSet::new();
            for n in 0..count {
                use base64::Engine;
                let key = format!("{kind}.{n}");
                let value = *fields
                    .get(key.as_str())
                    .ok_or_else(|| anyhow::anyhow!("action index"))?;
                let bytes = base64::engine::general_purpose::STANDARD.decode(value)?;
                let pid = String::from_utf8(bytes)?;
                ensure!(
                    safe_value(&pid) && pid.len() <= 1024 && names.insert(pid),
                    "action identity"
                );
                allowed.insert(key);
            }
            counts.push(count);
        }
        ensure!(
            fields.keys().all(|k| allowed.contains(*k)),
            "unknown receipt field"
        );
        let backup = read(
            &PathBuf::from(format!("{}.cm-backup.aes", p.receipt_path.display())),
            64 << 20,
        )?;
        ensure!(
            !backup.is_empty() && durable::hash(&backup) == backup_sha,
            "CM backup drift"
        );
        let levels = read(
            &PathBuf::from(format!("{}.bundle-levels", p.receipt_path.display())),
            64 << 10,
        )?;
        ensure!(levels.starts_with(b"schema=1\n"), "bundle ledger");
        Ok(Application {
            receipt_sha256: durable::hash(&receipt),
            backup_sha256: backup_sha.into(),
            bundle_levels_sha256: durable::hash(&levels),
            replaced: counts[0],
            created: counts[1],
            deleted: counts[2],
            compensation,
        })
    }
}
