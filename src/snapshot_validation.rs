//! Fixed local Java adapter. No untrusted command line, shell, output forwarding,
//! key generation or write permission. This proves snapshot format, not business health.
use crate::durable;
#[cfg(test)]
#[path = "snapshot_validation_tests.rs"]
mod tests;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct Validator {
    config: PathBuf,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Config {
    schema: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    java: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jar: Option<PathBuf>,
    mode: Mode,
    password_policy: PasswordPolicy,
    key: Key,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Mode {
    Plain,
    AesGcm,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum PasswordPolicy {
    Authenticated,
    Legacy,
    #[serde(rename = "logical-v1")]
    LogicalV1,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum Key {
    File { path: PathBuf },
    Default,
    Core,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Report {
    schema: u32,
    artifact_sha256: String,
    mode: String,
    configuration_count: u32,
    factory_count: u32,
    property_count: u32,
    password_value_count: u32,
    authenticated_password_count: u32,
    legacy_password_count: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    logical_password_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password_encoding: Option<String>,
    key_authenticated: bool,
    full_recovery_verified: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Proof {
    // Private journal only. Do not expose credential/tool fingerprints through status.
    configuration_digest: String,
    pub report: Report,
}
struct Inputs {
    config: Config,
    digest: String,
    core: Option<crate::core_validation::Ready>,
}
fn is_zero(value: &u32) -> bool {
    *value == 0
}
fn trusted(path: &Path, executable: bool) -> Result<()> {
    ensure!(path.is_absolute(), "validator path");
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_file()
            && info.nlink() == 1
            && info.mode() & 0o022 == 0
            && (info.uid() == 0 || info.uid() == unsafe { libc::geteuid() })
            && (!executable || info.mode() & 0o111 != 0),
        "validator file"
    );
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("validator parent"))?;
    let info = fs::metadata(parent)?;
    ensure!(
        info.is_dir()
            && info.mode() & 0o022 == 0
            && (info.uid() == 0 || info.uid() == unsafe { libc::geteuid() }),
        "validator directory"
    );
    Ok(())
}
impl Validator {
    /// Reuse the exact key/mode grant already proven during prepare. No new key lookup policy.
    pub fn startup_parameters(&self, expected: &Proof) -> Result<Vec<(String, String)>> {
        let inputs = self.inputs()?;
        ensure!(
            inputs.digest == expected.configuration_digest,
            "CONFLICT: validator grant changed"
        );
        let mut result = vec![
            (
                "snapshot.mode".into(),
                match inputs.config.mode {
                    Mode::Plain => "plain",
                    Mode::AesGcm => "aes-gcm",
                }
                .into(),
            ),
            (
                "password.policy".into(),
                match inputs.config.password_policy {
                    PasswordPolicy::Authenticated => "authenticated",
                    PasswordPolicy::Legacy => "legacy",
                    PasswordPolicy::LogicalV1 => "logical-v1",
                }
                .into(),
            ),
        ];
        if let Some(core) = inputs.core {
            result.extend([
                ("crypto.systemd.credentials".into(), "true".into()),
                ("crypto.key.sha256".into(), core.binding.active_key_sha256),
                (
                    "crypto.ring.sha256".into(),
                    core.binding.ring_sha256.unwrap_or_else(|| "none".into()),
                ),
            ]);
            return Ok(result);
        }
        result.push(match inputs.config.key {
            Key::Default => ("crypto.default".into(), "true".into()),
            Key::File { path } => (
                "crypto.key.file".into(),
                path.to_str()
                    .ok_or_else(|| anyhow::anyhow!("key path encoding"))?
                    .into(),
            ),
            Key::Core => anyhow::bail!("Core validation binding missing"),
        });
        Ok(result)
    }
    pub fn new(config: PathBuf) -> Result<Self> {
        let result = Self { config };
        let (config, _) = result
            .configuration()
            .map_err(|_| anyhow::anyhow!("FORBIDDEN: invalid snapshot validator configuration"))?;
        // Agent stays available while Core is stopped or its credentials are being recovered.
        // Resolve Core's binding lazily at validation/controlled-start admission.
        if !matches!(config.key, Key::Core) {
            result.inputs()?;
        }
        Ok(result)
    }
    fn configuration(&self) -> Result<(Config, Vec<u8>)> {
        trusted(&self.config, false)?;
        let (raw, metadata) = durable::read(&self.config, 16 * 1024)?;
        ensure!(
            metadata.mode & 0o077 == 0,
            "private validator configuration required"
        );
        let config: Config = serde_json::from_slice(&raw)?;
        ensure!(
            match config.key {
                Key::Core => config.schema == 2 && config.java.is_none() && config.jar.is_none(),
                _ => config.schema == 1 && config.java.is_some() && config.jar.is_some(),
            },
            "validator schema and credential owner"
        );
        Ok((config, raw))
    }
    fn inputs(&self) -> Result<Inputs> {
        let (config, raw) = self.configuration()?;
        if matches!(config.key, Key::Core) {
            let core = crate::core_validation::info()?;
            let digest = durable::hash(
                format!("{}\n{}", durable::hash(&raw), core.binding_sha256).as_bytes(),
            );
            return Ok(Inputs {
                config,
                digest,
                core: Some(core),
            });
        }
        let java = config
            .java
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("validator java"))?;
        let jar = config
            .jar
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("validator jar"))?;
        trusted(java, true)?;
        trusted(jar, false)?;
        let mut hashes = vec![durable::hash(&raw)];
        hashes.push(durable::hash(&durable::read(java, 64 << 20)?.0));
        hashes.push(durable::hash(&durable::read(jar, 32 << 20)?.0));
        let lib = jar.parent().unwrap().join("lib");
        let info = fs::symlink_metadata(&lib)?;
        ensure!(
            info.is_dir() && info.mode() & 0o022 == 0,
            "validator lib directory"
        );
        let mut files = fs::read_dir(lib)?
            .map(|e| e.map(|e| e.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        ensure!(
            !files.is_empty() && files.len() <= 128,
            "validator libraries"
        );
        files.sort();
        let mut total = 0;
        for file in files {
            ensure!(
                file.extension().is_some_and(|s| s == "jar"),
                "validator library type"
            );
            trusted(&file, false)?;
            let bytes = durable::read(&file, 32 << 20)?.0;
            total += bytes.len();
            ensure!(total <= 256 << 20, "validator library quota");
            hashes.push(file.file_name().unwrap().to_string_lossy().into_owned());
            hashes.push(durable::hash(&bytes));
        }
        if let Key::File { path } = &config.key {
            trusted(path, false)?;
            let (mut bytes, metadata) = durable::read(path, 32)?;
            let valid = metadata.mode & 0o077 == 0 && matches!(bytes.len(), 16 | 24 | 32);
            let digest = durable::hash(&bytes);
            bytes.fill(0);
            ensure!(valid, "validator key");
            hashes.push(digest);
        }
        Ok(Inputs {
            config,
            digest: durable::hash(hashes.join("\n").as_bytes()),
            core: None,
        })
    }
    pub fn validate(
        &self,
        path: &Path,
        expected_sha: &str,
        expected: Option<&Proof>,
    ) -> Result<Proof> {
        self.validate_inner(path, expected_sha, expected)
            .map_err(|_| {
                anyhow::anyhow!("CONFLICT: snapshot Java validation failed; staging retained")
            })
    }
    fn validate_inner(
        &self,
        path: &Path,
        expected_sha: &str,
        expected: Option<&Proof>,
    ) -> Result<Proof> {
        let inputs = self.inputs()?;
        if let Some(expected) = expected {
            ensure!(
                inputs.digest == expected.configuration_digest,
                "validator configuration changed before launch"
            );
        }
        let config = &inputs.config;
        let mode = match config.mode {
            Mode::Plain => "plain",
            Mode::AesGcm => "aes-gcm",
        };
        let policy = match config.password_policy {
            PasswordPolicy::Authenticated => "authenticated",
            PasswordPolicy::Legacy => "legacy",
            PasswordPolicy::LogicalV1 => "logical-v1",
        };
        let report = if let Some(core) = &inputs.core {
            crate::core_validation::validate(path, expected_sha, mode, policy, core)?
        } else {
            let jar = config
                .jar
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("validator jar"))?;
            let mut args = vec![
                "-Xmx256m",
                "-Xms16m",
                "-XX:ActiveProcessorCount=2",
                "-XX:+UseSerialGC",
                "-XX:+ExitOnOutOfMemoryError",
                "-jar",
                jar.to_str()
                    .ok_or_else(|| anyhow::anyhow!("validator jar encoding"))?,
                "validate",
                "--input",
                path.to_str()
                    .ok_or_else(|| anyhow::anyhow!("validator input encoding"))?,
                "--mode",
                mode,
                "--password-policy",
                policy,
            ];
            match &config.key {
                Key::Default => args.push("--default-key"),
                Key::File { path } => {
                    args.push("--key-file");
                    args.push(
                        path.to_str()
                            .ok_or_else(|| anyhow::anyhow!("validator key encoding"))?,
                    );
                }
                Key::Core => anyhow::bail!("Core validation binding missing"),
            }
            let output = crate::process::run_isolated(
                config
                    .java
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("validator java"))?,
                &args,
                Duration::from_secs(30),
            )?;
            ensure!(
                output.status.success() && output.stderr.is_empty() && output.stdout.len() <= 4096,
                "validator process"
            );
            serde_json::from_slice::<Report>(&output.stdout)?
        };
        ensure!(
            report.schema == 1
                && report.artifact_sha256 == expected_sha
                && report.mode == mode
                && !report.full_recovery_verified
                && (1..=4096).contains(&report.configuration_count)
                && report.factory_count <= report.configuration_count
                && report.property_count <= 65536
                && report.password_value_count <= 65536
                && report
                    .authenticated_password_count
                    .checked_add(report.legacy_password_count)
                    .and_then(|count| count.checked_add(report.logical_password_count))
                    == Some(report.password_value_count)
                && (report.logical_password_count == 0
                    || report.password_encoding.as_deref() == Some("BASE64_LOGICAL_V1"))
                && report
                    .password_encoding
                    .as_deref()
                    .is_none_or(|value| value == "BASE64_LOGICAL_V1")
                && (report.password_encoding.is_none()
                    || report.authenticated_password_count == 0
                        && report.legacy_password_count == 0)
                && (policy == "legacy" || report.legacy_password_count == 0)
                && (policy != "authenticated"
                    || report.logical_password_count == 0
                    || mode == "aes-gcm")
                && (policy != "legacy" || report.password_encoding.is_none())
                && (policy != "logical-v1"
                    || report.password_encoding.as_deref() == Some("BASE64_LOGICAL_V1")
                        && report.authenticated_password_count == 0
                        && report.legacy_password_count == 0)
                && report.key_authenticated
                    == (mode == "aes-gcm" || report.authenticated_password_count > 0),
            "validator report"
        );
        ensure!(
            self.inputs()?.digest == inputs.digest,
            "validator changed during process"
        );
        ensure!(
            durable::hash(&durable::read(path, 32 << 20)?.0) == expected_sha,
            "validator input changed"
        );
        Ok(Proof {
            configuration_digest: inputs.digest,
            report,
        })
    }
}
