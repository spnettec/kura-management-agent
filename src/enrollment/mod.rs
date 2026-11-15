//! One-time local enrollment from a fixed, explicitly granted Kura directory.
//! No private material crosses a browser/center/UDS message.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::watch;
mod crypto;
mod renewal;
pub(crate) use renewal::RenewInput;
#[cfg(test)]
mod tests;

pub(crate) fn tls_identity(
    certificate: Vec<u8>,
    key: Vec<u8>,
) -> Result<tonic::transport::Identity> {
    let key = Secret(key);
    let normalized = Secret(crypto::tls_private_key(&key.0)?);
    Ok(tonic::transport::Identity::from_pem(
        certificate,
        &normalized.0,
    ))
}

pub(super) struct Secret(pub Vec<u8>);
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Manifest {
    schema: String,
    request_id: String,
    gateway_id: String,
    endpoint: String,
    public_key_sha256: String,
    client_certificate_sha256: String,
    issuer_ca_sha256: String,
    console_ca_sha256: String,
    not_after: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Receipt {
    schema: String,
    candidate_id: String,
    request_id: String,
    stage_sha256: String,
    material: Manifest,
    binding_generation: u64,
    source_uid: u32,
    actor: String,
    operator: String,
    accepted_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    renewal: Option<renewal::Lineage>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BindInput {
    pub expected_revision: String,
    request_id: String,
    expected_stage_sha256: String,
    operator: String,
}

#[derive(Clone)]
pub struct Enrollment {
    store: Arc<Store>,
    config: watch::Sender<Option<crate::transport::Config>>,
    db: sqlx::SqlitePool,
    legacy: bool,
    startup_fault: bool,
    boot_id: String,
}
struct Store {
    root: PathBuf,
    grant: Option<PathBuf>,
    kura_uid: u32,
}
struct Candidate {
    path: PathBuf,
    receipt: Receipt,
}

fn uuid(value: &str) -> Result<()> {
    ensure!(
        uuid::Uuid::parse_str(value).is_ok_and(|u| u.to_string() == value),
        "INVALID_ARGUMENT"
    );
    Ok(())
}
fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "INVALID_ARGUMENT"
    );
    Ok(())
}
fn gateway(value: &str) -> Result<()> {
    let b = value.as_bytes();
    ensure!(
        (1..=128).contains(&b.len())
            && b[0].is_ascii_alphanumeric()
            && b.iter()
                .all(|v| v.is_ascii_alphanumeric() || b"_.-".contains(v)),
        "INVALID_ARGUMENT"
    );
    Ok(())
}
fn endpoint(value: &str) -> Result<()> {
    ensure!(value.len() <= 512 && value.is_ascii(), "INVALID_ARGUMENT");
    let address = value
        .strip_prefix("https://")
        .ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT"))?
        .strip_suffix('/')
        .unwrap_or_else(|| value.strip_prefix("https://").unwrap());
    ensure!(
        !address.is_empty()
            && !address
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b"/@?#".contains(&b)),
        "INVALID_ARGUMENT"
    );
    let port = if address.starts_with('[') {
        let end = address
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT"))?;
        address[1..end]
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT"))?;
        let tail = &address[end + 1..];
        if tail.is_empty() {
            None
        } else {
            Some(
                tail.strip_prefix(':')
                    .ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT"))?,
            )
        }
    } else {
        let (host, port) = address
            .rsplit_once(':')
            .map_or((address, None), |(a, b)| (a, Some(b)));
        ensure!(
            !host.is_empty()
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
                && host.bytes().any(|b| b.is_ascii_alphanumeric()),
            "INVALID_ARGUMENT"
        );
        port
    };
    if let Some(p) = port {
        ensure!(
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|p| p > 0),
            "INVALID_ARGUMENT"
        );
    }
    crate::transport::validate_endpoint(value)?;
    Ok(())
}
fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn no_links(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path.components().all(|c| matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )),
        "INVALID_ARGUMENT"
    );
    for p in path.ancestors() {
        ensure!(
            !fs::symlink_metadata(p)?.is_symlink(),
            "FORBIDDEN: enrollment path link"
        );
    }
    Ok(())
}
fn directory(path: &Path, uid: u32) -> Result<()> {
    no_links(path)?;
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == uid && m.mode() & 0o777 == 0o700,
        "FORBIDDEN: enrollment directory"
    );
    Ok(())
}
fn read(path: &Path, uid: u32, limit: u64) -> Result<Vec<u8>> {
    let (bytes, m) = crate::durable::read(path, limit)?;
    ensure!(
        m.uid == uid && m.mode == 0o600,
        "FORBIDDEN: enrollment file"
    );
    Ok(bytes)
}
fn own(path: &Path, limit: u64) -> Result<Vec<u8>> {
    read(path, unsafe { libc::geteuid() }, limit)
}
fn exact(path: &Path, names: &[&str]) -> Result<()> {
    let found = fs::read_dir(path)?
        .map(|v| v.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<std::collections::BTreeSet<_>>>()?;
    ensure!(
        found == names.iter().map(|s| s.to_string()).collect(),
        "CONFLICT: unexpected enrollment material"
    );
    Ok(())
}
fn manifest(path: &Path, uid: u32, id: &str, hash: &str) -> Result<Manifest> {
    directory(path, uid)?;
    exact(
        path,
        &[
            "client-chain.pem",
            "issuer-ca.pem",
            "console-ca.pem",
            "manifest.json",
            "complete",
        ],
    )?;
    let bytes = read(&path.join("manifest.json"), uid, 16384)?;
    ensure!(
        crate::durable::hash(&bytes) == hash
            && read(&path.join("complete"), uid, 65)? == format!("{hash}\n").as_bytes(),
        "CONFLICT: certificate stage changed"
    );
    let m: Manifest = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: certificate manifest"))?;
    ensure!(
        m.schema == "yofc.kura.remote.certificates.v1" && m.request_id == id,
        "INVALID_ARGUMENT"
    );
    gateway(&m.gateway_id)?;
    endpoint(&m.endpoint)?;
    for value in [
        &m.public_key_sha256,
        &m.client_certificate_sha256,
        &m.issuer_ca_sha256,
        &m.console_ca_sha256,
    ] {
        digest(value)?;
    }
    for (file, hash) in [
        ("issuer-ca.pem", &m.issuer_ca_sha256),
        ("console-ca.pem", &m.console_ca_sha256),
    ] {
        ensure!(
            crate::durable::hash(&read(&path.join(file), uid, 65536)?) == *hash,
            "CONFLICT: CA material changed"
        );
    }
    Ok(m)
}

impl Store {
    fn base(&self) -> PathBuf {
        self.root.join("enrollment")
    }
    fn pending(&self) -> PathBuf {
        self.root.join("identity-enrollment-pending.json")
    }
    fn pointer(&self) -> PathBuf {
        self.base().join("identity.json")
    }
    fn orphaned_receipt(&self) -> Result<bool> {
        let candidates = self.base().join("candidates");
        if !present(&candidates)? {
            return Ok(false);
        }
        directory(&self.base(), unsafe { libc::geteuid() })?;
        directory(&candidates, unsafe { libc::geteuid() })?;
        for entry in fs::read_dir(candidates)? {
            let path = entry?.path();
            directory(&path, unsafe { libc::geteuid() })?;
            if present(&path.join("receipt.json"))?
                || present(&path.join("identity-complete"))?
                || present(&path.join("completed-intent.json"))?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn record(&self) -> Result<Option<Receipt>> {
        if !present(&self.pointer())? {
            return Ok(None);
        }
        directory(&self.base(), unsafe { libc::geteuid() })?;
        let r: Receipt = serde_json::from_slice(&own(&self.pointer(), 16384)?)
            .map_err(|_| anyhow::anyhow!("CONFLICT: managed identity record"))?;
        renewal::validate_receipt(&r)?;
        uuid(&r.candidate_id)?;
        uuid(&r.request_id)?;
        digest(&r.stage_sha256)?;
        gateway(&r.material.gateway_id)?;
        endpoint(&r.material.endpoint)?;
        Ok(Some(r))
    }
    fn load(&self, boot: &str) -> Result<Option<crate::transport::Config>> {
        let Some(record) = self.record()? else {
            return Ok(None);
        };
        renewal::verify_lineage(self, &record)?;
        directory(&self.base().join("candidates"), unsafe { libc::geteuid() })?;
        let path = self.base().join("candidates").join(&record.candidate_id);
        directory(&path, unsafe { libc::geteuid() })?;
        let bytes = own(&path.join("receipt.json"), 16384)?;
        ensure!(
            bytes == own(&self.pointer(), 16384)?
                && own(&path.join("identity-complete"), 65)?
                    == format!("{}\n", crate::durable::hash(&bytes)).as_bytes(),
            "CONFLICT: managed identity receipt"
        );
        let m = manifest(
            &path.join("certificates"),
            unsafe { libc::geteuid() },
            &record.request_id,
            &record.stage_sha256,
        )?;
        ensure!(
            serde_json::to_vec(&m)? == serde_json::to_vec(&record.material)?,
            "CONFLICT: managed identity material"
        );
        for file in [
            "private.pk8",
            "public.der",
            "request.pem",
            "gateway.id",
            "complete",
            "agent-key.pem",
        ] {
            own(&path.join(file), 65536)?;
        }
        ensure!(
            own(&path.join("gateway.id"), 128)? == m.gateway_id.as_bytes()
                && own(&path.join("complete"), 64)? == b"kura.remote.identity.v1\n",
            "CONFLICT"
        );
        ensure!(
            own(&path.join("completed-intent.json"), 16384)? == bytes,
            "CONFLICT: incomplete identity commit"
        );
        crypto::validate_committed(&path, &m, record.accepted_at_unix_ms)?;
        Ok(Some(config(&path, &record, boot)))
    }
    fn prepare(&self, input: &BindInput, actor: String) -> Result<Candidate> {
        ensure!(
            !present(&self.pointer())? && !present(&self.pending())?,
            "CONFLICT: existing or unsettled identity"
        );
        self.prepare_candidate(input, actor, 1, None)
    }
    fn prepare_candidate(
        &self,
        input: &BindInput,
        actor: String,
        generation: u64,
        lineage: Option<renewal::Lineage>,
    ) -> Result<Candidate> {
        uuid(&input.request_id)?;
        digest(&input.expected_stage_sha256)?;
        ensure!(
            !input.operator.is_empty()
                && input.operator.len() <= 128
                && !input.operator.chars().any(char::is_control),
            "INVALID_ARGUMENT"
        );
        let source = self
            .grant
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("FORBIDDEN: enrollment not granted"))?;
        directory(source, self.kura_uid)?;
        let slot = source.join(&input.request_id);
        directory(&slot, self.kura_uid)?;
        exact(
            &slot,
            &[
                "private.pk8",
                "public.der",
                "request.pem",
                "gateway.id",
                "complete",
                "certificates",
            ],
        )?;
        let m = manifest(
            &slot.join("certificates"),
            self.kura_uid,
            &input.request_id,
            &input.expected_stage_sha256,
        )?;
        ensure!(
            read(&slot.join("gateway.id"), self.kura_uid, 128)? == m.gateway_id.as_bytes()
                && read(&slot.join("complete"), self.kura_uid, 64)? == b"kura.remote.identity.v1\n",
            "CONFLICT"
        );
        let base = self.base();
        crate::durable::directory(&base)?;
        let candidates = base.join("candidates");
        crate::durable::directory(&candidates)?;
        ensure!(
            fs::read_dir(&candidates)?.count() < 16,
            "RESOURCE_EXHAUSTED: preserve and archive enrollment candidates"
        );
        let id = uuid::Uuid::new_v4().to_string();
        let path = candidates.join(&id);
        fs::create_dir(&path)?;
        crate::durable::directory(&path)?;
        crate::durable::sync_directory(&candidates)?;
        for file in [
            "private.pk8",
            "public.der",
            "request.pem",
            "gateway.id",
            "complete",
        ] {
            let bytes = Secret(read(&slot.join(file), self.kura_uid, 16384)?);
            crate::durable::publish_new(
                &path.join(file),
                &bytes.0,
                crate::durable::FileMetadata::private(),
            )?;
        }
        let certs = path.join("certificates");
        crate::durable::directory(&certs)?;
        for file in [
            "client-chain.pem",
            "issuer-ca.pem",
            "console-ca.pem",
            "manifest.json",
            "complete",
        ] {
            crate::durable::publish_new(
                &certs.join(file),
                &read(&slot.join("certificates").join(file), self.kura_uid, 65536)?,
                crate::durable::FileMetadata::private(),
            )?;
        }
        let copied = manifest(
            &certs,
            unsafe { libc::geteuid() },
            &input.request_id,
            &input.expected_stage_sha256,
        )?;
        ensure!(
            serde_json::to_vec(&copied)? == serde_json::to_vec(&m)?,
            "CONFLICT: handoff changed during copy"
        );
        crypto::validate(&path, &m, true)?;
        let receipt = Receipt {
            schema: if lineage.is_some() {
                "yofc.agent.enrollment.v2"
            } else {
                "yofc.agent.enrollment.v1"
            }
            .into(),
            candidate_id: id,
            request_id: input.request_id.clone(),
            stage_sha256: input.expected_stage_sha256.clone(),
            material: m,
            binding_generation: generation,
            source_uid: self.kura_uid,
            actor,
            operator: input.operator.clone(),
            accepted_at_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis()
                .try_into()?,
            renewal: lineage,
        };
        Ok(Candidate { path, receipt })
    }
    fn commit(&self, candidate: &Candidate, decision: &[u8]) -> Result<()> {
        self.commit_with_hook(candidate, decision, |_| Ok(()))
    }
    fn commit_with_hook(
        &self,
        candidate: &Candidate,
        decision: &[u8],
        mut checkpoint: impl FnMut(&str) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            !present(&self.pointer())? && !present(&self.pending())?,
            "CONFLICT: existing or unsettled identity"
        );
        let bytes = serde_json::to_vec(&candidate.receipt)?;
        crate::durable::publish_new(
            &candidate.path.join("receipt.json"),
            &bytes,
            crate::durable::FileMetadata::private(),
        )?;
        checkpoint("receipt")?;
        crate::durable::publish_new(
            &candidate.path.join("identity-complete"),
            format!("{}\n", crate::durable::hash(&bytes)).as_bytes(),
            crate::durable::FileMetadata::private(),
        )?;
        checkpoint("receipt-complete")?;
        crate::durable::publish_new(
            &self.pending(),
            &bytes,
            crate::durable::FileMetadata::private(),
        )?;
        checkpoint("pending")?;
        crate::durable::publish_new(
            &self.pointer(),
            &bytes,
            crate::durable::FileMetadata::private(),
        )?;
        checkpoint("pointer")?;
        crate::durable::write(
            &self.root.join("remote-management.json"),
            decision,
            crate::durable::FileMetadata::private(),
        )?;
        checkpoint("decision")?;
        fs::rename(self.pending(), candidate.path.join("completed-intent.json"))?;
        checkpoint("renamed")?;
        crate::durable::sync_directory(&candidate.path)?;
        crate::durable::sync_directory(&self.root)?;
        checkpoint("durable")?;
        Ok(())
    }
}
fn config(path: &Path, r: &Receipt, boot: &str) -> crate::transport::Config {
    crate::transport::Config {
        endpoint: r.material.endpoint.clone(),
        gateway: r.material.gateway_id.clone(),
        binding_generation: r.binding_generation,
        ca: path
            .join("certificates/console-ca.pem")
            .to_string_lossy()
            .into_owned(),
        cert: path
            .join("certificates/client-chain.pem")
            .to_string_lossy()
            .into_owned(),
        key: path.join("agent-key.pem").to_string_lossy().into_owned(),
        boot_id: boot.into(),
    }
}

impl Enrollment {
    pub fn open(
        root: PathBuf,
        legacy: Option<crate::transport::Config>,
        grant: Option<PathBuf>,
        kura_uid: u32,
        db: sqlx::SqlitePool,
        boot_id: String,
    ) -> Result<Self> {
        crate::durable::directory(&root)?;
        if let Some(path) = &grant {
            ensure!(
                path.is_absolute()
                    && kura_uid != u32::MAX
                    && path.components().all(|c| matches!(
                        c,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )),
                "INVALID_ARGUMENT: explicit enrollment directory/UID required"
            );
        }
        let store = Arc::new(Store {
            root,
            grant,
            kura_uid,
        });
        let is_legacy = legacy.is_some();
        let (initial, fault) =
            if present(&store.pending())? || store.renewal_blocked().unwrap_or(true) {
                (None, true)
            } else if present(&store.pointer())? {
                if is_legacy {
                    (None, true)
                } else {
                    match store.load(&boot_id) {
                        Ok(v) => (v, false),
                        Err(_) => (None, true),
                    }
                }
            } else if store.orphaned_receipt().unwrap_or(true) {
                (None, true)
            } else {
                (legacy, false)
            };
        let (sender, _) = watch::channel(initial);
        Ok(Self {
            store,
            config: sender,
            db,
            legacy: is_legacy,
            startup_fault: fault,
            boot_id,
        })
    }
    pub fn current(&self) -> Option<crate::transport::Config> {
        self.config.borrow().clone()
    }
    pub fn subscribe(&self) -> watch::Receiver<Option<crate::transport::Config>> {
        self.config.subscribe()
    }
    pub fn fault(&self) -> bool {
        self.startup_fault || self.store.renewal_blocked().unwrap_or(true)
    }
    pub fn granted(&self) -> bool {
        self.store.grant.is_some()
    }
    pub fn status(&self, can_enroll: bool) -> Result<Value> {
        let pending =
            present(&self.store.pending())? || self.store.renewal_blocked().unwrap_or(true);
        let receipt = self.store.record();
        let fault = self.startup_fault || pending || receipt.is_err();
        let mut result = json!({"bound":self.current().is_some(),"legacyIdentity":self.legacy,"recoveryRequired":fault,"canEnroll":can_enroll && self.granted() && self.current().is_none() && !fault});
        if let Some(record) = receipt.ok().flatten() {
            result["acceptedRequestId"] = json!(record.request_id);
            result["acceptedStageSha256"] = json!(record.stage_sha256);
            result["clientCertificateSha256"] = json!(record.material.client_certificate_sha256);
        }
        Ok(result)
    }
    pub async fn bind(
        &self,
        input: BindInput,
        remote: crate::remote::Remote,
        actor: String,
    ) -> Result<Value> {
        ensure!(
            self.granted() && !self.legacy && !self.startup_fault && self.current().is_none(),
            "CONFLICT: identity cannot be replaced by enrollment"
        );
        let root = self.store.root.clone();
        let guard = tokio::task::spawn_blocking(move || {
            crate::system_change::Guard::acquire(&root, crate::system_change::Subsystem::Identity)
        })
        .await??;
        let pending:Option<i64>=sqlx::query_scalar("SELECT 1 FROM executions WHERE state IN ('RUNNING','UNKNOWN') AND operation NOT IN (1,2,3,4,8,9,11,15,20,23) LIMIT 1").fetch_optional(&self.db).await?;
        ensure!(
            pending.is_none(),
            "CONFLICT: uncertain execution requires recovery"
        );
        let owned = self.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            let candidate = owned.store.prepare(&input, actor.clone())?;
            let target = (
                candidate.receipt.material.endpoint.clone(),
                candidate.receipt.material.gateway_id.clone(),
                1,
            );
            remote.bind_target(&input.expected_revision, target, actor, |decision| {
                owned.store.commit(&candidate, decision)
            })?;
            owned.config.send_replace(Some(config(
                &candidate.path,
                &candidate.receipt,
                &owned.boot_id,
            )));
            owned.status(false)
        })
        .await?
    }
}
