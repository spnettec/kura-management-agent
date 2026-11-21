//! Original-ID records under a package-provisioned, Root-owned directory.
use super::{hex, is_uuid};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const STATE: &str = "/var/lib/kura-legacy-firewall/publication";
const MAX_RECORD: u64 = 2 * 1024 * 1024;
const MAX_OPERATIONS: usize = 4096;

pub struct Journal {
    dir: PathBuf,
    lock: File,
    pub scope: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Intent {
    pub schema: u8,
    pub operation_id: String,
    pub root_scope: String,
    pub request_sha256: String,
    pub wire_sha256: String,
    pub wire: String,
    pub commands: usize,
    pub generation: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Receipt {
    schema: u8,
    intent_sha256: String,
    outcome: Value,
}
fn no_record(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound
}

impl Journal {
    pub fn open() -> Result<Self> {
        let dir = PathBuf::from(STATE);
        for path in dir.ancestors() {
            let meta = fs::symlink_metadata(path)?;
            ensure!(
                meta.is_dir() && meta.uid() == 0 && meta.gid() == 0 && meta.mode() & 0o022 == 0,
                "UNPAIRED: firewall journal hierarchy"
            );
        }
        let lock = File::open(&dir)?;
        let meta = lock.metadata()?;
        ensure!(
            meta.mode() & 0o7777 == 0o700,
            "UNPAIRED: firewall journal mode"
        );
        lock.try_lock().context("BUSY: firewall publication")?;
        let named = fs::symlink_metadata(&dir)?;
        ensure!(
            meta.dev() == named.dev() && meta.ino() == named.ino(),
            "UNPAIRED: firewall journal changed"
        );
        let machine = fs::read_to_string("/etc/machine-id")?;
        let machine = machine.trim_end();
        ensure!(
            machine.len() == 32 && machine.bytes().all(super::lower_hex),
            "UNPAIRED: firewall machine identity"
        );
        let root = fs::metadata("/")?;
        let scope = hex(&Sha256::digest(serde_json::to_vec(&(
            "kura-firewall-publication-v1",
            machine,
            root.dev(),
            root.ino(),
            meta.dev(),
            meta.ino(),
        ))?));
        Ok(Self { dir, lock, scope })
    }
    fn path(&self, op: &str, suffix: &str) -> Result<PathBuf> {
        ensure!(is_uuid(op), "INVALID_ARGUMENT: original operation ID");
        Ok(self.dir.join(format!("{op}.{suffix}")))
    }
    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        let named = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if no_record(&e) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        ensure!(
            named.is_file()
                && named.uid() == 0
                && named.gid() == 0
                && named.nlink() == 1
                && named.mode() & 0o7777 == 0o600
                && named.len() <= MAX_RECORD,
            "UNPAIRED: firewall record metadata"
        );
        let file = File::open(path)?;
        let m = file.metadata()?;
        ensure!(
            m.ino() == named.ino() && m.dev() == named.dev(),
            "UNPAIRED: firewall record changed"
        );
        let mut raw = Vec::new();
        file.take(MAX_RECORD + 1).read_to_end(&mut raw)?;
        ensure!(
            raw.len() as u64 == m.len(),
            "UNPAIRED: firewall record size"
        );
        Ok(Some(raw))
    }
    fn create(&self, path: &Path, raw: &[u8]) -> Result<()> {
        ensure!(
            !raw.is_empty() && raw.len() as u64 <= MAX_RECORD,
            "RESOURCE_EXHAUSTED: firewall record"
        );
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(raw)?;
        f.sync_all()?;
        self.lock.sync_all()?;
        Ok(())
    }
    pub fn outcome(&self, op: &str, scope: &str, request: &str) -> Result<Value> {
        ensure!(self.scope == scope, "UNPAIRED: original firewall Root");
        let response = |state: &str| json!({"state":state,"operationId":op,"rootScope":scope,"requestSha256":request});
        let raw = self.read(&self.path(op, "intent")?)?;
        let path = self.path(op, "result")?;
        let staged = self.path(op, "staged")?;
        let receipt = self.read(&path)?;
        let pending = self.read(&staged)?;
        ensure!(
            receipt.is_none() || pending.is_none(),
            "UNPAIRED: duplicate original firewall result"
        );
        let Some(bytes) = raw else {
            ensure!(
                receipt.is_none() && pending.is_none(),
                "UNPAIRED: missing original firewall intent"
            );
            return Ok(response("NOT_FOUND"));
        };
        let Ok(intent) = serde_json::from_slice::<Intent>(&bytes) else {
            return Ok(response("UNKNOWN"));
        };
        ensure!(
            intent.schema == 1
                && intent.operation_id == op
                && intent.root_scope == scope
                && intent.request_sha256 == request,
            "UNPAIRED: original firewall request"
        );
        let promote = receipt.is_none();
        let Some(r) = receipt.or(pending) else {
            return Ok(response("UNKNOWN"));
        };
        let Ok(record) = serde_json::from_slice::<Receipt>(&r) else {
            return Ok(response("UNKNOWN"));
        };
        ensure!(
            record.schema == 1
                && record.intent_sha256 == hex(&Sha256::digest(&bytes))
                && record.outcome["requestSha256"] == request
                && record.outcome["operationId"] == op
                && record.outcome["rootScope"] == scope
                && record.outcome["wireSha256"] == intent.wire_sha256
                && matches!(
                    record.outcome["state"].as_str(),
                    Some("APPLIED" | "REJECTED" | "UNCHANGED")
                ),
            "UNPAIRED: original firewall result"
        );
        validate_ack(&intent, &record.outcome)?;
        if promote {
            // Finish publishing only a complete receipt for this exact original request.
            File::open(&staged)?.sync_all()?;
            fs::rename(staged, path)?;
            self.lock.sync_all()?;
        }
        Ok(record.outcome)
    }
    pub fn require_idle(&self) -> Result<()> {
        let mut intents = BTreeSet::new();
        let mut results = BTreeSet::new();
        for entry in fs::read_dir(&self.dir)? {
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("UNPAIRED: invalid firewall record name"))?;
            let (id, typ) = name
                .split_once('.')
                .context("UNPAIRED: unexpected firewall journal entry")?;
            ensure!(is_uuid(id), "UNPAIRED: invalid firewall history ID");
            match typ {
                "intent" => {
                    intents.insert(id.to_owned());
                }
                "staged" => anyhow::bail!("UNKNOWN: unpublished original firewall result"),
                "result" => {
                    results.insert(id.to_owned());
                }
                _ => anyhow::bail!("UNPAIRED: unexpected firewall journal entry"),
            }
            ensure!(
                intents.len() <= MAX_OPERATIONS && results.len() <= MAX_OPERATIONS,
                "RESOURCE_EXHAUSTED: firewall history"
            );
        }
        ensure!(
            intents == results,
            "UNKNOWN: unresolved original firewall operation"
        );
        for id in &intents {
            let bytes = self
                .read(&self.path(id, "intent")?)?
                .context("UNKNOWN: missing original intent")?;
            let intent: Intent =
                serde_json::from_slice(&bytes).context("UNKNOWN: incomplete original intent")?;
            let outcome = self.outcome(id, &self.scope, &intent.request_sha256)?;
            ensure!(
                matches!(
                    outcome["state"].as_str(),
                    Some("APPLIED" | "REJECTED" | "UNCHANGED")
                ),
                "UNKNOWN: unresolved original firewall result"
            );
        }
        ensure!(
            intents.len() < MAX_OPERATIONS,
            "RESOURCE_EXHAUSTED: firewall history"
        );
        Ok(())
    }
    pub fn begin(&self, intent: &Intent) -> Result<String> {
        // The exclusive directory lock spans require_idle, preparation and publication.
        let bytes = serde_json::to_vec(intent)?;
        self.create(&self.path(&intent.operation_id, "intent")?, &bytes)?;
        Ok(hex(&Sha256::digest(&bytes)))
    }
    pub fn finish(&self, op: &str, intent_sha256: String, outcome: &Value) -> Result<()> {
        let data = serde_json::to_vec(&Receipt {
            schema: 1,
            intent_sha256,
            outcome: outcome.clone(),
        })?;
        let staged = self.path(op, "staged")?;
        self.create(&staged, &data)?;
        let result = self.path(op, "result")?;
        ensure!(
            !result.try_exists()?,
            "CONFLICT: existing original firewall result"
        );
        fs::rename(staged, result)?;
        self.lock.sync_all()?;
        Ok(())
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    ensure!(
        value.len() % 2 == 0 && value.bytes().all(super::lower_hex),
        "UNPAIRED: firewall record bytes"
    );
    (0..value.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&value[i..i + 2], 16)?))
        .collect()
}

fn validate_ack(intent: &Intent, result: &Value) -> Result<()> {
    use kura_firewall_policy::{
        publication::FIRST_SEQUENCE,
        receipt::{BatchReceipts, Reply},
    };
    let wire = decode_hex(&intent.wire)?;
    ensure!(
        hex(&Sha256::digest(&wire)) == intent.wire_sha256
            && intent.generation > 0
            && intent.commands <= 8192,
        "UNPAIRED: original firewall wire"
    );
    if wire.is_empty() {
        ensure!(
            intent.commands == 0 && result["state"] == "UNCHANGED" && result.get("ack").is_none(),
            "UNPAIRED: empty firewall transaction"
        );
    } else {
        ensure!(
            wire.get(24..28) == Some(&intent.generation.to_be_bytes()[..]),
            "UNPAIRED: original firewall generation"
        );
        let ack = decode_hex(
            result["ack"]
                .as_str()
                .context("UNPAIRED: missing firewall ACK")?,
        )?;
        let mut batch = BatchReceipts::new(
            &wire,
            FIRST_SEQUENCE,
            FIRST_SEQUENCE + 1 + intent.commands as u32,
        )?;
        match batch.observe(&ack)? {
            Reply::Committed { message } => ensure!(
                result["state"] == "APPLIED" && message == ack,
                "UNPAIRED: successful firewall ACK"
            ),
            Reply::Rejected {
                errno,
                sequence,
                message,
            } => ensure!(
                result["state"] == "REJECTED"
                    && result["errno"] == errno
                    && result["sequence"] == sequence
                    && message == ack,
                "UNPAIRED: rejected firewall ACK"
            ),
            Reply::Pending => anyhow::bail!("UNKNOWN: incomplete firewall receipt"),
        }
    }
    Ok(())
}
