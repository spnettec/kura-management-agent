//! Restore the last settled policy through its original backend on early boot.
//! An attempted write is never repeated without an exact terminal receipt.

use super::{Confirmed, Firewall, LIMIT, State, TABLE, VersionedCandidate, durable, model};
use crate::system_change::Guard;
#[cfg(test)]
use crate::system_change::Subsystem;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    fs,
    io::ErrorKind,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use uuid::Uuid;

const ROOT: &str = "/var/lib/kura-management-agent";
const PENDING: &str = "pending.json";
const RECORD_LIMIT: u64 = 8_192;
// Imported receipts retain the complete, bounded raw Netfilter observation.
const RECEIPT_LIMIT: u64 = 1_048_576;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Scope {
    root_device: u64,
    root_inode: u64,
    net_device: u64,
    net_inode: u64,
    owner_lease_sha256: String,
    confirmed_sha256: String,
    revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Intent {
    schema_version: u8,
    boot_id: Uuid,
    scope: Scope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    imported: Option<ImportedIntent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ImportedIntent {
    initialization_receipt_sha256: String,
    image_sha256: String,
    expected_generation: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Receipt {
    intent: Intent,
    intent_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_readback: Option<Value>,
}

fn directory(path: &Path, private: bool) -> Result<()> {
    let attr = fs::symlink_metadata(path)?;
    let uid = unsafe { libc::geteuid() };
    ensure!(
        attr.is_dir()
            && attr.uid() == uid
            && if private {
                attr.mode() & 0o7777 == 0o700
            } else {
                attr.mode() & 0o022 == 0
            },
        "FORBIDDEN: unsafe confirmed firewall restore directory: {}",
        path.display()
    );
    Ok(())
}

fn bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let (data, attr) = durable::read(path, limit)?;
    ensure!(
        attr.uid == unsafe { libc::geteuid() } && attr.mode == 0o600,
        "FORBIDDEN: unsafe confirmed firewall restore file: {}",
        path.display()
    );
    Ok(data)
}

fn optional<T: DeserializeOwned>(path: &Path) -> Result<Option<(T, Vec<u8>)>> {
    optional_bounded(path, RECORD_LIMIT)
}

fn optional_bounded<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<Option<(T, Vec<u8>)>> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let raw = bytes(path, limit)?;
            Ok(Some((serde_json::from_slice(&raw)?, raw)))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn read_receipt(path: &Path) -> Result<Option<(Receipt, Vec<u8>)>> {
    let receipt = optional_bounded::<Receipt>(path, RECEIPT_LIMIT)?;
    if let Some((record, raw)) = &receipt {
        ensure!(record.intent.imported.is_some() || raw.len() as u64 <= RECORD_LIMIT,
            "RESOURCE_EXHAUSTED: original private firewall boot receipt");
    }
    Ok(receipt)
}

fn ledger(root: &Path) -> PathBuf {
    root.join("firewall/boot-restore")
}

fn receipt_path(path: &Path, id: Uuid) -> PathBuf {
    path.join(format!("{id}.receipt.json"))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Intent {
    fn require_root(&self, root: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(root)?;
        ensure!(
            metadata.is_dir()
                && metadata.dev() == self.scope.root_device
                && metadata.ino() == self.scope.root_inode,
            "FORBIDDEN: original firewall restore belongs to another Root"
        );
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == if self.imported.is_some() { 2 } else { 1 },
            "CONFLICT: invalid firewall restore intent backend schema"
        );
        ensure!(
            self.imported.as_ref().is_none_or(|rec| rec.expected_generation > 0
                && valid_digest(&rec.initialization_receipt_sha256) && valid_digest(&rec.image_sha256))
                && !self.boot_id.is_nil()
                && self.scope.revision > 0
                && self.scope.root_inode > 0
                && self.scope.net_inode > 0
                && valid_digest(&self.scope.confirmed_sha256)
                && valid_digest(&self.scope.owner_lease_sha256),
            "CONFLICT: invalid confirmed firewall restore intent"
        );
        Ok(())
    }
}

impl Receipt {
    fn check(&self, intent: &Intent, raw: &[u8]) -> Result<()> {
        self.intent.validate()?;
        ensure!(
            &self.intent == intent && self.intent_sha256 == durable::hash(raw),
            "CONFLICT: confirmed firewall restore receipt differs from its original intent"
        );
        match (&intent.imported, &self.native_readback) {
            (None, None) => (),
            (Some(imported), Some(value)) => crate::nm::handover::initialization::validate_boot_readback(value, imported.expected_generation)?,
            _ => anyhow::bail!("CONFLICT: firewall restore receipt backend differs from its intent"),
        }
        Ok(())
    }
}

fn pending(path: &Path) -> Result<Option<(Intent, Vec<u8>)>> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            directory(path.parent().context("firewall state directory")?, true)?;
            directory(path, true)?;
        }
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let original: Option<(Intent, Vec<u8>)> = optional(&path.join(PENDING))?;
    if let Some((intent, _)) = &original {
        intent.validate()?;
        intent.require_root(
            path.parent()
                .and_then(Path::parent)
                .context("firewall state Root")?,
        )?;
    }
    Ok(original)
}

struct Original {
    intent: Intent,
    intent_sha256: String,
    receipt_sha256: Option<String>,
}

impl Original {
    fn report(&self, pending: bool) -> Value {
        json!({
            "schemaVersion": 1,
            "state": if self.receipt_sha256.is_some() { "RESTORED" } else { "OUTCOME_UNKNOWN" },
            "originalBootId": self.intent.boot_id,
            "revision": self.intent.scope.revision,
            "intentSha256": self.intent_sha256,
            "receiptSha256": self.receipt_sha256,
            "pendingIntentRetained": pending
        })
    }

    fn require_receipt(&self) -> Result<()> {
        ensure!(
            self.receipt_sha256.is_some(),
            "OUTCOME_UNKNOWN: confirmed firewall restore has no original receipt"
        );
        Ok(())
    }
}

fn original_pending(path: &Path) -> Result<Option<Original>> {
    let Some((intent, raw)) = pending(path)? else {
        return Ok(None);
    };
    let receipt_sha256 = match read_receipt(&receipt_path(path, intent.boot_id))? {
        Some((receipt, receipt_raw)) => {
            receipt.check(&intent, &raw)?;
            Some(durable::hash(&receipt_raw))
        }
        None => None,
    };
    Ok(Some(Original {
        intent,
        intent_sha256: durable::hash(&raw),
        receipt_sha256,
    }))
}

fn resolved_pending(path: &Path) -> Result<Option<Intent>> {
    let Some(original) = original_pending(path)? else {
        return Ok(None);
    };
    original.require_receipt()?;
    Ok(Some(original.intent))
}

fn observe_under_guard(root: &Path, current_boot: impl FnOnce() -> Result<Uuid>) -> Result<Value> {
    let path = ledger(root);
    if let Some(original) = original_pending(&path)? {
        return Ok(original.report(true));
    }
    let id = current_boot()?;
    let Some((receipt, raw)) = read_receipt(&receipt_path(&path, id))? else {
        return Ok(json!({"schemaVersion": 1, "state": "NO_RECORD"}));
    };
    receipt.intent.require_root(root)?;
    ensure!(
        receipt.intent.boot_id == id,
        "CONFLICT: firewall restore boot identity differs"
    );
    let intent_raw = serde_json::to_vec(&receipt.intent)?;
    receipt.check(&receipt.intent, &intent_raw)?;
    let original = Original {
        intent: receipt.intent,
        intent_sha256: receipt.intent_sha256,
        receipt_sha256: Some(durable::hash(&raw)),
    };
    Ok(original.report(false))
}

fn acknowledge_under_guard(root: &Path) -> Result<Value> {
    let path = ledger(root);
    let Some(original) = original_pending(&path)? else {
        return Ok(json!({"schemaVersion": 1, "state": "NO_PENDING"}));
    };
    original.require_receipt()?;
    durable::remove(&path.join(PENDING))?;
    Ok(original.report(false))
}

pub(crate) fn admit(root: &Path) -> Result<()> {
    resolved_pending(&ledger(root))?;
    Ok(())
}

fn approved_policy(firewall: &Firewall) -> Result<(Confirmed, String, VersionedCandidate)> {
    let raw = bytes(&firewall.0.state.join("confirmed.json"), LIMIT)?;
    let confirmed = firewall.confirmed()?;
    ensure!(
        confirmed.revision > 0
            && confirmed.kura_policy()?.is_some()
            && serde_json::to_value(&confirmed)? == serde_json::from_slice::<Value>(&raw)?,
        "FORBIDDEN: exact typed confirmed firewall policy required"
    );
    bytes(&firewall.0.state.join("transaction.json"), LIMIT)?;
    let journal = firewall
        .journal()?
        .context("FORBIDDEN: original firewall journal required")?;
    let matches = match journal.state {
        State::Committed => {
            journal.confirmed_decision
                && journal.old.revision.checked_add(1) == Some(confirmed.revision)
                && Some(journal.candidate_text) == confirmed.text
                && Some(serde_json::to_value(journal.candidate)?)
                    == confirmed
                        .candidate
                        .as_ref()
                        .map(serde_json::to_value)
                        .transpose()?
        }
        State::RolledBack => {
            !journal.confirmed_decision
                && serde_json::to_value(journal.old)? == serde_json::to_value(&confirmed)?
        }
        _ => false,
    };
    ensure!(
        matches,
        "FORBIDDEN: no original settled decision for the confirmed policy"
    );
    let candidate = confirmed
        .candidate
        .clone()
        .context("typed confirmed candidate")?;
    Ok((confirmed, durable::hash(&raw), candidate))
}

fn exclusive_script(candidate: &VersionedCandidate) -> Result<String> {
    let text = candidate.render()?;
    let original = format!("destroy table inet {TABLE}\n");
    let exclusive = format!("create table inet {TABLE}\n");
    ensure!(
        text.lines()
            .filter(|line| *line == original.trim_end())
            .count()
            == 1,
        "CONFLICT: unsupported typed firewall compiler framing"
    );
    Ok(text.replacen(&original, &exclusive, 1))
}

fn own_table(firewall: &Firewall, expected: &str) -> Result<bool> {
    let observation: Value =
        serde_json::from_str(&firewall.run_nft(&["-j", "-p", "list", "ruleset"], None)?)?;
    let entries = observation["nftables"]
        .as_array()
        .context("INTERNAL: complete ruleset observation")?;
    let own: Vec<_> = entries
        .iter()
        .filter(|entry| {
            let object = entry.as_object().and_then(|row| row.values().next());
            object.is_some_and(|obj| {
                obj["family"] == "inet"
                    && (obj["table"] == TABLE
                        || entry.get("table").is_some() && obj["name"] == TABLE)
            })
        })
        .cloned()
        .collect();
    if own.is_empty() {
        return Ok(false);
    }
    ensure!(
        model::semantic_table(&own)? == model::expected_table(expected)?,
        "CONFLICT: existing firewall table differs from the confirmed policy"
    );
    Ok(true)
}

fn publish(path: &Path, value: &impl Serialize) -> Result<Vec<u8>> {
    let raw = serde_json::to_vec(value)?;
    durable::publish_new(path, &raw, durable::FileMetadata::private())?;
    Ok(raw)
}

fn restore_under_guard(
    firewall: &Firewall,
    intent: &Intent,
    candidate: &VersionedCandidate,
) -> Result<Value> {
    intent.validate()?;
    intent.require_root(&firewall.0.root)?;
    let path = ledger(&firewall.0.root);
    let pending_file = path.join(PENDING);
    let completion = receipt_path(&path, intent.boot_id);
    let prior = resolved_pending(&path)?;
    let text = candidate.render()?;
    if let Some((receipt, _)) = read_receipt(&completion)? {
        receipt.check(intent, &serde_json::to_vec(intent)?)?;
        ensure!(
            own_table(firewall, &text)?,
            "CONFLICT: completed firewall restore is absent; no re-dispatch"
        );
        if prior.is_some() {
            durable::remove(&pending_file)?;
        }
        return Ok(json!({"state":"ALREADY_RESTORED","revision":intent.scope.revision}));
    }
    if own_table(firewall, &text)? {
        return Ok(json!({"state":"ALREADY_PRESENT","revision":intent.scope.revision}));
    }
    ensure!(
        firewall.foreign_writers()?.is_empty(),
        "FORBIDDEN: another firewall writer is present"
    );
    firewall.forwarding_ready(candidate)?;
    let script = exclusive_script(candidate)?;
    firewall.run_nft(&["-c", "-f", "-"], Some(&script))?;
    durable::directory(&path)?;
    if prior.is_some() {
        durable::remove(&pending_file)?;
    }
    let raw = publish(&pending_file, intent)?;
    firewall
        .run_nft(&["-f", "-"], Some(&script))
        .context("OUTCOME_UNKNOWN: original confirmed firewall restore dispatch")?;
    ensure!(
        own_table(firewall, &text)
            .context("OUTCOME_UNKNOWN: confirmed firewall restore readback")?,
        "OUTCOME_UNKNOWN: original confirmed firewall restore not observed"
    );
    let receipt = Receipt {
        intent: intent.clone(),
        intent_sha256: durable::hash(&raw),
        native_readback: None,
    };
    publish(&completion, &receipt)
        .context("OUTCOME_UNKNOWN: confirmed firewall restore receipt publication")?;
    durable::remove(&pending_file)?;
    Ok(json!({"state":"RESTORED","revision":intent.scope.revision}))
}

fn current_boot_id() -> Result<Uuid> {
    let raw = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let id = Uuid::parse_str(raw.trim())?;
    ensure!(
        !id.is_nil(),
        "CONFLICT: missing original system boot identity"
    );
    Ok(id)
}

fn canonical_root() -> Result<&'static Path> {
    ensure!(
        cfg!(target_os = "linux") && unsafe { libc::geteuid() } == 0,
        "FORBIDDEN: confirmed firewall restore requires the Linux Root actor"
    );
    let root = Path::new(ROOT);
    for ancestor in root.ancestors().skip(1) {
        directory(ancestor, false)?;
    }
    directory(root, true)?;
    directory(&root.join("firewall"), true)?;
    Ok(root)
}

pub(crate) fn observe_original() -> Result<Value> {
    let root = canonical_root()?;
    let _guard = Guard::observe_original_firewall_boot(root)?;
    observe_under_guard(root, current_boot_id)
}

pub(crate) fn review_imported() -> Result<Value> {
    let root = canonical_root()?;
    let _guard = Guard::observe_original_firewall_boot(root)?;
    admit(root)?;
    crate::nm::handover::initialization::review_imported_boot(root)
}

pub(crate) fn acknowledge_original() -> Result<Value> {
    let root = canonical_root()?;
    let _guard = Guard::acknowledge_original_firewall_boot(root)?;
    acknowledge_under_guard(root)
}

pub(crate) fn restore() -> Result<Value> {
    let root = canonical_root()?;
    let state = root.join("firewall");
    let _guard = Guard::acquire_existing_firewall_boot(root)?;
    let firewall = Firewall::with_state(root.into(), state, None);
    if crate::nm::handover::initialization::owns_firewall_domain(root)? {
        return imported::restore(&firewall);
    }
    let owner = crate::nm::handover::confirmed_private_firewall_boot_owner(root)?;
    let (confirmed, digest, candidate) = approved_policy(&firewall)?;
    let root = fs::symlink_metadata(root)?;
    let network = fs::metadata("/proc/self/ns/net")?;
    let intent = Intent {
        schema_version: 1,
        boot_id: current_boot_id()?,
        scope: Scope {
            root_device: root.dev(),
            root_inode: root.ino(),
            net_device: network.dev(),
            net_inode: network.ino(),
            owner_lease_sha256: owner,
            confirmed_sha256: digest,
            revision: confirmed.revision,
        },
        imported: None,
    };
    restore_under_guard(&firewall, &intent, &candidate)
}

mod imported;

#[cfg(test)]
mod tests;
