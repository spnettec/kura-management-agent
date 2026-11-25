//! Original-ID records under a package-provisioned, Root-owned directory.
use super::{hex, is_uuid};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwarding: Option<super::forwarding::Forwarding>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Receipt {
    schema: u8,
    intent_sha256: String,
    #[serde(default)]
    outcome_sha256: Option<String>,
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
    pub fn identity_observation(&self) -> Result<super::root_identity::RootIdentity> {
        let root = File::open("/")?;
        let named = fs::symlink_metadata(&self.dir)?;
        let held = self.lock.metadata()?;
        ensure!((named.dev(), named.ino()) == (held.dev(), held.ino()), "UNPAIRED: journal changed");
        let machine = fs::read_to_string("/etc/machine-id")?;
        let root_meta = root.metadata()?;
        let scope = hex(&Sha256::digest(serde_json::to_vec(&(
            "kura-firewall-publication-v1", machine.trim_end(), root_meta.dev(), root_meta.ino(), held.dev(), held.ino(),
        ))?));
        ensure!(scope == self.scope, "UNPAIRED: Root changed during observation");
        super::root_identity::RootIdentity::observe(&root, &self.lock)
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
    pub fn inspect_outcome(&self, op: &str, scope: &str, request: &str) -> Result<(Value, bool)> {
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
            return Ok((response("NOT_FOUND"), false));
        };
        let Ok(intent) = serde_json::from_slice::<Intent>(&bytes) else {
            return Ok((response("UNKNOWN"), false));
        };
        ensure!(
            matches!(
                (intent.schema, intent.forwarding.is_some()),
                (1, false) | (2, true)
            ) && intent.operation_id == op
                && intent.root_scope == scope
                && intent.request_sha256 == request,
            "UNPAIRED: original firewall request"
        );
        let promote = receipt.is_none();
        let Some(r) = receipt.or(pending) else {
            return Ok((response("UNKNOWN"), false));
        };
        let Ok(record) = serde_json::from_slice::<Receipt>(&r) else {
            return Ok((response("UNKNOWN"), false));
        };
        let outcome_hash = outcome_digest(&record.outcome)?;
        ensure!(
            record.schema == 1
                && (record.outcome_sha256.is_some()
                    || (intent.schema == 1 && record.outcome.get("bootModel").is_none()))
                && record.intent_sha256 == hex(&Sha256::digest(&bytes))
                && record
                    .outcome_sha256
                    .as_ref()
                    .is_none_or(|value| value == &outcome_hash)
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
        if let Some(value) = record.outcome.get("approvedBootFamily") {
            ensure!(
                intent
                    .forwarding
                    .as_ref()
                    .is_some_and(|f| value == &f.family)
                    && record.outcome_sha256.is_some()
                    && record.outcome.get("bootModel").is_some(),
                "UNPAIRED: boot forwarding source"
            );
        }
        Ok((record.outcome, promote))
    }
    pub fn promote(&self, op: &str) -> Result<()> {
        let staged = self.path(op, "staged")?;
        File::open(&staged)?.sync_all()?;
        fs::rename(staged, self.path(op, "result")?)?;
        self.lock.sync_all()?;
        Ok(())
    }
    pub fn outcome(&self, op: &str, scope: &str, request: &str) -> Result<Value> {
        let (value, staged) = self.inspect_outcome(op, scope, request)?;
        if staged {
            // Completed results remain readable. Renaming a staged result is a write.
            super::admission::require_sender_receipt(op)?;
            self.promote(op)?;
        }
        Ok(value)
    }
    pub fn terminal_generation(&self, op: &str, outcome: &Value) -> Result<u32> {
        let bytes = self
            .read(&self.path(op, "intent")?)?
            .context("Missing boot intent")?;
        let intent: Intent = serde_json::from_slice(&bytes)?;

        match outcome["state"].as_str() {
            Some("APPLIED") if intent.commands != 0 => Ok(intent.generation.wrapping_add(1).max(1)),
            Some("UNCHANGED" | "APPLIED") if intent.commands == 0 => Ok(intent.generation),
            _ => anyhow::bail!("UNPAIRED: no committed boot generation"),
        }
    }
    pub fn history(&self, staged: Option<(&str, &Value)>) -> Result<History> {
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
                "staged" if staged.is_some_and(|(op, _)| op == id) => {
                    ensure!(
                        results.insert(id.to_owned()),
                        "UNPAIRED: duplicate firewall receipt"
                    );
                }
                "staged" => anyhow::bail!("UNKNOWN: unpublished original firewall result"),
                "result" => {
                    ensure!(
                        results.insert(id.to_owned()),
                        "UNPAIRED: duplicate firewall receipt"
                    );
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
        let mut history = History::default();
        for id in &intents {
            if let Some((_, outcome)) = staged.filter(|(op, _)| *op == id) {
                // Validated under this journal lock. Include the staged outcome in
                // the history proof without publishing it before kernel readback.
                history.record(outcome)?;
                continue;
            }
            let bytes = self
                .read(&self.path(id, "intent")?)?
                .context("UNKNOWN: missing original intent")?;
            let intent: Intent =
                serde_json::from_slice(&bytes).context("UNKNOWN: incomplete original intent")?;
            let (outcome, unpublished) =
                self.inspect_outcome(id, &self.scope, &intent.request_sha256)?;
            ensure!(
                !unpublished,
                "UNKNOWN: unpublished original firewall result"
            );
            ensure!(
                matches!(
                    outcome["state"].as_str(),
                    Some("APPLIED" | "REJECTED" | "UNCHANGED")
                ),
                "UNKNOWN: unresolved original firewall result"
            );
            history.record(&outcome)?;
        }
        Ok(history)
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
            outcome_sha256: Some(outcome_digest(outcome)?),
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

// A previous worker may still publish on this installation after a downgrade. Bind the
// latest family digests to the complete set of terminal publications, without relying on
// mtimes, netlink generations (which wrap), or the lexical order of UUIDs.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BootModel {
    history_sha256: String,
    models: BTreeMap<String, String>,
}

#[derive(Default)]
pub struct History {
    // operation ID -> (approved request, approved wire, terminal outcome)
    records: BTreeMap<String, [String; 3]>,
    tips: Vec<(BootModel, BTreeMap<String, String>)>,
    // Explicit Main approvals, keyed by original operation and bound to its candidate.
    approvals: BTreeMap<String, (String, String)>,
}

impl History {
    fn record(&mut self, outcome: &Value) -> Result<()> {
        let field = |key: &str| -> Result<String> {
            Ok(outcome[key]
                .as_str()
                .context("UNPAIRED: incomplete publication history")?
                .into())
        };
        let id = field("operationId")?;
        let row = [
            field("requestSha256")?,
            field("wireSha256")?,
            field("state")?,
        ];
        ensure!(
            self.records.insert(id, row).is_none(),
            "UNPAIRED: repeated publication history"
        );
        if let Some(value) = outcome.get("bootModel") {
            let tip: BootModel = serde_json::from_value(value.clone())?;
            ensure!(
                valid_hash(&tip.history_sha256)
                    && tip.models.iter().all(|(family, digest)| matches!(
                        family.as_str(),
                        "ipv4" | "ipv6"
                    ) && valid_hash(digest)),
                "UNPAIRED: invalid boot model receipt"
            );
            let routing: BTreeMap<String, String> = match outcome.get("bootForwarding") {
                Some(value) => serde_json::from_value(value.clone())?,
                None => BTreeMap::new(),
            };
            if let Some(family) = outcome.get("approvedBootFamily") {
                let family = family
                    .as_str()
                    .context("UNPAIRED: invalid boot forwarding family")?;
                let digest = tip
                    .models
                    .get(family)
                    .context("UNPAIRED: missing approved rules")?;
                ensure!(
                    outcome["forwardingEnabled"] == true
                        && matches!(outcome["state"].as_str(), Some("APPLIED" | "UNCHANGED"))
                        && routing.get(family).map(String::as_str)
                            == outcome["operationId"].as_str(),
                    "UNPAIRED: incomplete boot forwarding approval"
                );
                self.approvals
                    .insert(field("operationId")?, (family.to_owned(), digest.clone()));
            }
            self.tips.push((tip, routing));
        }
        Ok(())
    }

    fn digest(&self) -> Result<String> {
        Ok(hex(&Sha256::digest(serde_json::to_vec(&self.records)?)))
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn require_capacity(&self) -> Result<()> {
        ensure!(
            self.records.len() < MAX_OPERATIONS,
            "RESOURCE_EXHAUSTED: firewall history"
        );
        Ok(())
    }

    fn confirmed_tip(&self) -> Result<Option<&(BootModel, BTreeMap<String, String>)>> {
        let digest = self.digest()?;
        let mut matching = self
            .tips
            .iter()
            .filter(|(tip, _)| tip.history_sha256 == digest);
        let tip = matching.next();
        ensure!(
            matching.next().is_none(),
            "UNPAIRED: ambiguous boot model receipt"
        );
        Ok(tip)
    }
    pub fn confirmed_models(&self) -> Result<BTreeMap<String, String>> {
        Ok(self
            .confirmed_tip()?
            .map(|(tip, _)| tip.models.clone())
            .unwrap_or_default())
    }

    pub fn require_uninitialized(&self, family: &str) -> Result<()> {
        // Old receipts without model bindings cannot establish which family they touched.
        ensure!(
            self.records.is_empty()
                || (self.tips.len() == self.records.len()
                    && self.confirmed_tip()?.is_some()
                    && self
                        .tips
                        .iter()
                        .all(|(tip, _)| !tip.models.contains_key(family))),
            "UNPAIRED: firewall family has existing or unbound publication history"
        );
        Ok(())
    }
    pub fn confirmed_forwarding(&self) -> Result<BTreeMap<String, String>> {
        let Some((tip, grants)) = self.confirmed_tip()? else {
            return Ok(BTreeMap::new());
        };
        for (family, id) in grants {
            let (owner, digest) = self
                .approvals
                .get(id)
                .context("UNPAIRED: missing original boot forwarding approval")?;
            ensure!(
                family == owner && tip.models.get(family) == Some(digest),
                "UNPAIRED: boot forwarding approval differs from confirmed rules"
            );
        }
        Ok(grants.clone())
    }

    pub fn after(
        mut self,
        mut models: BTreeMap<String, String>,
        outcome: &Value,
        changes: &[super::FamilyChange],
    ) -> Result<Value> {
        self.record(outcome)?;
        if outcome["state"] == "APPLIED" || outcome["state"] == "UNCHANGED" {
            for change in changes {
                models.insert(
                    change.family.clone(),
                    hex(&Sha256::digest(change.candidate.as_bytes())),
                );
            }
        }
        Ok(serde_json::to_value(BootModel {
            history_sha256: self.digest()?,
            models,
        })?)
    }
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(super::lower_hex)
}

fn outcome_digest(value: &Value) -> Result<String> {
    let mut canonical = value.clone();
    canonical.sort_all_objects();
    Ok(hex(&Sha256::digest(serde_json::to_vec(&canonical)?)))
}

/// Package maintenance already holds the directory lock and checks the record's
/// Root and file metadata. Validate the historical kernel reply without opening
/// the journal or contacting Netfilter.
pub fn check_legacy_receipt(raw: &[u8], response: &[u8]) -> Result<()> {
    let intent: Intent = serde_json::from_slice(raw)?;
    let receipt: Receipt = serde_json::from_slice(response)?;
    ensure!(
        intent.schema == 1
            && intent.forwarding.is_none()
            && receipt.schema == 1
            && receipt.outcome_sha256.is_none()
            && receipt.outcome.get("bootModel").is_none()
            && receipt.intent_sha256 == hex(&Sha256::digest(raw))
            && receipt.outcome["rootScope"] == intent.root_scope
            && receipt.outcome["operationId"] == intent.operation_id
            && receipt.outcome["requestSha256"] == intent.request_sha256
            && receipt.outcome["wireSha256"] == intent.wire_sha256,
        "UNPAIRED: historical firewall receipt"
    );
    validate_ack(&intent, &receipt.outcome)
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
    let forwarding_applied = if let Some(f) = &intent.forwarding {
        ensure!(
            matches!(f.family.as_str(), "ipv4" | "ipv6") && f.namespace.iter().all(|n| *n > 0),
            "UNPAIRED: forwarding receipt scope"
        );
        if result["state"] != "REJECTED" {
            ensure!(
                result["forwardingEnabled"] == true,
                "UNPAIRED: forwarding readback"
            );
            !f.before
        } else {
            ensure!(
                result.get("forwardingEnabled").is_none(),
                "UNPAIRED: rejected forwarding write"
            );
            false
        }
    } else {
        ensure!(
            result.get("forwardingEnabled").is_none(),
            "UNPAIRED: unexpected forwarding receipt"
        );
        false
    };
    if wire.is_empty() {
        let state = if forwarding_applied {
            "APPLIED"
        } else {
            "UNCHANGED"
        };
        ensure!(
            intent.commands == 0 && result["state"] == state && result.get("ack").is_none(),
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

#[cfg(test)]
mod boot_model_tests {
    use super::*;
    use crate::FamilyChange;

    fn receipt(id: &str, state: &str) -> Value {
        json!({"operationId": id, "requestSha256": "a".repeat(64),
               "wireSha256": "b".repeat(64), "state": state})
    }

    fn approval(history: &[Value], id: &str, state: &str, family: &str, candidate: &str) -> Value {
        let mut journal = History::default();
        for previous in history {
            journal.record(previous).unwrap();
        }
        let models = journal.confirmed_models().unwrap();
        let change = FamilyChange {
            family: family.to_owned(),
            previous: String::new(),
            candidate: candidate.to_owned(),
        };
        let mut result = receipt(id, state);
        result["bootModel"] = journal.after(models, &result, &[change]).unwrap();
        result
    }

    fn read(records: &[&Value]) -> BTreeMap<String, String> {
        let mut history = History::default();
        for row in records {
            history.record(row).unwrap();
        }
        history.confirmed_models().unwrap()
    }

    #[test]
    fn initialization_requires_bound_history_for_the_selected_family() {
        let mut history = History::default();
        assert!(history.require_uninitialized("ipv4").is_ok());
        assert!(history.require_uninitialized("ipv6").is_ok());

        let original = approval(&[], "first", "APPLIED", "ipv4", "four");
        history.record(&original).unwrap();
        assert!(history.require_uninitialized("ipv4").is_err());
        assert!(history.require_uninitialized("ipv6").is_ok());

        let rejected = approval(&[original], "later", "REJECTED", "ipv6", "six");
        history.record(&rejected).unwrap();
        assert!(history.require_uninitialized("ipv6").is_ok());

        history.record(&receipt("legacy", "UNCHANGED")).unwrap();
        assert!(history.require_uninitialized("ipv6").is_err());
    }

    #[test]
    fn original_receipts_future_tip_and_downgrade_are_distinct() {
        let old = receipt("z", "APPLIED");
        let first = approval(std::slice::from_ref(&old), "c", "UNCHANGED", "ipv4", "four");
        let both = approval(&[old.clone(), first.clone()], "a", "APPLIED", "ipv6", "six");
        let expected = BTreeMap::from([
            ("ipv4".into(), hex(&Sha256::digest(b"four"))),
            ("ipv6".into(), hex(&Sha256::digest(b"six"))),
        ]);
        assert_eq!(read(&[&both, &old, &first]), expected);
        assert!(read(&[&first]).is_empty());
        let rejected = approval(
            &[old.clone(), first.clone(), both.clone()],
            "k",
            "REJECTED",
            "ipv6",
            "unapplied",
        );
        assert_eq!(read(&[&rejected, &both, &old, &first]), expected);
        let downgrade = receipt("b", "APPLIED");
        assert!(read(&[&downgrade, &both, &old, &first]).is_empty());
        let restored = approval(
            &[downgrade.clone(), both.clone(), old.clone(), first.clone()],
            "f",
            "APPLIED",
            "ipv6",
            "new six",
        );
        let got = read(&[&restored, &downgrade, &both, &old, &first]);
        assert_eq!(
            got,
            BTreeMap::from([("ipv6".into(), hex(&Sha256::digest(b"new six")))])
        );
    }

    #[test]
    fn forwarding_grant_requires_the_original_family_digest_and_complete_history() {
        let mut original = approval(&[], "first", "APPLIED", "ipv4", "original rules");
        original["bootForwarding"] = json!({"ipv4": "first"});
        original["approvedBootFamily"] = json!("ipv4");
        original["forwardingEnabled"] = json!(true);
        let mut prior = History::default();
        prior.record(&original).unwrap();
        assert_eq!(prior.confirmed_forwarding().unwrap()["ipv4"], "first");
        let mut changed = approval(
            std::slice::from_ref(&original),
            "new",
            "APPLIED",
            "ipv4",
            "other rules",
        );
        changed["bootForwarding"] = original["bootForwarding"].clone();
        let mut history = History::default();
        history.record(&changed).unwrap();
        history.record(&original).unwrap();
        assert!(history.confirmed_forwarding().is_err());

        let mut other = approval(
            std::slice::from_ref(&original),
            "next",
            "APPLIED",
            "ipv6",
            "original rules",
        );
        other["bootForwarding"] = json!({"ipv6": "first"});
        let mut history = History::default();
        history.record(&original).unwrap();
        history.record(&other).unwrap();
        assert!(history.confirmed_forwarding().is_err());
        prior.record(&receipt("legacy", "UNCHANGED")).unwrap();
        assert!(prior.confirmed_forwarding().unwrap().is_empty());
    }

    #[test]
    fn changed_terminal_history_and_malformed_family_digest_are_refused() {
        let old = receipt("a", "APPLIED");
        let new = approval(
            std::slice::from_ref(&old),
            "b",
            "UNCHANGED",
            "ipv4",
            "rules",
        );
        assert!(read(&[&receipt("a", "REJECTED"), &new]).is_empty());
        let mut corrupt = new;
        corrupt["bootModel"]["models"]["ipv4"] = json!("invalid");
        assert!(History::default().record(&corrupt).is_err());
    }
}
