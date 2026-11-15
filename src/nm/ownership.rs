//! Proof that the automatic NAT policy came from a committed NM operation.
//! The table name/comment alone never admits it as an owned firewall subsystem.
use super::coordinator::{NAT_TABLE, NatSet, settlement};
use super::*;
use std::{fs, os::unix::fs::MetadataExt};

const LIMIT: u64 = 1 << 20;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Record {
    schema_version: u8,
    operation_id: uuid::Uuid,
    receipt_sha256: String,
    nat: Option<NatSet>,
}

fn private(path: &Path) -> Result<Vec<u8>> {
    let parent = fs::symlink_metadata(path.parent().context("CONFLICT: NAT proof parent")?)?;
    ensure!(
        parent.is_dir()
            && parent.uid() == unsafe { libc::geteuid() }
            && parent.mode() & 0o777 == 0o700,
        "FORBIDDEN: unsafe NAT proof directory"
    );
    let (bytes, metadata) = crate::durable::read(path, LIMIT)?;
    ensure!(
        metadata.uid == unsafe { libc::geteuid() } && metadata.mode == 0o600,
        "FORBIDDEN: unsafe NAT ownership proof"
    );
    Ok(bytes)
}

fn raw(root: &Path) -> Result<Option<Record>> {
    let path = root.join("nm/nat-confirmed.json");
    match fs::symlink_metadata(&path) {
        Ok(_) => Ok(Some(serde_json::from_slice(&private(&path)?)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn proof(root: &Path, active: &str, archived: &str) -> Result<Vec<u8>> {
    let path = root.join("nm").join(active);
    match fs::symlink_metadata(&path) {
        Ok(_) => private(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            private(&root.join("nm/history").join(archived))
        }
        Err(error) => Err(error.into()),
    }
}

fn load(root: &Path) -> Result<Option<Record>> {
    let Some(record) = raw(root)? else {
        return Ok(None);
    };
    ensure!(
        record.schema_version == 1
            && !record.operation_id.is_nil()
            && record.receipt_sha256.len() == 64
            && record.receipt_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
        "CONFLICT: NAT ownership record identity"
    );
    let id = record.operation_id;
    let receipt_bytes = proof(
        root,
        &format!("receipts/{id}.json"),
        &format!("{id}.receipt.json"),
    )?;
    ensure!(
        crate::durable::hash(&receipt_bytes) == record.receipt_sha256,
        "CONFLICT: NAT receipt changed"
    );
    let receipt: transaction::Receipt = serde_json::from_slice(&receipt_bytes)?;
    let journal: transaction::Journal = serde_json::from_slice(&proof(
        root,
        "transaction.json",
        &format!("{id}.journal.json"),
    )?)?;
    // A later operation may have its own active journal. Resolve this record's
    // exact historical journal rather than treating the active one as its proof.
    let journal = if journal.operation_id == id {
        journal
    } else {
        serde_json::from_slice(&private(
            &root.join(format!("nm/history/{id}.journal.json")),
        )?)?
    };
    ensure!(
        receipt.schema_version == 1
            && journal.schema_version == 1
            && receipt.operation_id == id
            && journal.operation_id == id
            && receipt.state == transaction::State::Committed
            && journal.state == transaction::State::Committed
            && journal.terminal_receipt_sha256.as_deref() == Some(record.receipt_sha256.as_str())
            && receipt.intent_sha256 == journal.intent_sha256
            && receipt.source_digest == journal.source_digest
            && receipt.candidate_digest == journal.candidate_digest,
        "CONFLICT: NAT committed journal binding"
    );
    if let Some(binding)=&journal.role_binding {binding.validate()?;}
    let main = proof(
        root,
        &format!("intents/{id}.json"),
        &format!("{id}.intent.json"),
    )?;
    ensure!(
        crate::durable::hash(&main) == journal.intent_sha256,
        "CONFLICT: NAT original intent changed"
    );
    let header: transaction::IntentHeader = serde_json::from_slice(&main)?;
    ensure!(
        header.operation_id == id
            && header.source_digest == journal.source_digest
            && header.candidate_digest == journal.candidate_digest
            && header.nm_identity == journal.nm_identity
            && header.nat_before == journal.nat_before
            && header.role_binding == journal.role_binding
            && header.nm_identity.is_some(),
        "CONFLICT: NAT original source binding"
    );
    let action = journal
        .action_intents
        .iter()
        .find(|a| a.action == "firewall")
        .context("CONFLICT: NAT action proof missing")?;
    let action_bytes = proof(
        root,
        &format!("intents/{id}.firewall.json"),
        &format!("{id}.firewall.intent.json"),
    )?;
    ensure!(
        crate::durable::hash(&action_bytes) == action.sha256,
        "CONFLICT: NAT action changed"
    );
    let action: Value = serde_json::from_slice(&action_bytes)?;
    let nat: Option<NatSet> = serde_json::from_value(
        action
            .get("nat")
            .context("CONFLICT: NAT action absent")?
            .clone(),
    )?;
    ensure!(
        action["schemaVersion"] == 1
            && action["operationId"] == id.to_string()
            && action["action"] == "firewall"
            && action["table"] == NAT_TABLE
            && nat == record.nat,
        "CONFLICT: NAT policy proof mismatch"
    );
    ensure!(
        header
            .nat_target
            .as_ref()
            .and_then(|target| target.get("nat"))
            == Some(&serde_json::to_value(&record.nat)?),
        "CONFLICT: NAT original target proof missing"
    );
    Ok(Some(record))
}

fn baseline(value: &Value) -> Result<(Option<NatSet>, Option<Record>)> {
    let nat: Option<NatSet> =
        serde_json::from_value(value.get("nat").context("CONFLICT: NAT baseline")?.clone())?;
    let owner: Option<Record> =
        serde_json::from_value(value.get("ownership").cloned().unwrap_or(Value::Null))?;
    ensure!(
        settlement::nat_equal(nat.as_ref(), owner.as_ref().and_then(|r| r.nat.as_ref())),
        "CONFLICT: NAT baseline ownership unproven"
    );
    Ok((nat, owner))
}

pub(super) fn marker(root: &Path) -> Result<Value> {
    Ok(serde_json::to_value(raw(root)?)?)
}

pub(super) fn capture(root: &Path, observed: Option<&NatSet>) -> Result<Value> {
    let owner = load(root)?;
    ensure!(
        settlement::nat_equal(observed, owner.as_ref().and_then(|r| r.nat.as_ref())),
        "CONFLICT: NAT table is not the confirmed owned policy"
    );
    Ok(json!({"nat":observed,"ownership":owner}))
}

pub(super) fn ensure_baseline(root: &Path, value: &Value) -> Result<()> {
    let (_, expected) = baseline(value)?;
    ensure!(
        load(root)? == expected,
        "CONFLICT: NAT ownership changed since preparation"
    );
    Ok(())
}

pub(super) fn confirmation(root: &Path, journal: &transaction::Journal) -> Result<()> {
    let current = raw(root)?;
    if current
        .as_ref()
        .is_none_or(|record| record.operation_id != journal.operation_id)
    {
        return ensure_baseline(
            root,
            journal
                .nat_before
                .as_ref()
                .context("CONFLICT: NAT baseline missing")?,
        );
    }
    ensure!(
        journal.state == transaction::State::ConfirmDecided && journal.confirmed_decision,
        "CONFLICT: NAT pointer does not belong to this confirmation prefix"
    );
    let receipt = transaction::Receipt {
        schema_version: 1,
        operation_id: journal.operation_id,
        source_digest: journal.source_digest.clone(),
        candidate_digest: journal.candidate_digest.clone(),
        intent_sha256: journal.intent_sha256.clone(),
        state: transaction::State::Committed,
    };
    let expected = serde_json::to_vec(&receipt)?;
    let id = journal.operation_id;
    let actual = proof(
        root,
        &format!("receipts/{id}.json"),
        &format!("{id}.receipt.json"),
    )?;
    ensure!(
        actual == expected,
        "CONFLICT: NAT pointer terminal prefix differs"
    );
    let main = proof(
        root,
        &format!("intents/{id}.json"),
        &format!("{id}.intent.json"),
    )?;
    ensure!(
        crate::durable::hash(&main) == journal.intent_sha256,
        "CONFLICT: NAT original intent changed"
    );
    let header: transaction::IntentHeader = serde_json::from_slice(&main)?;
    let nat: Option<NatSet> = serde_json::from_value(
        header
            .nat_target
            .as_ref()
            .and_then(|value| value.get("nat"))
            .context("CONFLICT: NAT original target missing")?
            .clone(),
    )?;
    ensure!(
        current
            == Some(Record {
                schema_version: 1,
                operation_id: id,
                receipt_sha256: crate::durable::hash(&actual),
                nat
            }),
        "CONFLICT: NAT pointer terminal prefix changed"
    );
    Ok(())
}

pub(super) fn publish(
    root: &Path,
    journal: &transaction::Journal,
    receipt_sha256: String,
    nat: Option<NatSet>,
) -> Result<()> {
    let next = Record {
        schema_version: 1,
        operation_id: journal.operation_id,
        receipt_sha256,
        nat,
    };
    let id = journal.operation_id;
    let main = proof(
        root,
        &format!("intents/{id}.json"),
        &format!("{id}.intent.json"),
    )?;
    ensure!(
        crate::durable::hash(&main) == journal.intent_sha256,
        "CONFLICT: NAT original intent changed"
    );
    let header: transaction::IntentHeader = serde_json::from_slice(&main)?;
    ensure!(
        header
            .nat_target
            .as_ref()
            .and_then(|target| target.get("nat"))
            == Some(&serde_json::to_value(&next.nat)?),
        "CONFLICT: NAT original target proof missing"
    );
    // Recovery may find the terminal receipt and pointer published before the
    // journal's last fsync. Fresh candidate proof is still required by caller.
    if raw(root)?.as_ref() == Some(&next) {
        return Ok(());
    }
    ensure_baseline(
        root,
        journal
            .nat_before
            .as_ref()
            .context("CONFLICT: NAT ownership baseline missing")?,
    )?;
    crate::durable::json(&root.join("nm/nat-confirmed.json"), &next)
}

pub(crate) fn recognizes(root: &Path, ruleset: &Value) -> Result<bool> {
    let Some(record) = load(root)? else {
        return Ok(false);
    };
    let Some(expected) = record.nat else {
        return Ok(false);
    };
    let entries = ruleset["nftables"]
        .as_array()
        .context("CONFLICT: firewall ruleset format")?;
    let entries: Vec<_> = entries
        .iter()
        .filter(|entry| {
            entry.as_object().is_some_and(|object| {
                object.iter().any(|(kind, value)| {
                    value["family"] == "inet"
                        && if kind == "table" {
                            value["name"] == NAT_TABLE
                        } else {
                            value["table"] == NAT_TABLE
                        }
                })
            })
        })
        .cloned()
        .collect();
    let actual = settlement::parse_nat(&json!({"nftables":entries}));
    Ok(actual.is_ok_and(|actual| settlement::nat_equal(Some(&actual), Some(&expected))))
}

/// Fresh source observation,never an adoption of a familiar table name. Both
/// presence and absence must agree with the original committed NM authority.
pub(crate) fn kernel_authority(root: &Path, ruleset: &Value) -> Result<Value> {
    let owner = load(root)?;
    let entries = ruleset["nftables"].as_array().context("CONFLICT: firewall ruleset format")?;
    let entries: Vec<_> = entries.iter().filter(|entry| {
        entry.as_object().is_some_and(|object| object.iter().any(|(kind,value)| {
            value["family"] == "inet" && if kind == "table" {
                value["name"] == NAT_TABLE
            } else { value["table"] == NAT_TABLE }
        }))
    }).cloned().collect();
    let observed = if entries.is_empty() { None } else {
        Some(settlement::parse_nat(&json!({"nftables":entries}))?)
    };
    ensure!(settlement::nat_equal(observed.as_ref(), owner.as_ref().and_then(|record| record.nat.as_ref())),
        "CONFLICT: kernel automatic NAT has no matching original committed authority");
    Ok(json!({"nat":observed,"ownership":owner}))
}
