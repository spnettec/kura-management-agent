//! Link a completed early restore to the existing imported transaction head.
//! The new link changes the physical source while preserving logical revision.
use super::*;
use native::epoch::Epoch;

const RECEIPT_LIMIT: u64 = 1_048_576;

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Binding {
    schema_version: u8,
    boot_id: uuid::Uuid,
    pub(super) base: Head,
    // Pin both the immutable receipt and the old mutable pointer. A replaced
    // pointer cannot authorize finishing a partial metadata publication.
    receipt: MarkerIdentity,
    prior_pointer: Option<MarkerIdentity>,
}

fn ledger(root: &Path) -> PathBuf { root.join("firewall/boot-restore") }
fn receipt_path(root: &Path, boot: uuid::Uuid) -> PathBuf { ledger(root).join(format!("{boot}.receipt.json")) }
fn binding_path(root: &Path, boot: uuid::Uuid) -> PathBuf { ledger(root).join(format!("{boot}.rebind.json")) }

impl Binding {
    pub(super) fn read(root: &Path, boot: uuid::Uuid, reference: &MarkerIdentity) -> Result<Self> {
        directory(&ledger(root))?;
        let file = BoundFile::open(&binding_path(root, boot), 16_384)?;
        ensure!(file.marker()? == *reference, "CONFLICT: imported boot lineage binding was replaced");
        let binding: Self = serde_json::from_slice(&file.bytes)?;
        ensure!(binding.schema_version == 1 && !boot.is_nil() && binding.boot_id == boot
            && binding.prior_pointer.is_none() == matches!(binding.base, Head::Initialization { .. }),
            "CONFLICT: imported boot lineage identity and predecessor");
        Ok(binding)
    }

    pub(super) fn replay(&self, root: &Path, parent: CurrentSource) -> Result<CurrentSource> {
        let file = BoundFile::open(&receipt_path(root, self.boot_id), RECEIPT_LIMIT)?;
        ensure!(file.marker()? == self.receipt, "CONFLICT: imported boot lineage receipt was replaced");
        let proof = crate::firewall::decode_imported_receipt(root, self.boot_id, &file.bytes)?;
        let current = BootImage::new(parent)?.rebound(&proof, &self.receipt.sha256)?;
        file.verify_binding()?;
        Ok(current)
    }
}

/// Run under the existing exclusive firewall lock. A complete original receipt
/// plus fresh matching kernel observation can authorize metadata publication.
pub(in crate::nm::handover::initialization) fn adopt(
    root: &Path,
    original: &Original,
    owner: &str,
    epoch: &Epoch,
    observe: impl FnOnce() -> Result<Value>,
) -> Result<Option<Value>> {
    let boot = epoch.boot_id();
    let receipt_path = receipt_path(root, boot);
    if !present(&receipt_path)? { return Ok(None); }
    directory(&ledger(root))?;
    let receipt_file = BoundFile::open(&receipt_path, RECEIPT_LIMIT)?;
    let receipt = crate::firewall::decode_imported_receipt(root, boot, &receipt_file.bytes)?;
    ensure!(receipt.owner_lease_sha256 == owner,
        "FORBIDDEN: imported boot receipt belongs to another paired owner lease");
    epoch.require(&Epoch::from_boot_receipt(boot, receipt.net_device, receipt.net_inode)?)?;

    let view = read(root, &original.document, &original.origin, &original.source)?;
    if let Some(view) = &view {
        if view.recent_boot == Some(boot) {
            view.current.require_epoch(epoch)?;
            receipt_file.verify_binding()?;
            return Ok(Some(json!({"state":"ALREADY_REBOUND","bootId":boot,
                "revision":view.current.witness()?["revision"].as_str().context("CONFLICT: rebound revision")?.parse::<u64>()?})));
        }
        ensure!(view.settled, "OUTCOME_UNKNOWN: original imported transaction must settle before boot rebind");
        ensure!(view.history_depth < MAX_HISTORY, "RESOURCE_EXHAUSTED: imported boot lineage headroom");
    }
    let (base, parent) = match view {
        Some(view) => (view.head, view.current),
        None => (Head::Initialization { receipt_sha256: receipt.initialization_sha256.clone() },
            initial(&original.document, &original.origin, &original.source)?),
    };
    let pointer = root.join("firewall/confirmed.json");
    let prior = if present(&pointer)? { Some(BoundFile::open(&pointer, LIMIT)?) } else { None };
    let prior_marker = prior.as_ref().map(BoundFile::marker).transpose()?;
    ensure!(prior_marker.is_none() == matches!(base, Head::Initialization { .. }),
        "CONFLICT: imported boot rebind predecessor pointer changed");
    if let Some(file) = &prior {
        let current: Confirmed = serde_json::from_slice(&file.bytes)?;
        current.require_head_kind()?;
        ensure!(current.head == base, "CONFLICT: imported boot rebind predecessor differs");
    }
    let receipt_marker = receipt_file.marker()?;
    let image = BootImage::new(parent)?;
    let rebound = image.rebound(&receipt, &receipt_marker.sha256)?;
    ensure!(image.readback(&observe()?, receipt.expected_generation)? == receipt.readback,
        "CONFLICT: live kernel differs from the exact imported boot receipt");
    epoch.require(&Epoch::capture()?)?;
    original.file.verify_binding()?;
    receipt_file.verify_binding()?;

    let binding = Binding { schema_version: 1, boot_id: boot, base, receipt: receipt_marker,
        prior_pointer: prior_marker };
    let path = binding_path(root, boot);
    let expected = serde_json::to_vec(&binding)?;
    if present(&path)? {
        let existing = BoundFile::open(&path, 16_384)?;
        ensure!(existing.bytes == expected,
            "OUTCOME_UNKNOWN: original boot rebind differs from its retained predecessor; preserve history");
    } else {
        durable::publish_new(&path, &expected, FileMetadata::private())?;
    }
    let file = BoundFile::open(&path, 16_384)?;
    ensure!(file.bytes == expected, "CONFLICT: imported boot rebind evidence changed");
    let witness = rebound.witness()?;
    let source_digest = witness["sourceDigest"].as_str().context("CONFLICT: rebound source digest")?;
    let current = Confirmed {
        backend: Backend::Imported, schema_version: 2,
        head: Head::BootRestore { boot_id: boot, reference: file.marker()? },
        revision: receipt.revision, source_digest: source_digest.into(),
    };
    if let Some(predecessor) = prior {
        predecessor.verify_binding()?;
        durable::json(&pointer, &current)?;
    } else {
        durable::publish_new(&pointer, &serde_json::to_vec(&current)?, FileMetadata::private())?;
    }
    Ok(Some(json!({"state":"REBOUND","bootId":boot,"revision":receipt.revision,
        "sourceDigest":source_digest,"bootReceiptSha256":binding.receipt.sha256})))
}
