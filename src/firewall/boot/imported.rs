//! Restore the exclusive imported layout with a generation-fenced native batch.
use super::*;
use crate::nm::handover::initialization::{BootImage, imported_boot_source};
use std::time::{Duration, Instant};

fn kernel_identity() -> Result<(Uuid, u64, u64)> {
    let boot = current_boot_id()?;
    let namespace = fs::File::open("/proc/thread-self/ns/net")?;
    let metadata = namespace.metadata()?;
    ensure!(boot == current_boot_id()?, "CONFLICT: physical boot changed during observation");
    Ok((boot, metadata.dev(), metadata.ino()))
}

fn require_scope(root: &Path, intent: &Intent) -> Result<()> {
    intent.require_root(root)?;
    ensure!(kernel_identity()? == (intent.boot_id, intent.scope.net_device, intent.scope.net_inode),
        "CONFLICT: imported restore physical scope changed");
    Ok(())
}

pub(super) fn restore(firewall: &Firewall) -> Result<Value> {
    let root = &firewall.0.root;
    let (owner, image) = imported_boot_source(root)?;
    let observe = || BootImage::observe(|| {
        let output = firewall.run_nft(&["-j", "-p", "list", "ruleset"], None)?;
        Ok(serde_json::from_str(&output)?)
    }, Instant::now() + Duration::from_secs(12));
    restore_under_guard(root, &owner, &image, observe, |generation| {
        image.dispatch(generation, Instant::now() + Duration::from_secs(10))
    })
}

fn restore_under_guard(
    root: &Path,
    owner: &str,
    image: &BootImage,
    mut observe: impl FnMut() -> Result<Value>,
    dispatch: impl FnOnce(u32) -> Result<()>,
) -> Result<Value> {
    let path = ledger(root);
    let pending_file = path.join(PENDING);
    let prior = resolved_pending(&path)?;
    let (boot_id, net_device, net_inode) = kernel_identity()?;
    image.require_new_epoch(boot_id, net_device, net_inode)?;
    let completion = receipt_path(&path, boot_id);
    let metadata = fs::symlink_metadata(root)?;
    let intent = |generation| Intent {
        schema_version: 2,
        boot_id,
        scope: Scope {
            root_device: metadata.dev(), root_inode: metadata.ino(), net_device, net_inode,
            owner_lease_sha256: owner.into(), confirmed_sha256: image.source_sha256().into(),
            revision: image.revision(),
        },
        imported: Some(ImportedIntent {
            initialization_receipt_sha256: image.initialization_sha256().into(),
            image_sha256: image.image_sha256().into(),
            expected_generation: generation,
        }),
    };

    if let Some((receipt, _)) = read_receipt(&completion)? {
        receipt.intent.require_root(root)?;
        let expected = receipt.intent.imported.as_ref().context("CONFLICT: another firewall backend owns this boot receipt")?;
        let intent = intent(expected.expected_generation);
        receipt.check(&intent, &serde_json::to_vec(&intent)?)?;
        let observed = image.readback(&observe()?, expected.expected_generation)?;
        require_scope(root, &intent)?;
        ensure!(receipt.native_readback.as_ref() == Some(&observed),
            "CONFLICT: completed imported restore changed; no re-dispatch");
        if prior.is_some() {
            durable::remove(&pending_file)?;
        }
        return Ok(json!({"state":"ALREADY_RESTORED","revision":image.revision()}));
    }

    let generation = image.empty_generation(&observe()?)?;
    super::super::require_forwarding(image.forwarding_families()?)?;
    let intent = intent(generation);
    intent.validate()?;
    require_scope(root, &intent)?;
    durable::directory(&path)?;
    if prior.is_some() {
        durable::remove(&pending_file)?;
    }
    let raw = publish(&pending_file, &intent)?;
    // Once saved, an interrupted or ambiguous original is only observable.
    require_scope(root, &intent).context("OUTCOME_UNKNOWN: imported restore scope before dispatch")?;
    dispatch(generation).context("OUTCOME_UNKNOWN: original imported firewall restore dispatch")?;
    let readback = image.readback(&observe().context("OUTCOME_UNKNOWN: imported restore kernel observation")?, generation)
        .context("OUTCOME_UNKNOWN: original imported firewall restore readback")?;
    require_scope(root, &intent).context("OUTCOME_UNKNOWN: imported restore scope after dispatch")?;
    let receipt = Receipt {
        intent, intent_sha256: durable::hash(&raw), native_readback: Some(readback),
    };
    publish(&completion, &receipt).context("OUTCOME_UNKNOWN: imported firewall restore receipt publication")?;
    durable::remove(&pending_file)?;
    Ok(json!({"state":"RESTORED","revision":image.revision()}))
}
