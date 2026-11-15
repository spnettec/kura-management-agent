//! A fresh stopped-service observation under the immutable original startup.
//! No stored receipt,failed JVM call or caller payload constructs this challenge.
use super::*;
use crate::nm::handover::native::epoch::Epoch;

#[derive(Clone, PartialEq, Eq)]
pub(in crate::nm) struct Challenge {
    original_unit: crate::system_control::Unit,
    stopped_unit: crate::system_control::Unit,
    completion_receipt_sha256: String,
    selected_profile_sha256: String,
    stop_policy: crate::system_control::StopPolicy,
    epoch: Epoch,
}
impl Challenge {
    pub(in crate::nm) fn parameters(&self) -> Value {
        json!({"schemaVersion":1,"scope":"fresh-same-owner-stopped-service-observation",
            "originalStartupReceiptSha256":self.completion_receipt_sha256,
            "selectedProfileSha256":self.selected_profile_sha256,"stopPolicy":self.stop_policy,
            "originalUnit":self.original_unit,"currentUnit":self.stopped_unit,
            "physicalEpoch":self.epoch,"currentJvmWitness":false,
            "historicalStartupRewritten":false,"ownerGrant":false})
    }
    pub(in crate::nm) fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    pub(in crate::nm) fn runtime_digest(&self) -> Result<String> {
        digest(
            &json!({"schemaVersion":1,"domain":"nm.imported.stopped-runtime.v1",
            "stopped":self.parameters()}),
        )
    }
}

/// A selection hint only. Every selected capability samples its complete state
/// again; a failed or transitional live sample never falls back to stopped.
pub(super) fn hint(root: &Path, original: &Requirements, systemctl: &Path) -> Result<bool> {
    ensure!(
        original.state == State::Committed,
        "FORBIDDEN: runtime mode requires original committed ownership"
    );
    let anchor = completion::runtime_anchor(root, original)?;
    let unit = crate::system_control::inspect_unit(systemctl, &anchor.config.unit)?;
    ensure!(
        unit.unit == anchor.original.unit.unit && (unit.running() || unit.stopped()),
        "CONFLICT: original ordinary service is in an unproven or transitional state"
    );
    Ok(unit.stopped())
}

pub(super) fn challenge(
    root: &Path,
    original: &Requirements,
    systemctl: &Path,
) -> Result<Challenge> {
    ensure!(
        original.state == State::Committed,
        "FORBIDDEN: stopped runtime requires original committed ownership"
    );
    let epoch = Epoch::capture()?;
    let anchor = completion::runtime_anchor(root, original)?;
    // Production Coordinator supplies the fixed /usr/bin/systemctl; that path
    // also checks the actual cgroup is absent or unpopulated with no processes.
    let unit = crate::system_control::inspect_stopped_unit(systemctl, &anchor.config.unit)?;
    ensure!(
        unit.unit == anchor.original.unit.unit
            && (unit.control_group.is_empty()
                || unit.control_group == anchor.original.unit.control_group),
        "CONFLICT: stopped runtime is outside the original mapped ordinary service"
    );
    ensure!(
        anchor.stop_policy
            == crate::system_control::inspect_stop_policy(systemctl, &anchor.config)?,
        "CONFLICT: stopped runtime service definition differs from original pinned policy"
    );
    ensure!(
        unit == crate::system_control::inspect_stopped_unit(systemctl, &anchor.config.unit)?,
        "CONFLICT: ordinary service changed during stopped observation"
    );
    let again = completion::runtime_anchor(root, original)?;
    ensure!(
        anchor.receipt_sha256 == again.receipt_sha256
            && anchor.profile_sha256 == again.profile_sha256
            && anchor.original == again.original
            && anchor.stop_policy == again.stop_policy,
        "CONFLICT: original startup anchor changed during stopped observation"
    );
    epoch.require(&Epoch::capture()?)?;
    Ok(Challenge {
        original_unit: anchor.original.unit,
        stopped_unit: unit,
        completion_receipt_sha256: anchor.receipt_sha256,
        selected_profile_sha256: anchor.profile_sha256,
        stop_policy: anchor.stop_policy,
        epoch,
    })
}

pub(super) fn finish(
    root: &Path,
    original: &Requirements,
    expected: &Challenge,
    systemctl: &Path,
) -> Result<String> {
    ensure!(
        challenge(root, original, systemctl)? == *expected,
        "CONFLICT: original stopped service/epoch/profile changed during current authority observation"
    );
    Ok(expected.completion_receipt_sha256.clone())
}
